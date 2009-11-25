# PermissibleSystem
module PermissibleSystem

  class Config

    def self.set_options(options)
      @@options = options.reverse_merge(PermissibleSystem::Config.default_authorization_policy)
      @@options[:token_groups] = invert_groups(@@options[:groups])
      @@options
    end

    def self.invert_groups(groups)
      inverse = Hash.new { |h,k| h[k] = Array.new }
      groups.each_pair do |name, actions|
        actions.each{|action| inverse[action] << name}
      end
      inverse
    end

    def self.get_options
      @@options
    end

    def self.default_authorization_policy
      {
        :groups => {
          :read   => [ :index, :show ],
          :modify => [ :index, :show, :edit, :update,  ],
          :write  => [ :index, :show, :new, :create, :edit, :update, :destroy ]
        },
        :group_order => [ :read, :modify, :write ],
        :default => :allow,
        :except => [],
        :only => nil
      }
    end

  end


  # we pass in can_edit_fees?
  # we need to return [:can_edit_fees, :can_modify_fees, :can_write_fees]
  # options => :token => "can_edit_fees", or :action => "action", :controller => :controller
  def self.acceptable_tokens(token)
    token = token.to_s unless token.is_a?(String)
    config_options = PermissibleSystem::Config.get_options
    if token =~ /can_(.*?)_(.*)\?/i
      action = $1.to_sym
      controller = $2
    end
    tokens = ["can_#{action}_#{controller}"]
    # it's an action so put in the appropriate groups
    config_options[:token_groups][action].each { |a| tokens << "can_#{a}_#{controller}" }
    # it's a group, so put in higher groups ie, if request is read allow if they've got modify
    config_options[:group_order].reverse[0..config_options[:group_order].reverse.index(action)].each do |a|
      tokens << "can_#{a}_#{controller}"
    end if config_options[:group_order].include?(action)
    tokens
  end

  def self.permission_check(user, token, source="No Source")
    options = PermissibleSystem::Config.get_options

    # check 2: see if any of the tokens even exist
    # also need to see if they assume allow
    # if none of the tokens exist and they assume allow, get out of here
    # if none of the token exist and assume deny, raise error
    applicable_tokens = PermissibleSystem.acceptable_tokens(token)
    possible_permissions = Permission.all(:conditions => {:token => applicable_tokens})
    log_string = "#{source.capitalize} checking: #{applicable_tokens.inspect}, tokens exist: #{possible_permissions.present?}"
    log_string << " user has permission: #{user.permissions.all(:conditions => {:id => possible_permissions.collect(&:id)}).present?}" unless possible_permissions.blank?
    Rails.logger.info(log_string)
    if possible_permissions.blank?
      return if options[:default] == :allow
      if options[:default] == :deny
        raise NotAuthorized if source.controller?
        return false if source.model?
      end
    end
    # Rails.logger.info "Passed check 2 (no tokens in db)"

    # check 3: see if the user has the token to proceed
    # under this condition there are permissions set for the action
    # if the user does not have any of the permissions stop them
    # otherwise allow them (because they explicitly HAVE the permission)
    if user.permissions.all(:conditions => {:id => possible_permissions.collect(&:id)}).blank?
      raise NotAuthorized if source.controller?
      return false if source.model?
    end
    Rails.logger.info "Passed check 3 -- AUTHORIZED! (user has permissions)"
    return true
  end

  # This should be the exception used for unauthorized access event
  class NotAuthorized < Exception; end

  def self.included(base)
    case base.superclass.to_s
    when "ActiveRecord::Base"
      base.send(:include, PermissibleModelMethods)
    when "ActionController::Base"
      base.extend PermissibleControllerClassMethods
    end
  end

  # options => {:controller_override => Proc, :model_override => Proc, :groups => {:alias => [actions_array]} or false, :default => :allow or :deny }
  module PermissibleControllerClassMethods
    def check_authorization(options={})
      options = PermissibleSystem::Config.set_options(options)
      raise "groups and group_order are inconsistent!" unless (options[:group_order] - options[:groups].keys).blank?
      raise "unknown default option #{options[:default]}, must be either :allow or :deny" unless [ :allow, :deny ].include?(options[:default])
      include PermissibleSystem::PermissibleControllerInstanceMethods
      self.send(:before_filter, :authorization_before_filter) # Proc.new {|c| c.authorization_before_filter(options)})
    end
  end

  module PermissibleControllerInstanceMethods

    def authorization_before_filter
      return unless logged_in?
      options = PermissibleSystem::Config.get_options
      return true if (options[:controller_override] ? options[:controller_override].call(self) : false )
      # Rails.logger.info "Passed check 1 (override)"
      PermissibleSystem.permission_check(current_user, "can_#{params[:action]}_#{params[:controller]}?", "controller")
    end


    def render_error
      Rails.logger.warn " * Attempt by #{current_user} to access something they don't have permission for."
      respond_to do |format|
        format.html {render :file => 'public/403.html', :status => 403}
        format.js {
          render :update do |page|
            page.alert "You are not authorized to #{params[:action]} #{params[:controller]}."
          end
        }
      end
    end
  end

  module PermissibleModelMethods

    #TODO - Engineers, Re-implement dynamic role check
    def method_missing(method_id, *args)
      #      if match = matches_dynamic_role_check?(method_id)
      # options = PermissibleSystem::Config.get_options
      # check = match.captures.first
      # return ( role.name.downcase == check )
      #elsif match = matches_dynamic_perm_check?(method_id)
      if match = matches_dynamic_perm_check?(method_id)
        options = PermissibleSystem::Config.get_options
        return true if (options[:model_override] ? options[:model_override].call(self) : false )
        PermissibleSystem.permission_check(self, method_id, "model")
      else
        super
      end
    end

    private

    def matches_dynamic_role_check?(method_id)
      /^is_an?_([a-zA-Z]\w*)\?$/.match(method_id.to_s)
    end

    def matches_dynamic_perm_check?(method_id)
      # puts "MEthod: #{method_id}"
      /^(can_[a-zA-Z]\w*)\?$/.match(method_id.to_s)
    end

  end

end
