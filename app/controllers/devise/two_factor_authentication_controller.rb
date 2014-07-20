class Devise::TwoFactorAuthenticationController <  ActiveAdmin::Devise::SessionsController # DeviseController
  prepend_before_filter :authenticate_scope!
  before_filter :prepare_and_validate, :handle_two_factor_authentication

  def show
    if not resource.nil? and params[:code].nil?
      respond_with(resource)
    else
      redirect_to :root
    end
  end

  def update
    if resource.authenticate_otp(params[:code], drift: 60) 
      warden.session(resource_name)[:need_two_factor_authentication] = false
      sign_in resource_name, resource, :bypass => true
      redirection_path = 
        if ActiveRecord::Base.connection.table_exists? 'current_namespaces' and CurrentNamespace.count > 0 and !Rails.env.development?
          CurrentNamespace.first.current_namespace.to_sym || "/admin"
        else
          "/admin"
        end
      redirect_to stored_location_for(resource_name) || redirection_path
      resource.update_attribute(:second_factor_attempts_count, 0)
    else
      resource.second_factor_attempts_count += 1
      resource.save
      set_flash_message :error, :attempt_failed
      if resource.max_login_attempts?
        sign_out(resource)
        render :template => 'devise/two_factor_authentication/max_login_attempts_reached' and return
      else
        respond_with(resource)
      end
    end
  end

  private

    def authenticate_scope!
      self.resource = send("current_#{resource_name}")
    end

    def prepare_and_validate
      redirect_to :root and return if resource.nil?
      @limit = resource.class.max_login_attempts
      if resource.max_login_attempts?
        sign_out(resource)
        render :template => 'devise/two_factor_authentication/max_login_attempts_reached' and return
      end
    end
end
