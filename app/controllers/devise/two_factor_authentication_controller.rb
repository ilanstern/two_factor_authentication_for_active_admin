class Devise::TwoFactorAuthenticationController <  ActiveAdmin::Devise::SessionsController # DeviseController
  skip_before_filter    :handle_two_factor_authentication
  skip_before_filter    :handle_password_change
  before_filter         :prepare_and_validate
  prepend_before_filter :authenticate_scope!,   :only => [:show, :update]

  def show
  end

  def update
    render :show and return if params[:code].nil?

    if resource.authenticate_otp(params[:code], drift: 60) 
      warden.session(resource_name)[:need_two_factor_authentication] = false
      sign_in resource_name, resource, :bypass => true
      redirection_path = 
        if ActiveRecord::Base.connection.table_exists? 'current_namespaces' and CurrentNamespace.count > 0
          "/#{CurrentNamespace.last.current_namespace}"
        else
          "/admin"
        end
      redirect_to stored_location_for(resource_name) || redirection_path
      resource.update_attribute(:second_factor_attempts_count, 0)
    else
      resource.second_factor_attempts_count += 1
      resource.save
      flash.now[:error] = find_message(:attempt_failed)
      if resource.max_login_attempts?

        if Rails.env.production?
          ExceptionNotifier.notify_exception(Exception.new("User locked by failed 2 step password attempts: #{resource.username}"))
        end


        sign_out(resource)
        render :max_login_attempts_reached
      else
        render :show
      end
    end
  end

  def devise_controller?
    true
  end

  private

    def authenticate_scope!
      send(:"authenticate_#{resource_name}!")
      self.resource = send("current_#{resource_name}")
    end

    def prepare_and_validate
      redirect_to :root and return if resource.nil?
      @limit = resource.class.max_login_attempts
      if resource.max_login_attempts?
        sign_out(resource)
        render :max_login_attempts_reached
      end
    end
end
