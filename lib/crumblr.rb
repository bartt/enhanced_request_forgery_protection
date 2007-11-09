# Crumblr

require 'openssl'

module Crumblr

  def self.included(base)
    base.send(:include, InstanceMethods)
    base.class_eval do
      helper_method :issue_crumb
    end
  end

  module InstanceMethods

    # Issue a crumb to verify at the receiving end of the form
    # submission that the request came from a trusted source.
    def issue_crumb(timestamp)
      session[:crumb_secret] = String.rand(6) unless session[:crumb_secret] 
      signature = "#{request.remote_ip}#{timestamp}#{cookies[:_session_id]}#{session[:crumb_secret]}"
      logger.debug("_session_id = #{cookies[:_session_id]}
signature = #{signature}")
      OpenSSL::Digest::SHA1.hexdigest(signature)
    end

    # Verify that the crumb is valid. 
    def verify_crumb
      if (request.post? || request.put? || request.delete?) then
        @@crumb_window ||= 15.minutes
        @@crumb_flash_msg ||= 'Form submission timed out. Please resubmit.'
        logger.debug("Crumb window = #{@@crumb_window}\nCrumb flash msg = #{@@crumb_flash_msg}")
        if (defined?(params[:_crumb]) && 
              defined?(params[:_timestamp]) && 
              Time.at(params[:_timestamp].to_i) + @@crumb_window > Time.now &&
              (params[:_crumb] == OpenSSL::Digest::SHA1.hexdigest("#{request.remote_ip}#{params[:_timestamp]}#{cookies[:_session_id]}#{session[:crumb_secret]}"))) then
          return true
        else
          logger.warn("Invalid crumb:
_crumb = #{params[:_crumb]}
_timestamp = #{params[:_timestamp]}
remote_ip = #{request.remote_ip}
_session_id = #{cookies[:_session_id]}
crumb_secret = #{session[:crumb_secret]}
digest = #{OpenSSL::Digest::SHA1.hexdigest("#{request.remote_ip}#{params[:_timestamp]}#{cookies[:_session_id]}#{session[:crumb_secret]}")}")
          if request.env['HTTP_REFERER']
            flash[:warning] = @@crumb_flash_msg
            redirect_to request.env['HTTP_REFERER'] 
          else
            render :text => 'Invalid crumb', :status => 404
          end
        end
      else
        return true
      end
    end
  end

end
