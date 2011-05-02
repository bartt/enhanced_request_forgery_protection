require 'openssl'

# A plugin to protect against {Cross-Site Request Forgery}[http://en.wikipedia.org/wiki/Crsf].
# This plugin requires +string_ext+.
#
# = Class variables
# 
# Because crumb verification is a request filter one can't pass
# variables to a +verify_crumb+. But because Crumblr gets mixed into
# ActionController one can use class instance variables to pass
# information to +verify_crumb+ and +issue_crumb+. Crumblr uses the
# following attributes:
# 
# <tt>crumb_window</tt>::
#     The time window within which the form has to be submitted and
#     verified. Defaults to <i>15 minutes</i>.
# <tt>crumb_flash_msg</tt>::
#     The message to passed to the session flash if the crumb doesn't
#     validate. Defaults to <i>Form submission timed out. Please
#     resubmit.</i>.
# <tt>crumb_scope</tt>::
#     The scope of actions that use compatible crumbs. Defaults to
#     <i>the ActionController's class name</i> which means that
#     +verify_crumb+ only validates actions of that controller.
#     Override to broaden the scope.  Setting the scope in 2
#     controllers to the same value makes their crumbs compatible.
module Crumblr
  # Shortcut to the name of the Rails session ID.
  def self.session_id
    Rails.application.class.send('config').session_options[:key]
  end

  def self.included(base) #:nodoc:
    base.send(:extend, ClassMethods)
    base.send(:include, InstanceMethods)
    base.class_eval do
      helper_method :issue_crumb
    end
  end

  module ClassMethods #:nodoc:
    def crumb_scope
      @crumb_scope ||= self.name
    end

    def crumb_window
      @crumb_window ||= 15.minutes
    end

    def crumb_timed_out_msg
      @crumb_timed_out_msg ||= 'Form submission timed out. Please resubmit.'
    end

    def crumb_invalid_msg
      @crumb_invalid_msg ||= 'Possible form data tampering. Please resubmit.'
    end
  end

  module InstanceMethods #:doc:

    # Issue a crumb to verify at the receiving end of the form
    # submission that the request came from a trusted source.
    #
    # +issue_crumb+ is intended to be used by view helper +crumb_tags+
    # only. It calculates the value for the hidden tag +_crumb+ that
    # +crumb_tags+ renders.
    #
    # This value is the SHA1 hash of the following values concatenated:
    # <tt>request.remote_ip</tt>::
    #     The IP address of the remote client
    # <tt>timestamp</tt>::
    #     The timestamp at which the crumb was issued
    # <tt>cookies[::Crumblr.session_id]</tt>::
    #     The session's ID
    # <tt>crumb_scope</tt>::
    #     A class attribute in the ActionController where crumblr is used.
    # <tt>session[:crumb_secret]</tt>::
    #     A random string acting as salt
    def issue_crumb(timestamp)
      session[:crumb_secret] ||= String.rand(6)
      signature = "#{request.remote_ip}#{timestamp}#{cookies[::Crumblr.session_id]}#{self.class.crumb_scope}#{session[:crumb_secret]}"
      logger.debug("Issued crumb:
_session_id = #{cookies[::Crumblr.session_id]}
signature = #{signature}")
      OpenSSL::Digest::SHA1.hexdigest(signature)
    end

    # Verify that a crumb is valid. A crumb consists of query
    # parameters +_crumb+ and +_timestamp+, both if which are rendered
    # by view helper +crumb_tags+. There is no validation on http GET
    # as GET is commonly used w/o form submission.
    #
    # Verify_crumb lets the request through if the crumb is valid. The
    # client will be redirect back to where it came from when the
    # crumb is <em>not valid</em> and the <em>request includes an HTTP
    # referer</em>. Requests with invalid crumbs and <em>no HTTP
    # referer</em> receive a 404.
    def verify_crumb 
      if request.post? || request.put? || request.delete? then
        # Must have valid a crumb
        if defined?(params[:_crumb]) && defined?(params[:_timestamp]) then
          if Time.at(params[:_timestamp].to_i) + self.class.crumb_window > Time.now then
            if valid_crumb? then
              return true
            else
              # The request is within the controller's time window, but the crumb is invalid.
              # This means either tampering (with _timestamp or _crumb) or the remote IP
              # address has changed.
              log_crumb_mismatch("Invalid crumb within time window")
              flash[:warning] = self.class.crumb_invalid_msg
              redirect_or_reset
            end
          else
            if valid_crumb? then
              # The crumb is valid, but the request came in after the controller's time window.
              # Most likely the user waited too long.
              log_crumb_mismatch("Valid crumb outside time window")
              flash[:warning] = self.class.crumb_timed_out_msg
              redirect_or_reset
            else
              # The crumb is invalid and the request came in after the controller's time window.
              # This could be tampering with _crumb (or possibly _timestamp) or the remote IP
              # address has changed.
              log_crumb_mismatch("Invalid crumb outside time window")
              flash[:warning] = self.class.crumb_timed_out_msg
              flash[:warning] << "\n" + self.class.crumb_invalid_msg
              redirect_or_reset
            end
          end
        else
          # Either _crumb or _timestamp was missing. This smells like tampering.
          missing = [:_crumb, :_timestamp].select {|key| !defined?(params[:_crumb])}
          logger.warn("Parameter(s) #{missing.join('and ')} are/is missing.")
          reset_session_with_error
        end
      else
        return true
      end
    end

    private

    # Is the crumb received in the request valid?
    def valid_crumb?
      @digest = OpenSSL::Digest::SHA1.hexdigest("#{request.remote_ip}#{params[:_timestamp]}#{cookies[::Crumblr.session_id]}#{self.class.crumb_scope}#{session[:crumb_secret]}")
      params[:_crumb] == @digest
    end

    # Return the visitor to the origin of the request. Most
    # often this will be local URL and this redirect will
    # re-issue new crumbs. No harm done if the referrer is an
    # external site. Crumblr's goal is to only accept requests
    # from specific local origins.
    def redirect_or_reset
      if request.env['HTTP_REFERER']
        redirect_to request.env['HTTP_REFERER']
      else
        reset_session_with_error
      end
    end

    # Return standard 404 message. Let the ActionController's
    # rescue mechanisme handle this routing error rather then
    # explicitly returning the default public/404.html
    # file. Only report the lowest stack level in the error
    # log.
    def reset_session_with_error
      reset_session
      raise ActionController::RoutingError, "A valid crumb is required", caller(0)[0]
    end

    # Log details of a crumb mismatch to the application log.
    def log_crumb_mismatch(msg)
      logger.warn("#{msg}:
  _crumb = #{params[:_crumb]}
  _timestamp = #{params[:_timestamp]}
  remote_ip = #{request.remote_ip}
  _session_id = #{cookies[::Crumblr.session_id]}
  scope = #{self.class.crumb_scope}
  crumb_secret = #{session[:crumb_secret]}
  digest = #{@digest}")
    end
  end
end
