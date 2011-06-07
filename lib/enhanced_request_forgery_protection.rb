require 'openssl'

# A plugin to protect against {Cross-Site Request Forgery}[http://en.wikipedia.org/wiki/Crsf].
#
# = Class variables
#
# Because authenticity_token verification is a request filter one can't pass
# variables to a +verify_authenticity_token+. But because EnhancedRequestForgeryProtection gets mixed into
# ActionController one can use class instance variables to pass
# information to +verify_authenticity_token+ and +hexdigest+. EnhancedRequestForgeryProtection uses the
# following attributes:
#
# <tt>authenticity_scope</tt>::
#     The scope of actions that use compatible authenticity tokens. Defaults to
#     <i>the ActionController's class name</i> which means that
#     +verify_authenticity_token+ only validates actions of that controller.
#     Override to broaden the scope.  Setting the scope in 2
#     controllers to the same value makes their authenticity tokens compatible.
# <tt>authenticity_window</tt>::
#     The time window within which the form has to be submitted and
#     verified. Defaults to <i>1 hour</i>.
# <tt>authenticity_flash_timed_out_msg</tt>::
#     The message to passed to the session flash if the authenticity
#     token arrives outside the authenticity window. Defaults to
#     <i>Form submission timed out. Please resubmit.</i>.
# <tt>authenticity_flash_invalid_msg</tt>::
#     The message to passed to the session flash if the authenticity_token doesn't
#     validate. Defaults to: <i>Possible form data tampering. Please
#     resubmit.</i>
module EnhancedRequestForgeryProtection
  extend ActiveSupport::Concern

  include AbstractController::Helpers

  included do
    helper_method :form_authenticity_token
  end

  module ClassMethods #:nodoc:
    def authenticity_scope
      @authenticity_scope ||= self.name
    end

    def authenticity_window
      @authenticity_window ||= 1.hour
    end

    def authenticity_timed_out_msg
      @authenticity_timed_out_msg ||= 'Form submission timed out. Please resubmit.'
    end

    def authenticity_invalid_msg
      @authenticity_invalid_msg ||= 'Possible form data tampering. Please resubmit.'
    end
  end

  module InstanceMethods #:doc:
    protected
      # The actual before_filter that is used.  Modify this to change how you handle unverified requests.
      def verify_authenticity_token
        verified_request? || handle_unverified_request
      end

      def handle_unverified_request
        if request.env['HTTP_REFERER']
          redirect_to request.env['HTTP_REFERER']
        else
          reset_session
        end
      end

      # Returns true or false if a request is verified.  Checks:
      #
      # * is it a GET request?  Gets should be safe and idempotent
      # * Does the form_authenticity_token match the given token value from the params?
      # * Does the X-CSRF-Token header match the form_authenticity_token
      def verified_request?
        return true if !protect_against_forgery? || request.get?
        @token = params[request_forgery_protection_token]
        @stamped_at, @digest = split_request_authenticity_token
        if @digest == hexdigest
          within_authenticity_window?
        else
          if request.headers['X-CSRF-Token']
            @token = request.headers['X-CSRF-Token']
            @stamped_at, @digest = split_request_authenticity_token
            if @digest == hexdigest
              within_authenticity_window?
            else
              log_authenticity_mismatch("Invalid X-CSRF-Token header")
              flash[:warning] = self.class.authenticity_invalid_msg
              false
            end
          else
            log_authenticity_mismatch("Invalid #{request_forgery_protection_token}")
            flash[:warning] = self.class.authenticity_invalid_msg
            false
          end
        end
      end

      # Generates a timestamped authenticity token
      def form_authenticity_token
        @private_form_authenticity_token ||= begin
          @stamped_at = timestamp
          "#{@stamped_at}#{hexdigest}"
        end
      end

      # Sets the token value for the current session.
      def csrf_token
        session[:_csrf_token] ||= ActiveSupport::SecureRandom.base64(32)
      end

      # Create a 10 digit timestamp for the current time
      def timestamp
        "%010d" % Time.now().to_i
      end

      # Create a hexadecimal digest of the request's remote IP address, the timestamp of the form authenticity token,
      # the CSRF token and the class' authenticity scope
      def hexdigest
        OpenSSL::Digest::SHA1.hexdigest("#{request.remote_ip}#{@stamped_at}#{csrf_token}#{self.class.authenticity_scope}")
      end

      # Split the request's authenticity token into the 2 components it is made up from: the timestamp of the token and
      # the hexadecimal digest.
      def split_request_authenticity_token
        @token.respond_to?(:[]) ? [@token[0..9], @token[10..-1]] : [nil, nil]
      end

      # Check if the request falls within the authenticity window of the class.
      def within_authenticity_window?
        if Time.at(@stamped_at.to_i) + self.class.authenticity_window > Time.now
          true
        else
          log_authenticity_mismatch("Authenticity token outside time window")
          # Replace the authenticity_invalid_msg if there was one.
          flash[:warning] = self.class.authenticity_timed_out_msg
          false
        end
      end

      # Log details of a authenticity_token mismatch to the application log.
      def log_authenticity_mismatch(msg)
        logger.warn("#{msg}:
    #{request_forgery_protection_token} = #{@token}
    timestamp = #{@stamped_at}
    remote_ip = #{request.remote_ip}
    csrf_token = #{csrf_token}
    scope = #{self.class.authenticity_scope}
    hexdigest = #{hexdigest}")
      end
  end
end

if defined?(ActionController::RequestForgeryProtection)
  ActiveSupport.on_load(:action_controller) do
    include EnhancedRequestForgeryProtection
  end
end