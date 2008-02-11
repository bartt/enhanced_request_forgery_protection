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

  def self.included(base) #:nodoc:
    base.send(:extend, ClassMethods)
    base.send(:include, InstanceMethods)
    base.class_eval do
      helper_method :issue_crumb
    end
  end

  module ClassMethods
    def crumb_scope
      @crumb_scope ||= self.name
    end

    def crumb_window
      @crumb_window ||= '15.minutes'
    end

    def crumb_flash_msg
      @crumb_flash_msg ||= 'Form submission timed out. Please resubmit.'
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
    # <tt>cookies[:_session_id]</tt>::
    #     The session's ID
    # <tt>crumb_scope</tt>::
    #     A class attribute in the ActionController where crumblr is used.
    # <tt>session[:crumb_secret]</tt>::
    #     A random string acting as salt
    def issue_crumb(timestamp)
      session[:crumb_secret] = String.rand(6) unless session[:crumb_secret] 
      signature = "#{request.remote_ip}#{timestamp}#{cookies[:_session_id]}#{self.class.crumb_scope}#{session[:crumb_secret]}"
      logger.debug("_session_id = #{cookies[:_session_id]}
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
      if (request.post? || request.put? || request.delete?) then
        logger.debug("Crumb window = #{self.class.crumb_window}\nCrumb flash msg = #{self.class.crumb_flash_msg}")
        if (defined?(params[:_crumb]) && 
              defined?(params[:_timestamp]) && 
              Time.at(params[:_timestamp].to_i) + self.class.crumb_window > Time.now &&
              (params[:_crumb] == OpenSSL::Digest::SHA1.hexdigest("#{request.remote_ip}#{params[:_timestamp]}#{cookies[:_session_id]}#{self.class.crumb_scope}#{session[:crumb_secret]}"))) then
          return true
        else
          logger.warn("Invalid crumb:
_crumb = #{params[:_crumb]}
_timestamp = #{params[:_timestamp]}
remote_ip = #{request.remote_ip}
_session_id = #{cookies[:_session_id]}
scope = #{self.class.crumb_scope}
crumb_secret = #{session[:crumb_secret]}
digest = #{OpenSSL::Digest::SHA1.hexdigest("#{request.remote_ip}#{params[:_timestamp]}#{cookies[:_session_id]}#{session[:crumb_secret]}")}")
          # Return the visitor to the origin of the request. Most
          # often this will be local URL and this redirect will
          # re-issue new crumbs. No harm done if the referrer is an
          # external site. Crumblr's goal is to only accept requests
          # from specific local origins.
          if request.env['HTTP_REFERER']
            flash[:warning] = self.class.crumb_flash_msg
            redirect_to request.env['HTTP_REFERER'] 
          else
            # Return standard 404 message. Let the ActionController's
            # rescue mechanisme handle this routing error rather then
            # explicitly returning the default public/404.html
            # file. Only report the lowest stack level in the error
            # log.
            raise ActionController::RoutingError, "Invalid crumb: #{params[:_crumb]}", caller(0)[0]
          end
        end
      else
        return true
      end
    end
  end

end
