require File.expand_path(File.dirname(__FILE__) + '/../spec_helper')

describe "EnhancedRequestForgeryProtection" do
  describe "ClassMethods" do
    it "should assign an anonimous class the correct defaults" do
      klass = Class.new
      klass.send(:include, EnhancedRequestForgeryProtection)
      klass.authenticity_scope.to_s.should eq ""
      klass.authenticity_window.should eq 1.hour
      klass.authenticity_timed_out_msg.should eq 'Form submission timed out. Please resubmit.'
      klass.authenticity_invalid_msg.should eq 'Possible form data tampering. Please resubmit.'
    end

    it "should assign a named class the correct defaults" do
      class Klass
        include EnhancedRequestForgeryProtection
      end
      Klass.authenticity_scope.should eq 'Klass'
      Klass.authenticity_window.should eq 1.hour
      Klass.authenticity_timed_out_msg.should eq 'Form submission timed out. Please resubmit.'
      Klass.authenticity_invalid_msg.should eq 'Possible form data tampering. Please resubmit.'
    end

    it "should override defaults through class instance variables" do
      klass = Class.new do
        include EnhancedRequestForgeryProtection
        @authenticity_scope = "my scope"
        @authenticity_window = 1.day
        @authenticity_timed_out_msg = "Slow poke!"
        @authenticity_invalid_msg = "Invalid"
      end
      klass.authenticity_scope.should eq "my scope"
      klass.authenticity_window.should eq 1.day
      klass.authenticity_timed_out_msg.should eq 'Slow poke!'
      klass.authenticity_invalid_msg.should eq 'Invalid'
    end
  end

  describe "InstanceMethods" do
    before :each do
      class Object
        remove_const :Klass
      end
      class Klass
        include EnhancedRequestForgeryProtection
      end
    end

    it "should verify authenticity when the request is verified" do
      klass = Klass.new
      klass.stub(:verified_request?) { true }
      klass.send(:verify_authenticity_token).should eq true
    end

    it "should reset the session when there is no referrer" do
      klass = Klass.new
      klass.stub(:verified_request?) { false }
      klass.stub_chain(:request, :env) { {} }
      klass.stub(:reset_session) { :reset_session }
      klass.send(:verify_authenticity_token).should eq :reset_session
    end

    it "should redirect to the referrer" do
      klass = Klass.new
      klass.stub(:verified_request?) { false }
      klass.stub_chain(:request, :env) { {"HTTP_REFERER" => :URL} }
      klass.stub(:redirect_to) do |arg|
        arg
      end
      klass.send(:verify_authenticity_token).should eq :URL
    end

    it "should return the same form authenticity token for a single request" do
      klass = Klass.new
      klass.stub_chain(:request, :remote_ip) { "127.0.0.1" }
      klass.stub(:session) { {:_csrf_token => "2b5194e50c68243dca0bde800d0d1473c3cbc"} }
      first_token = klass.send(:form_authenticity_token)
      sleep 1
      first_token.should eq klass.send(:form_authenticity_token)
    end

    it "should be able to split an incoming authenticity token into a timestamp and digest" do
      klass = Klass.new
      klass.stub_chain(:request, :remote_ip) { "127.0.0.1" }
      klass.stub(:session) { {:_csrf_token => "2b5194e50c68243dca0bde800d0d1473c3cbc"} }
      klass.instance_eval { @token = klass.send(:form_authenticity_token) }
      klass.instance_eval { @token }.should eq klass.send(:form_authenticity_token)
      time_stamp, digest = klass.send(:split_request_authenticity_token)
      digest.should eq klass.send(:hexdigest)
      time_stamp.should eq klass.instance_eval { @stamped_at }
    end

    it "should reject requests outside the class's authenticity window" do
      klass = Klass.new
      class Klass
        @authenticity_window = -1.day
      end
      Klass.authenticity_window.should eq -1.day
      logger = double("Logger")
      logger.stub(:warn) { |arg| arg }
      klass.stub(:logger) { logger }
      klass.stub(:request_forgery_protection_token) { "" }
      klass.stub(:flash) { {} }
      klass.stub_chain(:request, :remote_ip) { "127.0.0.1" }
      klass.stub(:session) { {:_csrf_token => "2b5194e50c68243dca0bde800d0d1473c3cbc"} }
      klass.send(:form_authenticity_token)
      klass.send(:within_authenticity_window?).should eq false
    end

    it "should accept requests inside the class's authenticity window" do
      klass = Klass.new
      klass.stub_chain(:request, :remote_ip) { "127.0.0.1" }
      klass.stub(:session) { {:_csrf_token => "2b5194e50c68243dca0bde800d0d1473c3cbc"} }
      klass.send(:form_authenticity_token)
      klass.send(:within_authenticity_window?).should eq true
    end

    it "should verify GET requests" do
      klass = Klass.new
      klass.stub(:protect_against_forgery?) { true }
      klass.stub_chain(:request, :get?) { true }
      klass.send(:verified_request?).should eq true
    end

    it "should verify non GET requests when protection against forgery is turned off" do
      klass = Klass.new
      klass.stub(:protect_against_forgery?) { false }
      klass.stub_chain(:request, :get?) { false }
      klass.send(:verified_request?).should eq true
    end

    it "should verify a request forgery protection token passed in as a parameter" do
      klass = Klass.new
      klass.stub(:protect_against_forgery?) { true }
      klass.stub_chain(:request, :get?) { false }
      klass.stub(:request_forgery_protection_token) { :_token }
      klass.stub_chain(:request, :remote_ip) { "127.0.0.1" }
      klass.stub(:session) { {:_csrf_token => "2b5194e50c68243dca0bde800d0d1473c3cbc"} }
      klass.stub(:params) { {:_token => klass.send(:form_authenticity_token)} }
      klass.send(:verified_request?).should eq true
    end

    it "should verify a request forgery protection token passed in as a header" do
      klass = Klass.new
      klass.stub(:protect_against_forgery?) { true }
      klass.stub_chain(:request, :get?) { false }
      klass.stub(:params) { {:_token => ""} }
      klass.stub(:request_forgery_protection_token) { :_token }
      klass.stub_chain(:request, :remote_ip) { "127.0.0.1" }
      klass.stub(:session) { {:_csrf_token => "2b5194e50c68243dca0bde800d0d1473c3cbc"} }
      klass.stub_chain(:request, :headers) { {'X-CSRF-Token' => klass.send(:form_authenticity_token)} }
      logger = double("Logger")
      logger.stub(:warn) { |arg| arg }
      klass.stub(:logger) { logger }
      klass.send(:verified_request?)
      klass.send(:verified_request?).should eq true
    end

    it "should log an invalid request forgery protection token" do
      # Invalid token in the parameters with valid timestamp and no token in the header
      klass = Klass.new
      klass.stub(:protect_against_forgery?) { true }
      klass.stub_chain(:request, :get?) { false }
      klass.stub(:params) { {:_token => klass.instance_eval {timestamp} } }
      klass.stub(:request_forgery_protection_token) { :_token }
      klass.stub_chain(:request, :remote_ip) { "127.0.0.1" }
      klass.stub(:session) { {:_csrf_token => "2b5194e50c68243dca0bde800d0d1473c3cbc"} }
      klass.stub_chain(:request, :headers) { {} }
      klass.stub(:log_authenticity_mismatch) { |arg| arg.should eq "Invalid _token" }
      hsh = Hash.new
      klass.stub(:flash) { hsh }
      klass.send(:verified_request?).should eq false
      klass.instance_eval{ flash[:warning] }.should eq Klass.authenticity_invalid_msg

      # No token at all
      klass.stub(:params) { {} }
      klass.send(:verified_request?).should eq false
      klass.instance_eval{ flash[:warning] }.should eq Klass.authenticity_invalid_msg

      # No token in the parameters, invalid token in the header
      klass.stub_chain(:request, :headers) { {"X-CSRF-Token" => klass.instance_eval {timestamp} } }
      klass.stub(:log_authenticity_mismatch) { |arg| arg.should eq "Invalid X-CSRF-Token header" }
      klass.send(:verified_request?).should eq false
      klass.instance_eval{ flash[:warning] }.should eq Klass.authenticity_invalid_msg
    end
  end
end