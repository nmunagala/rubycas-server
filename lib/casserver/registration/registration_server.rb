require 'casserver/utils'
require 'casserver/cas'
require 'casserver/base'

module CASServer
  class RegistrationServer < CASServer::Base

    if ENV['CONFIG_FILE']
      CONFIG_FILE = ENV['CONFIG_FILE']
    elsif !(c_file = File.dirname(__FILE__) + "/../../config.yml").nil? && File.exist?(c_file)
      CONFIG_FILE = c_file
    else
      CONFIG_FILE = "/etc/rubycas-server/config.yml"
    end

    include CASServer::CAS # CAS protocol helpers

    # Use :public_folder for Sinatra >= 1.3, and :public for older versions.
    def self.use_public_folder?
      Sinatra.const_defined?("VERSION") && Gem::Version.new(Sinatra::VERSION) >= Gem::Version.new("1.3.0")
    end

    set :app_file, __FILE__
    set( use_public_folder? ? :public_folder : :public, # Workaround for differences in Sinatra versions.
         Proc.new { settings.config[:public_dir] || File.join(root, "..", "..", "public") } )

    config = HashWithIndifferentAccess.new(
        :maximum_unused_login_ticket_lifetime => 5.minutes,
        :maximum_unused_service_ticket_lifetime => 5.minutes, # CAS Protocol Spec, sec. 3.2.1 (recommended expiry time)
        :maximum_session_lifetime => 2.days, # all tickets are deleted after this period of time
        :log => {:file => 'casserver.log', :level => 'DEBUG'},
        :uri_path => ""
    )
    set :config, config

    def self.uri_path
      config[:uri_path]
    end

    def self.is_empty?(text)
      text.nil? || text.blank?
    end

    def self.raise_if_user_not_configured(credentials)
      @nickname = credentials[:nickname]
      @email = credentials[:username]
      @email2 = credentials[:username2]
      @password = credentials[:password]
      raise CASServer::AuthenticatorError.new( t.error.empty_fields ) if is_empty? @nickname or is_empty? @email or is_empty? @email2 or is_empty? @password
    end

    def self.raise_if_username_different(credentials)
      email = credentials[:username]
      email2 = credentials[:username2]
      raise CASServer::AuthenticatorError.new( t.error.email_diff ) if email != email2
    end

    def self.raise_if_user_already_exists(email)
      results = user_model.find(:first, :conditions => ["email = ?", email])
      raise CASServer::AuthenticatorError.new( t.error.user_already_exists ) if !results.nil? && results.attributes['id'] > 0
    end

    def self.signup(params)
      # 2.2.2 (required)
      @nickname = params['nickname']
      @username = params['username']
      @username2 = params['username2']
      @password = params['password']
      @lt = params['lt']

      # Remove leading and trailing widespace from username.
      @email.strip! if @email

      if @email && settings.config[:downcase_username]
        $LOG.debug("Converting username #{@username.inspect} to lowercase because 'downcase_username' option is enabled.")
        @email.downcase!
      end

      credentials = {
          :nickname => @nickname,
          :username => @username,
          :username2 => @username2,
          :password => @password,
          :service => @service,
          :request => @env
      }
      raise_if_user_not_configured(credentials)
      raise_if_username_different(credentials)
      raise_if_user_already_exists(credentials[:username])

      credentials_are_valid = false
      extra_attributes = {}
      successful_authenticator = nil
      begin
        auth_index = 0
        settings.auth.each do |auth_class|
          auth = auth_class.new

          auth_config = settings.config[:authenticator][auth_index]
          # pass the authenticator index to the configuration hash in case the authenticator needs to know
          # it splace in the authenticator queue
          auth.configure(auth_config.merge('auth_index' => auth_index))

          $LOG.info("before inserting user")

          credentials_are_valid = auth.create_user(credentials)
          $LOG.info("after inserting user")

          if credentials_are_valid
            @authenticated = true
            @authenticated_username = @username
            extra_attributes.merge!(auth.extra_attributes) unless auth.extra_attributes.blank?
            successful_authenticator = auth
            break
          end

          auth_index += 1
        end

        if credentials_are_valid
          $LOG.info("Account for username '#{@username}' successfully created.")
          $LOG.debug("Authenticator provided additional user attributes: #{extra_attributes.inspect}") unless extra_attributes.blank?

          # 3.6 (ticket-granting cookie)
          tgt = generate_ticket_granting_ticket(@username, extra_attributes)
          response.set_cookie('tgt', tgt.to_s)
          @lt = generate_login_ticket.ticket

          $LOG.debug("Ticket granting cookie '#{tgt.inspect}' granted to #{@username.inspect}")

          if @service.blank?
            $LOG.info("Successfully authenticated user '#{@username}' at '#{tgt.client_hostname}'. No service param was given, so we will not redirect.")
            @message = {:type => 'confirmation', :message => t.notice.success_logged_in}
          else
            @st = generate_service_ticket(@service, @username, tgt)

            begin
              service_with_ticket = service_uri_with_ticket(@service, @st)

              $LOG.info("Redirecting authenticated user '#{@username}' at '#{@st.client_hostname}' to service '#{@service}'")
              redirect service_with_ticket, 303 # response code 303 means "See Other" (see Appendix B in CAS Protocol spec)
            rescue URI::InvalidURIError
              $LOG.error("The service '#{@service}' is not a valid URI!")
              @message = {
                  :type => 'mistake',
                  :message => t.error.invalid_target_service
              }
            end
          end
        else
          @form_action = "https://ec2-54-73-0-50.eu-west-1.compute.amazonaws.com/cas/signup"
          $LOG.warn("Impossibile to create account for user '#{@username}'")
          @message = {:type => 'mistake', :message => t.error.incorrect_username_or_password}
          $LOG.warn("Rendering....#{@template_engine},  #{:signup}")
          status 401
        end
      rescue CASServer::AuthenticatorError => e
        $LOG.error(e)
        # generate another login ticket to allow for re-submitting the form
        @lt = generate_login_ticket.ticket
        @message = {:type => 'mistake', :message => e.to_s}
        status 401
      end

      render @template_engine, :signup
    end
  end
end
