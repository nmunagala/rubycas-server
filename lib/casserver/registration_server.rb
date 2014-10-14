require 'casserver/utils'
require 'casserver/cas'
require 'casserver/base'

module CASServer
  class RegistrationServer < Server
    get "#{uri_path}/signup" do
      CASServer::Utils::log_controller_action(self.class, params)

      # make sure there's no caching
      headers['Pragma'] = 'no-cache'
      headers['Cache-Control'] = 'no-store'
      headers['Expires'] = (Time.now - 1.year).rfc2822

      # optional params
      @service = clean_service_url(params['service'])
      @renew = params['renew']
      @gateway = params['gateway'] == 'true' || params['gateway'] == '1'

      if tgc = request.cookies['tgt']
        tgt, tgt_error = validate_ticket_granting_ticket(tgc)
      end

      if tgt and !tgt_error
        @authenticated = true
        @authenticated_username = tgt.username
        @message = {:type => 'notice',
                    :message => t.notice.logged_in_as(tgt.username)}
      elsif tgt_error
        $LOG.debug("Ticket granting cookie could not be validated: #{tgt_error}")
      elsif !tgt
        $LOG.debug("No ticket granting ticket detected.")
      end

      if params['redirection_loop_intercepted']
        @message = {:type => 'mistake',
                    :message => t.error.unable_to_authenticate}
      end

      begin
        if @service
          if @renew
            $LOG.info("Authentication renew explicitly requested. Proceeding with CAS login for service #{@service.inspect}.")
          elsif tgt && !tgt_error
            $LOG.debug("Valid ticket granting ticket detected.")
            st = generate_service_ticket(@service, tgt.username, tgt)
            service_with_ticket = service_uri_with_ticket(@service, st)
            $LOG.info("User '#{tgt.username}' authenticated based on ticket granting cookie. Redirecting to service '#{@service}'.")
            redirect service_with_ticket, 303 # response code 303 means "See Other" (see Appendix B in CAS Protocol spec)
          elsif @gateway
            $LOG.info("Redirecting unauthenticated gateway request to service '#{@service}'.")
            redirect @service, 303
          else
            $LOG.info("Proceeding with CAS login for service #{@service.inspect}.")
          end
        elsif @gateway
          $LOG.error("This is a gateway request but no service parameter was given!")
          @message = {:type => 'mistake',
                      :message => t.error.no_service_parameter_given}
        else
          $LOG.info("Proceeding with CAS login without a target service.")
        end
      rescue URI::InvalidURIError
        $LOG.error("The service '#{@service}' is not a valid URI!")
        @message = {:type => 'mistake',
                    :message => t.error.invalid_target_service}
      end

      lt = generate_login_ticket

      $LOG.debug("Rendering login form with lt: #{lt}, service: #{@service}, renew: #{@renew}, gateway: #{@gateway}")

      @lt = lt.ticket

      #$LOG.debug(env)

      # If the 'onlyLoginForm' parameter is specified, we will only return the
      # login form part of the page. This is useful for when you want to
      # embed the login form in some external page (as an IFRAME, or otherwise).
      # The optional 'submitToURI' parameter can be given to explicitly set the
      # action for the form, otherwise the server will try to guess this for you.
      if params.has_key? 'onlyLoginForm'
        if @env['HTTP_HOST']
          guessed_login_uri = "http#{@env['HTTPS'] && @env['HTTPS'] == 'on' ? 's' : ''}://#{@env['REQUEST_URI']}/signup}"
        else
          guessed_login_uri = nil
        end

        @form_action = params['submitToURI'] || guessed_login_uri

        if @form_action
          render @template_engine, :login
        else
          status 500
          render t.error.invalid_submit_to_uri
        end
      else
        render @template_engine, :login
      end
    end

    # 2.2
    post "#{uri_path}/signup" do
      Utils::log_controller_action(self.class, params)

      # 2.2.1 (optional)
      @service = clean_service_url(params['service'])

      # 2.2.2 (required)
      @username = params['username']
      @password = params['password']
      @lt = params['lt']

      # Remove leading and trailing widespace from username.
      @username.strip! if @username

      if @username && settings.config[:downcase_username]
        $LOG.debug("Converting username #{@username.inspect} to lowercase because 'downcase_username' option is enabled.")
        @username.downcase!
      end

      if error = validate_login_ticket(@lt)
        @message = {:type => 'mistake', :message => error}
        # generate another login ticket to allow for re-submitting the form
        @lt = generate_login_ticket.ticket
        status 500
        return render @template_engine, :login
      end

      # generate another login ticket to allow for re-submitting the form after a post
      @lt = generate_login_ticket.ticket

      $LOG.debug("Logging in with username: #{@username}, lt: #{@lt}, service: #{@service}, auth: #{settings.auth.inspect}")

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

          credentials_are_valid = Users.create({
            :username => @username,
            :password => @password,
            :service => @service,
            :request => @env
          })
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
          $LOG.info("Credentials for username '#{@username}' successfully created.")
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
          @form_action = "https://cas.navionics.com/cas/login"
          $LOG.warn("Invalid credentials given for user '#{@username}'")
          @message = {:type => 'mistake', :message => t.error.incorrect_username_or_password}
          $LOG.warn("Rendering....#{@template_engine},  #{:login}")
          status 401
        end
      rescue CASServer::AuthenticatorError => e
        $LOG.error(e)
        # generate another login ticket to allow for re-submitting the form
        @lt = generate_login_ticket.ticket
        @message = {:type => 'mistake', :message => e.to_s}
        status 401
      end

      render @template_engine, :login
    end

  end
end
