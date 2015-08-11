require 'casserver/authenticators/sql'

require 'digest/sha1'
require 'digest/sha2'
require 'crypt-isaac'

# This is a more secure version of the SQL authenticator. Passwords are encrypted
# rather than being stored in plain text.
#
# Based on code contributed by Ben Mabey.
#
# Using this authenticator requires some configuration on the client side. Please see
# http://code.google.com/p/rubycas-server/wiki/UsingTheSQLEncryptedAuthenticator
class CASServer::Authenticators::SQLEncrypted < CASServer::Authenticators::SQL
  # Include this module into your application's user model.
  #
  # Your model must have an 'encrypted_password' column where the password will be stored,
  # and an 'encryption_salt' column that will be populated with a random string before
  # the user record is first created.
  module EncryptedPassword
    def self.included(mod)
      raise "#{self} should be inclued in an ActiveRecord class!" unless mod.respond_to?(:before_save)
      #mod.before_save :generate_encryption_salt
    end

    def encrypt(str)
      generate_encryption_salt unless encryption_salt
      Digest::SHA256.hexdigest("#{encryption_salt}::#{str}")
    end

    def password=(password)
      self[:encrypted_password] = encrypt(password)
    end

    def generate_encryption_salt
      self.encryption_salt = Digest::SHA1.hexdigest(Crypt::ISAAC.new.rand(2**31).to_s) unless encryption_salt
    end
  end

  def self.setup(options)
    super(options)
    user_model = user_models[options[:auth_index]]
    user_model.__send__(:include, EncryptedPassword)
  end

  def validate(credentials)
    read_standard_credentials(credentials)
    raise_if_not_configured

    username_column = @options[:username_column] || "username"
    encrypt_function = @options[:encrypt_function] || 'user.encrypted_password == Digest::SHA1.hexdigest("--#{user
.salt}--#{@password}--")'

    log_connection_pool_size
    results = user_model.find(:all, :conditions => ["#{username_column} = ?", @username])
    user_model.connection_pool.checkin(user_model.connection)

    if results.size > 0
      $LOG.warn("Multiple matches found for user '#{@username}'") if results.size > 1
      user = results.first
      unless @options[:extra_attributes].blank?
        if results.size > 1
          $LOG.warn("#{self.class}: Unable to extract extra_attributes because multiple matches were found for #{@username.inspect}")
        else
          extract_extra(user)
              log_extra
        end
      end
      return eval(encrypt_function)
    else
      return false
    end
  end

  def encrypt(string1, string2)
    generate_hash("--#{string1}--#{string2}--")
  end

  def generate_hash(string)
    Digest::SHA1.hexdigest(string)
  end

  def create_user(credentials)
    salt = generate_hash("--#{Time.now.utc.to_s}--#{credentials[:password]}--")
    encrypted_pwd =  encrypt(salt, credentials[:password])
    token = encrypt(Time.now.utc.to_s, credentials[:password])
    token_expires_at = nil

    log_connection_pool_size
    user_model.connection_pool.checkin(user_model.connection)

    results = user_model.create({:nickname => credentials[:nickname], :email => credentials[:username],
                                 :encrypted_password => encrypted_pwd, :salt => salt,
                                 :token => token, :token_expires_at => token_expires_at})

    unless results.nil? && @options[:extra_attributes].blank?
      extract_extra(results)
      log_extra
    end
    return results.nil? ? false : results.attributes['id'] > 0
  end

  def find_user_by_email(email)
    log_connection_pool_size
    user_model.connection_pool.checkin(user_model.connection)

    results = user_model.find(:first, :conditions => ["email = ?", email])

    return results.nil? ? false : results.attributes['id'] > 0
  end

  def find_user_by_nickname(nickname)
    log_connection_pool_size
    user_model.connection_pool.checkin(user_model.connection)

    results = user_model.find(:first, :conditions => ["nickname = ?", nickname])

    return results.nil? ? false : results.attributes['id'] > 0

  end

  def existing_user(credentials)
    read_standard_credentials(credentials)
    raise_if_not_configured
    username_column = @options[:username_column] || "username"
    result = user_model.find(:first, :conditions => ["#{username_column} = ?", @username])
  end

  def update_user_password(credentials)
    read_standard_credentials(credentials)
    raise_if_not_configured

    salt = Digest::SHA1.hexdigest("--#{Time.now.utc.to_s}--#{@password}--")
    encrypted_pwd = Digest::SHA1.hexdigest("--#{salt}--#{@password}--")

    username_column = @options[:username_column] || "username"
    log_connection_pool_size
    results = user_model.find(:all, :conditions => ["#{username_column} = ?", @username])
    user_model.connection_pool.checkin(user_model.connection)

    if results.size > 0
      $LOG.warn("Multiple matches found for user '#{@username}'") if results.size > 1
      user = results.first
      unless @options[:extra_attributes].blank?
        if results.size > 1
          $LOG.warn("#{self.class}: Unable to extract extra_attributes because multiple matches were found for #{@username.inspect}")
        else
          extract_extra(user)
          log_extra
        end
      end
      user.encrypted_password = encrypted_pwd
      user.salt = salt

      return user.save()
    else
      return false
    end
  end

  def update_user_nickname(credentials)
    read_standard_credentials(credentials)
    raise_if_not_configured

    username_column = @options[:username_column] || "username"
    log_connection_pool_size
    results = user_model.find(:all, :conditions => ["#{username_column} = ?", @username])
    user_model.connection_pool.checkin(user_model.connection)

    if results.size > 0
      $LOG.warn("Multiple matches found for user '#{@username}'") if results.size > 1
      user = results.first
      user.nickname = credentials[:nickname]
      unless @options[:extra_attributes].blank?
        if results.size > 1
          $LOG.warn("#{self.class}: Unable to extract extra_attributes because multiple matches were found for #{@username.inspect}")
        else
          extract_extra(user)
          log_extra
        end
      end

      return user.save()
    else
      return false
    end
  end

end
