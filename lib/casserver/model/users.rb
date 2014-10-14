module CASServer::Model
  class Users < CASServer::Authenticators::SQL
    def self.create(params)
      nickname = params[:nickname]
      username = params[:username]
      encrypted_password = encrypt_pwd params[:password]
      user_model.create({:nickname => nickname, :username => username, :encrypted_password => encrypted_password} )
    end

    private
    def encrypt_pwd(pwd)
      salt = generate_hash("--#{Time.now.utc.to_s}--#{pwd}--")
      encrypted_password = Digest::SHA1.hexdigest("--#{salt}--#{pwd}")
    end
  end
end
