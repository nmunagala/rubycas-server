require 'casserver/utils'
require 'casserver/cas'
require 'casserver/base'

module CASServer
  class RegistrationServer < Server
    # The #.#.# comments (e.g. "2.1.3") refer to section numbers in the CAS protocol spec
    # under http://www.ja-sig.org/products/cas/overview/protocol/index.html

    # 2.1 :: Login

    # 2.1.1
    get "#{uri_path}/sign_up" do
    end

    # 2.2
    post "#{uri_path}/sign_up" do
    end
  end
end
