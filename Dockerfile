FROM ubuntu:14.04

# Install packages for building ruby
RUN apt-get update
RUN apt-get install -y --force-yes build-essential wget git
RUN apt-get install -y --force-yes zlib1g-dev libssl-dev libreadline-dev libyaml-dev libxml2-dev libxslt-dev libmysqlclient-dev mysql-client libsqlite3-dev nano
RUN apt-get install -y --force-yes ruby2.0 ruby2.0-dev
RUN apt-get clean

RUN ln -sf /usr/bin/ruby2.0 /usr/bin/ruby
RUN ln -sf /usr/bin/gem2.0 /usr/bin/gem
RUN gem update --system
RUN gem install bundler

ADD . /home/core/sinatra-dev
RUN cd /home/core/sinatra-dev; git checkout development
RUN cd /home/core/sinatra-dev; mv configurations/dev_config.yml config.yml
RUN cd /home/core/sinatra-dev; bundle install
RUN cd /home/core/sinatra-dev; sed -i 's/port\: 80/port: 8080/g' config.yml
EXPOSE 8080
WORKDIR /home/core/sinatra-dev
CMD ["/usr/local/bin/bundle", "exec", "rubycas-server", "--host", "127.0.0.1", "-p", "8080", "-c","config.yml"]
