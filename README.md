# Navionics RubyCAS-Server
[ ![Codeship Status for Navionics/rubycas-server](https://codeship.io/projects/69ae2dc0-4350-0132-d403-66ccbeb6bad7/status)](https://codeship.io/projects/44658)


## Software

Provides single sign-on authentication for web applications, implementing the server-end of Jasig's CAS protocol. The project is forked by http://rubycas.github.com

## Vagrant Installation

Is possible to run this project using Vagrant, coreos and docker locally in easy way.
1. `git clone git@github.com:rubycas/rubycas-server.git`
2. `cd rubycas-server`
3. `cd coreos-vagrant`
4. `vagrant up`

## Manual Installation

Example with mysql database:

1. `git clone git@github.com:rubycas/rubycas-server.git`
2. `cd rubycas-server`
3. `cp configurations/config.example.yml config.yml`
4. Customize your server by modifying the `config.yml` file. It is well commented but make sure that you take care of the following:
    1. Change the database driver to `mysql2`
    2. Configure at least one authenticator
    3. You might want to change `log.file` to something local, so that you don't need root. For example just `casserver.log`
    4. You might also want to disable SSL for now by commenting out the `ssl_cert` line and changing the port to something like `8888`
5. Create the database (i.e. `mysqladmin -u root create casserver` or whatever you have in `config.yml`)
6. Modify the existing Gemfile by adding drivers for your database server. For example, if you configured `mysql2` in config.yml, add this to the Gemfile: `gem "mysql2"`
7. Run `bundle install`
8. `bundle exec rubycas-server -c config.yml`

## License

RubyCAS-Server is licensed for use under the terms of the MIT License.
See the LICENSE file bundled with the official RubyCAS-Server distribution for details.
