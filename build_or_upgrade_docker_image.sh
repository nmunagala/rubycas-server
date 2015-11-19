#development cas install script

DIRECTORY=/home/core/cas-dev/sinatra/
if [ -d "$DIRECTORY" ]; then
	cd /home/core/cas-dev/sinatra/
	git reset --hard HEAD
	git clean -f
	git pull
else
	git clone https://github.com/Navionics/rubycas-server.git /home/core/cas-dev/sinatra
	cd /home/core/cas-dev/sinatra/
	git checkout development
fi
# cd in repository just to be sure
cd /home/core/cas-dev/sinatra/
cp ../Dockerfile /home/core/cas-dev/sinatra/
docker build -t navionics/cas-dev:V4 .
docker stop rubycas-dev
docker rm rubycas-dev
docker create --name rubycas-dev -p 8080:8080 navionics/cas-dev:V4
docker start rubycas-dev