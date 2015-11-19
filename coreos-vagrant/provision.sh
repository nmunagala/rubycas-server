cd /home/core/share/
docker build -t navionics/cas-dev:V4 .
docker stop rubycas-dev
docker rm rubycas-dev
docker create --name rubycas-dev -p 8080:8080 navionics/cas-dev:V4
docker start rubycas-dev