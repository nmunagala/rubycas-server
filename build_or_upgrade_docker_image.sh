#!/bin/bash

args=$(getopt -l "env:" -o "s:h" -- "$@")

eval set -- "$args"

while [ $# -ge 1 ]; do
        case "$1" in
                -e|--env)
                        env="$2"
                        shift
                        ;;
                -h)
                        echo "Build rubycas environment"
                        echo "-e --env use this environment to build rubycas (local|dev|production)"
                        exit 0
                        ;;
        esac
        shift
done

echo "env: $env"

DIRECTORY=/home/core/cas-$env/sinatra/
if [ -d "$DIRECTORY" ]; then
	cd $DIRECTORY
	git reset --hard HEAD
	git clean -f
	git pull
else
	git clone https://github.com/Navionics/rubycas-server.git $DIRECTORY
	cd $DIRECTORY
    case "$env" in
        ("local") git checkout development ;;
        ("dev") git checkout development ;;
        ("production") git checkout master;;
        (*) git checkout development ;;
    esac
fi
# cd in repository just to be sure
cd $DIRECTORY
cp ../Dockerfile $DIRECTORY
img_name=rubycas-$env
docker build -t navionics/$img_name:V4 .
docker stop $img_name
docker rm $img_name
docker create --name $img_name -p 8080:8080 navionics/$img_name:V4
docker start $img_name