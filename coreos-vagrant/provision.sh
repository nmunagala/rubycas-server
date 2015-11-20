#!/bin/bash

args=$(getopt -l "env:" -o "s:h" -- "$@")

eval set -- "$args"
env="local"
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

DIRECTORY=/home/core/share/
cd $DIRECTORY
img_name=rubycas-$env
cp ../configurations/$env_config.yml config.yml
cd home/core/share/coreos-vagrant/
docker build -t navionics/$img_name:V4 .
docker stop $img_name
docker rm $img_name
docker create --name $img_name -p 8080:8080 navionics/$img_name:V4
docker start $img_name
