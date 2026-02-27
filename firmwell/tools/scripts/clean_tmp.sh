find /tmp -mindepth 1 -maxdepth 1 -type d -name 'docker' -prune -o -exec rm -rf {} \; # keep /tmp/docker

docker stop $(docker ps -aq)
docker rm $(docker ps -aq)
