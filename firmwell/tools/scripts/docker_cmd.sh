cat << 'EOF' >> ~/.zshrc
# alias
function doexec() {
    docker exec -it "$1" /bin/bash
}

function dobuild(){
    docker-compose build
    docker-compose up
}

alias dodown="docker-compose down -v"
#alias dobuild="docker-compose build"
#alias doup="docker-compose up"
alias dops="docker ps -a"
alias dorm="docker rm"
alias do="docker"

function doin() {
    container_name=$(docker ps -q -n 1)
    docker exec -it "$container_name" /bin/bash
}

function doinsh() {
    container_name=$(docker ps -q -n 1)
    docker exec -it "$container_name" /bin/sh
}

alias mgetpods="minikube kubectl -- get pods"
alias mapply="minikube kubectl -- apply -f gh_job.yaml"
alias mdelete="minikube kubectl -- delete -f gh_job.yaml"

function klogs() {
    kubectl logs "$1"
}

function dormc() {
    docker kill $(docker ps -q)
    docker stop $(docker ps -q)
    docker rm $(docker ps -a -q)
}

# export DOCKER_HOST=127.0.0.1:2375

source /root/venv/bin/activate
