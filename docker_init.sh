#!/bin/bash

if [[ -z $TERM ]]; then
	export TERM=xterm
fi

# cgroup v2: enable nesting
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
	# move the processes from the root group to the /init group,
	# otherwise writing subtree_control fails with EBUSY.
	# An error during moving non-existent process (i.e., "cat") is ignored.
	mkdir -p /sys/fs/cgroup/init
	xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || :
	# enable controllers
	sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers \
		> /sys/fs/cgroup/cgroup.subtree_control
fi


mkdir /tmp/docker
mkdir /tmp/scratch
mkdir -p /data-root
mount | grep tmpfs

/usr/bin/qemu-arm-static --version
mount binfmt_misc -t binfmt_misc /proc/sys/fs/binfmt_misc



# setup dockerd
if [[ -n "$DOCKER_HOST" || -n "$POD_NAME" ]]; then
    export DOCKER_HOST='tcp://127.0.0.1:2375'
else # local
    mount -t tmpfs -o rw,size=8G tmpfs /data-root

    JOB_INDEX="1"
    mkdir -p /work/$JOB_INDEX
    mv /work/FirmAE /work/$JOB_INDEX/FirmAE

    cat <<EOF > /etc/docker/daemon.json
{
    "storage-driver": "overlay2",
    "data-root": "/data-root"
}
EOF
    dockerd > /dev/null &
fi



MAX_CHECKS=100
CHECK_COUNT=0
DOCKER_RUNNING=false

while [ $CHECK_COUNT -lt $MAX_CHECKS ]; do
    if docker ps > /dev/null 2>&1; then
        echo "Docker daemon is running."
        DOCKER_RUNNING=true
        break
    else
        ((CHECK_COUNT++))
        echo "Docker daemon is not running. Attempt $CHECK_COUNT of $MAX_CHECKS. Waiting..."
        sleep 5
    fi
done

if [ "$DOCKER_RUNNING" = false ]; then
    echo "Maximum number of attempts reached. Docker daemon is still not running."
    echo "=== Memory info ==="
    free -h 2>/dev/null || cat /proc/meminfo
    echo "=== Disk/tmpfs info ==="
    df -h
    echo "=== Processes ==="
    ps aux 2>/dev/null
    exit 1
fi


sleep 2
echo "========================================"
docker ps
echo "========================================"
ps -aux
echo "========================================"

docker load -i /docker_img/ubuntu32.tar
docker tag cc30 32bit/ubuntu:16.04


sleep 2
echo "========================================"
docker images
echo "========================================"

# setup binfmt
docker load -i /docker_img/multiarch_qemu-user-static_latest.tar
docker tag 3539 multiarch/qemu-user-static:latest
docker run --rm --privileged multiarch/qemu-user-static:latest --reset -p yes
docker rmi multiarch/qemu-user-static:latest


echo -1 > /proc/sys/fs/binfmt_misc/qemu-mipsn32
echo -1 > /proc/sys/fs/binfmt_misc/qemu-mipsn32el
echo -1 > /proc/sys/fs/binfmt_misc/qemu-mips64el
echo -1 > /proc/sys/fs/binfmt_misc/qemu-mips64

echo "======================================"
ls /proc/sys/fs/binfmt_misc
ps -aux


mkdir /results
mkdir /tmp/logs
mkdir /patches
mkdir /cache

if [[ ! -e /host/dev ]]; then
 	ln -s /dev /host/dev
fi


echo "--------------------------------------------------------------------"



echo "192.168.0.1 tendawifi.com" >> /etc/hosts
echo "192.168.1.1 tendawifi.com" >> /etc/hosts
echo "192.168.1.1 router" >> /etc/hosts
echo "192.168.0.1 router" >> /etc/hosts
echo "192.168.1.1 www.mywifiext.net" >> /etc/hosts
echo "192.168.0.1 www.mywifiext.net" >> /etc/hosts
echo "192.168.0.254 tplinkrepeater.net" >> /etc/hosts
echo "192.168.1.1 tplinkrepeater.net" >> /etc/hosts
echo "192.168.0.1 tplinkrepeater.net" >> /etc/hosts
echo "192.168.1.1 routerlogin.net" >> /etc/hosts
echo "192.168.0.1 routerlogin.net" >> /etc/hosts
echo "192.168.0.1 www.routerlogin.net" >> /etc/hosts
echo "192.168.1.1 www.routerlogin.net" >> /etc/hosts


sysctl -w vm.dirty_bytes=134217728
sysctl -w vm.dirty_background_ratio=15
ulimit -c 0 # disable
#ulimit -c unlimited # enable

echo 1 > /proc/sys/vm/overcommit_memory


# set ghidra memory
sed -i 's/VMARG_LIST="-XX:ParallelGCThreads=2 -XX:CICompilerCount=2"/VMARG_LIST="-XX:ParallelGCThreads=2 -XX:CICompilerCount=2 -Xmx2G"/' /ghidra_11.2_PUBLIC/support/analyzeHeadless

PG_STATUS=/tmp/PG_STATUS_LOG
sed -i "s/#huge_pages = try/huge_pages = off/" /usr/share/postgresql/12/postgresql.conf.sample
sudo pg_dropcluster 12 main
sudo pg_createcluster 12 main
sudo /etc/init.d/postgresql restart
sudo -u postgres bash -c "psql -c \"CREATE USER firmadyne WITH PASSWORD 'firmadyne';\"" > /dev/null
sudo -u postgres createdb -O firmadyne firmware > /dev/null
sudo -u postgres psql -d firmware < /work/$JOB_INDEX/FirmAE/database/schema  > /dev/null

sudo service postgresql stop
sudo service postgresql start
sleep 5
sudo service postgresql status > $PG_STATUS 2>&1
sleep 1

PG_FAILED=`grep ": down" $PG_STATUS`
if [[ $PG_FAILED != "" ]]; then
	echo "pg_ctl failed on " $NODE_NAME >> ${LOCAL_OUT}
	cp ${LOCAL_OUT} ${OUT_PATH}
	echo "PG STATUS:"
	cat $PG_STATUS
	sleep 30s
	exit 1
fi


