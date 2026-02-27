# Deploying a Kubernetes Cluster

This document describes how to set up a Kubernetes cluster (v1.28) on Ubuntu 20.04 for artifact evaluation, including container runtime, local Docker registry, and NFS shared storage for firmware analysis.

# 1. Kubernetes
## 1.1 Install Kubernetes Components

```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gpg
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
```

## 1.2 Prepare All Nodes (Control Plane and Workers)

### 1.2.1 Set Hostnames and Update /etc/hosts
```bash
sudo hostnamectl set-hostname <your-hostname>
# Optionally edit /etc/hosts to include all nodes' IPs and hostnames
```

### 1.2.2 Disable Swap
```bash
sudo swapoff -a
sudo sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
```

### 1.2.3 Load Kernel Modules for Networking

```bash
echo br_netfilter | sudo tee /etc/modules-load.d/br_netfilter.conf
sudo systemctl restart systemd-modules-load.service
sudo modprobe br_netfilter
echo 1 | sudo tee /proc/sys/net/bridge/bridge-nf-call-iptables
echo 1 | sudo tee /proc/sys/net/bridge/bridge-nf-call-ip6tables
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo sysctl --system
```

### 1.2.4 Install Container Runtime (containerd)

 Download and Install containerd

```bash
sudo apt update
sudo apt install -y wget tar
wget https://github.com/containerd/containerd/releases/download/v1.7.12/containerd-1.7.12-linux-amd64.tar.gz
sudo tar Cxzvf /usr/local containerd-1.7.12-linux-amd64.tar.gz
```


### 1.2.5 Configure and Start containerd

```bash
sudo mkdir -p /etc/containerd
sudo containerd config default | sudo tee /etc/containerd/config.toml
```



```
sudo systemctl daemon-reload
sudo systemctl start containerd
sudo systemctl enable containerd
sudo systemctl status containerd
```

### 1.2.6 Install and Test crictl

```bash
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.28.0/crictl-v1.28.0-linux-amd64.tar.gz
tar -zxvf crictl-v1.28.0-linux-amd64.tar.gz
sudo install -m 755 crictl /usr/local/bin/crictl
crictl --runtime-endpoint=unix:///run/containerd/containerd.sock version
```



## 1.3 Initialize the Control Plane Node

On the master/control-plane node:

```bash
sudo kubeadm init
```

Configure `kubectl` for your user:

```bash
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

## 1.4. Join Worker Nodes

On each worker node, use the join command output by `kubeadm init` (example):

```bash
sudo kubeadm join <control-plane-ip>:6443 --token <token> --discovery-token-ca-cert-hash sha256:<hash>
```

## 1.5. Install CNI Plugin (Flannel Example)

On the control-plane node:

```bash
kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
```

Wait for all nodes to become `Ready`:

```bash
kubectl get nodes
```

## 1.6. Set Up NFS Shared Storage

### 1.6.1 On the NFS Server (host or dedicated storage server)

Install NFS server:

```bash
sudo apt update
sudo apt install -y nfs-kernel-server
```

Create shared directory and set permissions:

```bash
sudo mkdir -p /shared
sudo chown nobody:nogroup /shared
sudo chmod 777 /shared
```

Edit `/etc/exports` (replace subnet as appropriate):

```
/shared 192.168.0.0/16(rw,sync,no_root_squash,no_subtree_check)
```

Apply the export:

```bash
sudo exportfs -ra
```

### 1.6.2 On Every Cluster Node (host and workers)

Install NFS client:

```bash
sudo apt update
sudo apt install -y nfs-common
```

Mount the shared directory:

```bash
sudo mkdir -p /shared
sudo mount <nfs-server-ip>:/shared /shared
```

(Optional) Auto-mount at boot: add to `/etc/fstab`:

```
<nfs-server-ip>:/shared /shared nfs defaults 0 0
```

Verify access:

```bash
touch /shared/testfile
ls -l /shared
```

## 1.7. Test Cluster Readiness

Check node status:

```bash
kubectl get nodes
```

Use the provided `k8s_test.sh` script to verify Docker registry, node health, and shared storage accessibility.

The cluster is now ready for artifact deployment.

See the main artifact documentation for steps on image publishing, YAML configuration, and firmware analysis job submission.

