# FIRMWELL

FIRMWELL is a dependency-aware firmware rehosting framework that **automates the emulation of Linux-based embedded firmware** by reconstructing both system-level interfaces and user-space resources.
The implementation consists of three main stages: multi-process emulation of the init and target binaries, automated identification of the process that blocks service rehosting, and root cause analysis with adaptive recovery.


# Build Docker Container
```
docker build -f ./Dockerfile -t firmwell:latest .
```

Or pull the pre-built image directly:
```
docker pull ghcr.io/qc9c/firmwell:latest
```

# Run Docker Container
```
docker run --privileged -v /dev:/host/dev -it firmwell:latest bash
```

Copy the your firmware image into the running container:
```
docker cp <your_firm_image> <container_id>:/tmp
```

(If you are not already inside the container shell, enter it with:)
```
docker exec -it <container_id> bash
```

Initialize the analysis environment inside the container:
```
bash /fw/docker_init.sh
```


## Firmware Rehosting
Run the following command to start the analysis. FIRMWELL typically completes rehosting in about 10 minutes:
```
bash /fw/run.sh <brand> /tmp/<your_firm_image>
```

Supported `<brand>` values include: `dlink`, `netgear`, `tplink`, `trendnet`, `linksys`, `asus`, `belkin`, `tenda`, `edimax`, `engenius`, `zyxel`, `ubiquiti`.

Upon completion, the console will display:
```
REHOST STATUS - <sha256sum>: SUCCESS
```
This indicates successful rehosting. The resulting rehosted image will be saved at `/tmp/results/<sha256sum>`.


### Launching the Rehosted Image

After successful rehosting, the exported image can be started independently via `docker-compose`:
```
tar xf /tmp/results/<sha256sum>.tar.gz
cd <sha256sum>/<firm_name>/minimal
docker-compose build && docker-compose up
```

The network service will start automatically. The bound IP address is typically `192.168.0.1` or `192.168.1.1`.



## Citation

```
@inproceedings{firmwell,
  author = {Qin, Chuan and Zhang, Cen and Zheng, Yaowen and Liu, Puzhuo and Zhang, Jian and Li, Yeting and Zhang, Weidong and Liu, Yang and Sun, Limin},
  title = {{User-Space Dependency-Aware Rehosting for Linux-Based Firmware Binaries}},
  booktitle = {{Proceedings of the Network and Distributed System Security Symposium (NDSS'26)}},
  year = {2026},
  publisher = {{The Internet Society}},
  address = {{San Diego, California, USA}},
  url = {https://www.ndss-symposium.org/wp-content/uploads/2026-s249-paper.pdf}
}
```


## Security Notice: Privileged Docker Mode and procfs

FIRMWELL uses Docker-in-Docker (DinD) for rehosting, which requires the outer container to run with `--privileged`. When `privileged=True`, the host machine's procfs is mounted into the container. In this mode, writes to `/proc` from multiple containers can **directly modify the host's procfs**, which may affect host system behavior.

The `--privileged` CLI flag controls this behavior and defaults to `False`. Pass `--privileged` to enable privileged mode for inner containers. During our experiments, we used `--privileged` and ran FIRMWELL inside VMware virtual machines to isolate the host from potential side effects.

**We strongly recommend running FIRMWELL inside a virtual machine** to avoid unintended modifications to the host system.


## Known Issues

### Kubernetes OOM Causes Docker Process Crash and Rehosting Failure

When running FIRMWELL in Kubernetes with insufficient memory limits, the OOM killer may terminate Docker-related processes inside the Pod, leading to two failure patterns:

1. **`MemoryError` during rehosting analysis** — The Python process itself runs out of memory (e.g., when parsing large `EXECVE_TRACE` files), raising `MemoryError` in `Rehosting.py`. Subsequent subprocess calls (e.g., `docker ps`) also fail with `OSError: [Errno 12] Cannot allocate memory`.

2. **`ConnectionError: Connection refused` to Docker daemon** — The Docker daemon (`dockerd`) inside the Pod is killed by the OOM killer. When FIRMWELL attempts to start or inspect a container, it fails with `requests.exceptions.ConnectionError` connecting to `127.0.0.1:2375`.

**Solution**: Increase the memory resource limit for the Kubernetes Job/Pod (in `fw_k8s_job.yaml`), then re-run the analysis for the affected firmware images.


## Disclaimer

This is an **academic research prototype** developed as part of a research project published at NDSS'26. It is provided as-is for research and educational purposes only.

- The codebase is in **alpha stage** and has not been fully tested across all environments or firmware configurations. Unexpected behavior may occur.
- FIRMWELL runs firmware binaries with elevated privileges (Docker `--privileged` mode). **Use at your own risk.** We strongly recommend running it inside a virtual machine (see [Security Notice](#security-notice-privileged-docker-mode-and-procfs)).
- The authors are not responsible for any damage, data loss, or security issues arising from the use of this software.
- This tool is not intended for production use or deployment in any critical infrastructure.


## Acknowledgements

This project is inspired by the following open-source projects:

- [Firmadyne](https://github.com/firmadyne/firmadyne)
- [FirmAE](https://github.com/pr0v3rbs/FirmAE)
- [Greenhouse](https://github.com/sefcom/greenhouse)
- [Pandawan](https://github.com/BUseclab/Pandawan)
- [FirmAFL](https://github.com/zyw-200/FirmAFL)


## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
