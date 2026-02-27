# Key Code List

*   `docker_init.sh`: Initializes the Docker container analysis environment. This script is executed at the start of the main container. It handles critical setup tasks, including setting up `binfmt_misc` to allow direct execution of non-native binaries (e.g., MIPS, ARM) via QEMU, starting the Docker daemon, and pre-loading required Docker images.

*   `run.sh`: A wrapper script to run the analysis pipeline for a single firmware image. It simplifies the process of invoking the main analysis logic.
    *   **Description**: It takes the firmware's brand and image path as arguments, sets up local paths, calculates the image's SHA256 hash, and then executes `firmwell.py` with a default set of parameters suitable for a standard rehosting attempt. It also handles timeouts and packages the results into a tarball upon completion.
    *   **Usage**: `./run.sh <BRAND> <PATH_TO_FIRMWARE_IMAGE> [ADDITIONAL_ARGS]`

*   `docker_k8_run.sh`: An advanced script designed to launch large-scale, parallel analysis jobs within a Kubernetes (k8s) cluster.
    *   **Description**: This script reads firmware metadata from a list file based on a job index. It manages complex configurations, including persistent storage paths for logs and results, setting up a PostgreSQL database required by the FirmAE components, and passing a wide range of parameters to `firmwell.py` for automated batch processing.

*   `firmwell.py`: The main entry point and central orchestrator of the FIRMWELL project.
    *   **Description**: This Python script parses a rich set of command-line arguments that allow for fine-grained control over the entire rehosting process. It initializes the `FIRMWELL` class, which uses the `Planter` module to unpack the firmware image and prepare the filesystem. Subsequently, it initiates the core rehosting procedure by creating and running an instance of the `Rehosting` class.

*   `backend/Rehosting.py`: Implements the core rehosting logic of FIRMWELL. This is where the main emulation and automated fixing cycle occurs.
    *   **Description**: This class is responsible for launching the target firmware's services in an emulated environment, using either QEMU-user mode for individual processes or QEMU-system mode for full OS emulation. It operates in an iterative loop: (1) run the service, (2) use a `checker` to test its functionality, (3) if it fails, use `ErrorLocator` to analyze trace logs and find the root cause, and (4) apply a `FixStrategy` to patch the environment or configuration. This cycle repeats until the service is successfully rehosted or the maximum number of attempts is reached.

*   `backend/call_chain_utils/`: This directory contains modules for static analysis to determine the sequence of process execution.
    *   **Description**: The tools in this directory, such as `GhidraTool.py`, are used to perform static analysis on the firmware's binaries. The goal is to construct a "call chain"—a dependency graph of which processes launch others. This is crucial for the "Blocking Process Identification" phase (Section III-B of the paper), as it helps determine which processes must be running for the target service to launch successfully.

*   `backend/reason_fix/`: Implements the "Root Cause Oriented Misemulation Fix" strategies from Section III-C of the paper.
    *   **Description**: This directory is central to FIRMWELL's automated debugging capabilities. `ErrorLocator.py` parses runtime trace logs to pinpoint the exact cause of an emulation failure. `FixStrategy.py` contains a collection of methods to resolve these failures, such as creating missing files, symlinks, or device nodes; setting environment variables; or reusing configuration values from a database of known-good firmware.

*   `backend/utils/`: Provides a collection of utility modules for common tasks required throughout the project.
    *   **Description**: Contains helpers like `FileSystemUtil.py` for robust file and directory manipulation, `NetworkUtil.py` for configuring virtual network interfaces and firewalls inside the container, and `ProcessUtil.py` for managing and inspecting processes running within the emulated environment.

*   `qemu_user/`: Contains files related to the QEMU user-mode emulator.
    *   **Description**: This directory holds the source code for FIRMWELL's modified version of QEMU for user-mode emulation. This mode allows running and tracing individual ELF binaries from the target firmware (e.g., a web server) on the host's kernel, which is faster and more lightweight than full system emulation.

*   `qemu_system_files/`: Contains files required for supporting QEMU system-mode emulation.
    *   **Description**: This directory acts as a repository of pre-compiled, statically-linked tools and libraries for various CPU architectures (e.g., `busybox.armel`, `gdbserver.mipseb`, `libnvram.so.mipsel`). These files are injected into the firmware's filesystem to provide a stable set of utilities and to replace or supplement missing or problematic components, ensuring a more robust full-system emulation.