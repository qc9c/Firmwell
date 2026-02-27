FROM quay.io/skopeo/stable:latest AS fetch
RUN mkdir -p /out

RUN skopeo copy --retry-times 3 \
      docker://ghcr.io/qc9c/ubuntu32:latest \
      docker-archive:/out/ubuntu32.tar:ubuntu32:latest \
 && skopeo copy --retry-times 3 \
      docker://ghcr.io/qc9c/multiarch_qemu-user-static_latest:latest \
      docker-archive:/out/multiarch_qemu-user-static_latest.tar:multiarch_qemu-user-static_latest:latest \
 && skopeo copy --retry-times 3 \
      docker://ghcr.io/qc9c/fact_extractor:latest \
      docker-archive:/out/fact_extractor.tar:fkiecad/fact_extractor:latest


FROM capysix/greenhouse-ae:latest
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y apt-utils git curl python3 python3-pip wget sudo net-tools iputils-ping iptables iproute2 build-essential
RUN apt-get install -y p7zip-full p7zip-rar zip libpq-dev vim dnsutils jq unrar ca-certificates # uml-utils
RUN apt-get install -y qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
RUN apt-get install -y libssl-dev libffi-dev libxml2 libxml2-dev libxslt1-dev zlib1g-dev gcc cmake
RUN apt-get install -y openssh-server zsh rsync csvtool software-properties-common



# install ghidra
RUN #add-apt-repository ppa:openjdk-r/ppa
RUN apt update && apt install -y openjdk-21-jdk
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20240926.zip -O /ghidra_11.2_PUBLIC_20240926.zip
RUN unzip /ghidra_11.2_PUBLIC_20240926.zip -d /
RUN rm /ghidra_11.2_PUBLIC_20240926.zip



RUN python -m pip install jinja2 pyyaml
RUN . /root/venv/bin/activate \
    && python3 -m pip install docker==5.0.0 requests==2.24.0 selenium==3.141.0 lxml==4.7.1 networkx==2.8.4 ifaddr==0.2.0 python-magic six redis pexpect paramiko pysnmp future pyelftools pyparsing colorama psycopg2 sonyflake-py pyyaml minio pymongo jinja2

# install binwalk for python3 venv
RUN cd /work/FirmAE/binwalk-2.3.3 && /root/venv/bin/python3 setup.py install


# FIRMWELL
WORKDIR /
COPY ./docker_img /docker_img
COPY --from=fetch /out/*.tar /docker_img/


COPY ./firmwell/qemu_system_files /qemu_system_files
COPY ./firmwell/qemu_user /qemu_user
RUN chmod +x /qemu_user/*
RUN cp -r /qemu_user/* /usr/bin/

COPY ./firmwell/eval_gh /fw/firmwell/eval_gh


COPY ./firmwell/analysis /analysis
RUN chmod +x /analysis/chromedriver
COPY ./firmwell/greenhouse_files /fw/firmwell/greenhouse_files
COPY ./firmwell/plugins /fw/firmwell/plugins
COPY ./firmwell/tools/scripts /fw/firmwell/tools/scripts
COPY ./firmwell/tools/templates /fw/firmwell/tools/templates
COPY ./firmwell/tools/get_nvram /fw/firmwell/tools/get_nvram

COPY ./firmwell/backend /fw/firmwell/backend
COPY ./firmwell/__init__.py /fw/firmwell/__init__.py


ARG SYS_FUZZ=False
COPY ./firmwell/sys_fuzz /tmp/sys_fuzz
RUN echo "SYS_FUZZ=$SYS_FUZZ" && \
    if [ "$SYS_FUZZ" = "True" ]; then \
      cp -r /tmp/sys_fuzz/fuzz /qemu_system_files/ && \
      cp /tmp/sys_fuzz/QemuSysRunner.py /fw/firmwell/backend/QemuSysRunner.py; \
    fi
RUN rm -rf /tmp/sys_fuzz

COPY ./firmwell.py /fw/firmwell.py
COPY ./entrypoint.sh /fw/entrypoint.sh
COPY ./docker_init.sh /fw/docker_init.sh
COPY ./docker_k8_extract.sh /fw/docker_k8_extract.sh
COPY ./docker_k8_run.sh /fw/docker_k8_run.sh
COPY ./run.sh /fw/run.sh

RUN chmod -R +x /fw
