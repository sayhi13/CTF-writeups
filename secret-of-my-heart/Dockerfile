FROM ubuntu:16.04

ENV DEBIAN_FRONTEND=noninteractive

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

RUN apt-get update && apt-get install -y \
    build-essential \
    python3 \
    python3-pip \
    python3-dev \
    libffi-dev \
    libssl-dev \
    git \
    gdb \
	gdbserver \
    tmux \
    curl \
    wget \
    netcat \
    vim \
    procps \
    && rm -rf /var/lib/apt/lists/*

RUN cd /tmp && \
    wget https://launchpad.net/ubuntu/+archive/primary/+files/libc-bin_2.23-0ubuntu5_amd64.deb && \
    wget https://launchpad.net/ubuntu/+archive/primary/+files/libc6_2.23-0ubuntu5_amd64.deb && \
    wget https://launchpad.net/ubuntu/+archive/primary/+files/libc-dev-bin_2.23-0ubuntu5_amd64.deb && \
    wget https://launchpad.net/ubuntu/+archive/primary/+files/libc6-dev_2.23-0ubuntu5_amd64.deb && \
    dpkg -i libc-bin_2.23-0ubuntu5_amd64.deb libc6_2.23-0ubuntu5_amd64.deb libc-dev-bin_2.23-0ubuntu5_amd64.deb libc6-dev_2.23-0ubuntu5_amd64.deb && \
    apt-mark hold libc6 libc6-dev libc-bin libc-dev-bin && \
    rm -f /tmp/*.deb

RUN python3 -m pip install --upgrade "pip<21" && \
    pip3 install pwntools

RUN git clone https://github.com/longld/peda.git /opt/peda && \
    echo "source /opt/peda/peda.py" >> /root/.gdbinit

RUN printf "%s %s %s %s" "syntax on" "set number" "set tabstop=4" "set autoindent" > ~/.vimrc

WORKDIR /ctf

CMD ["bash"]
