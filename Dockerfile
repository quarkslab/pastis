FROM ubuntu:22.04

# Download and install basic dependencies.
RUN apt-get update

RUN DEBIAN_FRONTEND="noninteractive" \
    apt-get install -y --no-install-suggests --no-install-recommends \
        build-essential \
        cmake \
        curl \
        git \
        less \
        pkg-config \
        python3 \
        python3-pip \
        sudo \
        tar \
        unzip

# Download and install Honggfuzz dependencies.
RUN DEBIAN_FRONTEND="noninteractive" \
    apt-get install -y --no-install-suggests --no-install-recommends \
        clang \
        libbfd-dev \
        libunwind-dev \
        libunwind8-dev

#
# AFLplusplus
#

RUN DEBIAN_FRONTEND="noninteractive" \
    apt-get install -y --no-install-suggests --no-install-recommends \
        build-essential \
        python3-dev \
        python3-setuptools \
        automake \
        cmake \
        git \
        flex \
        bison \
        libglib2.0-dev \
        libpixman-1-dev \
        cargo \
        libgtk-3-dev \
        # for QEMU mode
        ninja-build \
        gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev \
        libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev

# Download, compile and install AFLplusplus.
RUN git clone https://github.com/AFLplusplus/AFLplusplus && \
    cd AFLplusplus && \
    CC=clang make && \
    cd qemu_mode && \
    ./build_qemu_support.sh && \
    cd .. && \
    make install

#
# Honggfuzz
#

RUN DEBIAN_FRONTEND="noninteractive" \
    apt-get install -y --no-install-suggests --no-install-recommends \
        libbfd-dev \
        libblocksruntime-dev \
        liblzma-dev \
        libunwind-dev

# Copy honggfuzz PASTIS patch.
RUN mkdir patches
COPY engines/pastis-honggfuzz/patches/honggfuzz-5a504b49-pastis.patch patches/honggfuzz-5a504b49-pastis.patch

# Download, patch, compile and install Honggfuzz.
RUN git clone https://github.com/google/honggfuzz.git honggfuzz-5a504b49 && \
    cd honggfuzz-5a504b49 && \
    git checkout 5a504b49fe829a73b6ea88214d8e4bcf3d103d4f && \
    cd .. && \
    patch -s -p0 < patches/honggfuzz-5a504b49-pastis.patch && \
    cd honggfuzz-5a504b49 && \
    CFLAGS="-O3 -funroll-loops" make && \
    make install

#
# PASTIS
#

RUN DEBIAN_FRONTEND="noninteractive" \
    apt-get install -y --no-install-suggests --no-install-recommends \
        libmagic1 \
        python-is-python3

RUN pip install pastis-framework

ENV AFLPP_PATH=/usr/local/bin
ENV HFUZZ_PATH=/usr/local/bin

# Add new user.
RUN adduser --disabled-password --gecos '' pastis-user && \
    adduser pastis-user sudo && \
    echo 'pastis-user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Switch to the new user.
USER pastis-user

WORKDIR /workspace
