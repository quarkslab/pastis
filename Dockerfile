FROM ubuntu:22.04

# Download and install packages.
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" \
    apt-get install -y --no-install-suggests --no-install-recommends \
        # Basic packages.
        build-essential \
        clang \
        cmake \
        curl \
        git \
        less \
        pkg-config \
        python-is-python3 \
        python3 \
        python3-pip \
        sudo \
        tar \
        unzip \
        vim \
        # Packages for AFL++.
        automake \
        bison \
        cmake \
        flex \
        libglib2.0-dev \
        libgtk-3-dev \
        libpixman-1-dev \
        python3-dev \
        python3-setuptools \
        # Packages for AFL++-QEMU.
        ninja-build \
        # Packages for Honggfuzz.
        binutils-dev \
        libblocksruntime-dev \
        libunwind-dev \
        # Packages for PASTIS.
        libmagic1 && \
    DEBIAN_FRONTEND="noninteractive" \
    apt-get install -y --no-install-suggests --no-install-recommends \
        # Packages for AFL++-QEMU.
        gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev \
        libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev

# Download, compile and install AFLplusplus.
RUN git clone https://github.com/AFLplusplus/AFLplusplus && \
    cd AFLplusplus && \
    CC=clang make && \
    cd qemu_mode && \
    ./build_qemu_support.sh && \
    cd .. && \
    make install && \
    cd .. && \
    rm -rf AFLplusplus

# Copy Honggfuzz PASTIS patch.
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
    make install && \
    cd .. && \
    rm -rf honggfuzz-5a504b49 patches

# Download and install PASTIS
RUN git clone https://github.com/quarkslab/pastis.git && \
    cd pastis && \
    pip install . && \
    cd .. && \
    rm -rf pastis

# Clean up.
RUN pip cache purge

# Set environment variables.
ENV AFLPP_PATH=/usr/local/bin
ENV HFUZZ_PATH=/usr/local/bin

# Add new user.
RUN adduser --disabled-password --gecos '' pastis-user && \
    adduser pastis-user sudo && \
    echo 'pastis-user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Switch to the new user.
USER pastis-user

# Set work directory.
WORKDIR /workspace
