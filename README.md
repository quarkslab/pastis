<p align="center">
	<img src="https://github.com/quarkslab/pastis/raw/main/doc/figs/logo_pastis.png"  width="100%">
</p>

The PASTIS project is a fuzzing framework aiming at combining various software testing techniques
within the same workflow to perform collaborative fuzzing also called ensemble fuzzing.
At the moment it supports the following fuzzing engines:

* **Honggfuzz** (greybox fuzzer)
* **AFL++** (greybox fuzzer)
* **TritonDSE** (whitebox fuzzer)

<p align="center" style="font-size:20px">
  <a href="https://quarkslab.github.io/pastis">
    [Documentation] 
  </a>
</p>


<p align="center">
  <a href="https://github.com/quarkslab/pastis/releases">
    <img src="https://img.shields.io/github/v/release/quarkslab/pastis?logo=github">
  </a>
  <img src="https://img.shields.io/github/license/quarkslab/pastis"/>
  <a href="https://github.com/quarkslab/pastis/releases">
    <img src="https://img.shields.io/github/actions/workflow/status/quarkslab/pastis/doc.yml">
  </a>
  <a href="https://github.com/quarkslab/pastis/releases">
    <img src="https://img.shields.io/github/actions/workflow/status/quarkslab/pastis/release.yml">
  </a>
  <img src="https://img.shields.io/github/downloads/quarkslab/pastis/total"/>
  <img src="https://img.shields.io/pypi/dm/pastis-framework"/>
  
</p>

---

# Overview

<p align="center" style="font-size:20px">
  <a href="https://www.youtube.com/watch?v=9uwXciOxtyQ">
    <img src="https://i.ytimg.com/vi/9uwXciOxtyQ/maxresdefault.jpg" width="50%">
  </a>
</p>

> **Note**
> The video highlight the use-case driven by SAST alerts. However, the
> main use-case the standard fuzzing for coverage or bug research.


---

# Quick start

* [Installation](#installation)
* [Usage](#usage)
* [Adding a fuzzer](#adding-a-fuzzer)

## Installation

The PASTIS framework can be installed with:

```bash
pip install pastis-framework
```

The pip package will install all dependencies and the tritondse
engine.

**AFL++**

To install AFL++ please refer to the official [documentation](https://github.com/AFLplusplus/AFLplusplus#getting-started).

**Honggfuzz**

Honggfuzz requires a specific build with a [patch applied](https://github.com/quarkslab/pastis/blob/main/engines/pastis-honggfuzz/patches/honggfuzz-5a504b49-pastis.patch)
it can be compiled by applying the following steps:

```bash
sudo apt-get install binutils-dev libunwind-dev libblocksruntime-dev clang
git clone https://github.com/quarkslab/pastis.git
cd pastis/engines/pastis-honggfuzz/patches
./make_hf.sh
echo "export HFUZZ_PATH=$PWD/honggfuzz-5a504b49" >> ~/.profile
```

## Usage

The main component is the ``broker`` that will serve the appropriate configurations to fuzzing
engines and that will aggregate results. An example is the following:

```bash
tar xvf doc/figs/fsm-demo.tar.gz && cd fsm-demo
make
pastis-broker -b bin -s initial -w output
```

It will run the broker using binaries in the *bin* directory. Initial corpus
is *initial* and the whole output workspace will be save in *output*. By default
it will listen on the local interface on port 5555.

Then fuzzing engines can be launched to start testing the software.

```commandline
pastis-aflpp online
```

Or:

```commandline
pastis-triton online
```

Full documentation is available: [here](https://quarkslab.github.io/pastis/campaign.html)

## Adding a Fuzzer

Integrating a fuzzer requires writing a Python driver using the ``libpasts`` library
installed by the package. It requires implementing some callbacks to receive the initial
configuration and also to receive inputs from the broker. Conversely the API enables
sending newly generated inputs to the broker.

The process is further [detailed in the documentation](https://quarkslab.github.io/pastis/adding-fuzzer.html).


> **Note**
> We warmly welcome any Pull Request to add the support for a new fuzzing engine.

---

## Docker

You can also run PASTIS using Docker:

```bash
docker pull ubuntu:22.04
docker build -t pastis-docker .
docker run -v <HOST-WORKSPACE>:/workspace --cap-add=SYS_PTRACE --user $(id -u $USER):$(id -g $USER) -it pastis-docker
```

To open another terminal to an already running container:

```bash
docker exec -it $(docker ps | grep 'pastis-docker' | awk '{print $1}') /bin/bash
```

The PASTIS Docker image has already installed all the needed dependencies such as AFL++ and Honggfuzz.

---

## Papers and conference

* **Symbolic Execution the Swiss-Knife of the Reverse Engineer Toolbox**  
  **Venue**: KLEE Workshop, 2022 [[:books:]](https://srg.doc.ic.ac.uk/klee22/talks/David-Reverse-Engineering.pdf) [[:movie_camera:]](https://youtu.be/PNbNtTa5Sp4)  
  **Authors**: Robin David, Richard Abou Chaaya, Christian Heitman  


* **From source code to crash test-case through software testing automation**  
  **Venue**: European Cyber Week, C&ESAR Workshop, 2021  [paper](https://ceur-ws.org/Vol-3056/paper-02.pdf) [slides](https://github.com/quarkslab/conf-presentations/blob/main-page/C%26ESAR-2021/CESAR-2021_slides_2-2.pdf)  
  **Authors**: Robin David, Jonathan Salwan, Justin Bourroux  


## Cite Pastis

```latex
soon
```


## Contributors

Pastis is powered by [Quarkslab](https://quarkslab.com) and initially financed by DGA-MI.

[**All contributions**](https://github.com/quarkslab/pastis/graphs/contributors)

