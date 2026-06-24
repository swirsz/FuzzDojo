# syntax=docker/dockerfile:1.7

############################################
# OSS-FUZZ IMAGE
############################################

FROM anoncollege/challenge-legacy AS oss-fuzz-src

USER root
SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

ARG OSS_FUZZ_COMMIT=2de60f967131cb6042781c85e2ebce97cfbb47ba
# May 26, 2026

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && \
    apt-get install -yqq --no-install-recommends git ca-certificates && \
    git clone https://github.com/google/oss-fuzz /opt/oss-fuzz && \
    cd /opt/oss-fuzz && \
    git checkout "$OSS_FUZZ_COMMIT" && \
    find /opt/oss-fuzz -type d \( -name ".git" -o -name ".github" \) -prune -exec rm -rf {} +

############################################
# llvm-builder IMAGE
############################################

FROM anoncollege/challenge-legacy AS llvm-builder

USER root
SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
ENV SRC=/src
ARG arch=x86_64
ENV FULL_LLVM_BUILD=1

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && \
    xargs apt-get install -yqq --no-install-recommends <<EOF
git
build-essential
cmake
ninja-build
python3
curl
wget
ca-certificates 
EOF

# Install newer cmake.
ENV CMAKE_VERSION=3.29.2
WORKDIR $SRC
RUN curl -fsSL \
      "https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/cmake-$CMAKE_VERSION-Linux-$arch.sh" \
      -o "cmake-$CMAKE_VERSION-Linux-$arch.sh" && \
    chmod +x "cmake-$CMAKE_VERSION-Linux-$arch.sh" && \
    "./cmake-$CMAKE_VERSION-Linux-$arch.sh" --skip-license --prefix="/usr/local" && \
    rm "cmake-$CMAKE_VERSION-Linux-$arch.sh" && \
    rm -rf /usr/local/doc/cmake /usr/local/bin/cmake-gui

# --mount=type=cache,target=/src/llvm-project

COPY --from=oss-fuzz-src /opt/oss-fuzz /opt/oss-fuzz
COPY --from=oss-fuzz-src /opt/oss-fuzz/infra/base-images/base-clang/checkout_build_install_llvm.sh /root/

RUN --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/build/llvm \
    set +e; \
    bash -x /root/checkout_build_install_llvm.sh > /tmp/llvm-build.log 2>&1; \
    status=$?; \
    if [ "$status" -ne 0 ]; then \
        echo "LLVM build failed with status $status"; \
        echo "Last 300 lines of /tmp/llvm-build.log:"; \
        tail -n 300 /tmp/llvm-build.log; \
        exit "$status"; \
    fi

############################################
# DOWNLOAD STAGE
############################################

FROM anoncollege/challenge-legacy AS downloads

USER root
SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && \
    xargs apt-get install -yqq --no-install-recommends <<EOF
git
subversion
wget
curl
ca-certificates
python3-pip
EOF
    
COPY --chmod=755 sbin/download.sh /opt/download.sh

RUN DOWNLOAD_PARALLEL_JOBS=6 \
    /opt/download.sh

############################################
# MAIN IMAGE
############################################


FROM anoncollege/challenge-legacy

USER root

SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

################################################################################

# From oss-fuzz/infra/base-images/base-image, base-clang, base-builder, base-runner

ENV DEBIAN_FRONTEND=noninteractive
ENV OUT=/out
ENV SRC=/src
ENV WORK=/work
WORKDIR $SRC

RUN mkdir -p "$OUT" "$SRC" "$WORK" /corpus && \
    chmod a+rwx "$OUT" "$SRC" "$WORK" /corpus

# prevent merge conflict with llvm-builder's man pages
RUN rm -rf /usr/local/man 
# Copy only finished LLVM artifacts
COPY --from=llvm-builder /usr/local /usr/local
#COPY --from=llvm-builder /out /out
COPY --chown=hacker:hacker --from=oss-fuzz-src /opt/oss-fuzz /opt/oss-fuzz

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && \
    apt-get install -yqq --no-install-recommends \
    git \
    python3-pip \
    binutils \
    file \
    ca-certificates \
    fonts-dejavu \
    libcap2 \
    rsync \
    unzip \
    wget \
    zip

RUN cd /opt && \
    curl -fsSLO https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-431.0.0-linux-x86_64.tar.gz && \
    tar -xf google-cloud-cli-431.0.0-linux-x86_64.tar.gz && \
    ./google-cloud-sdk/install.sh --quiet && \
    rm google-cloud-cli-431.0.0-linux-x86_64.tar.gz

ENV PATH="/opt/google-cloud-sdk/bin:${PATH}"

ENV PYTHON_VERSION=3.10.14
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    PYTHON_DEPS="\
        zlib1g-dev \
        libncurses5-dev \
        libgdbm-dev \
        libnss3-dev \
        libssl-dev \
        libsqlite3-dev \
        libreadline-dev \
        libffi-dev \
        libbz2-dev \
        liblzma-dev" && \
    unset CFLAGS CXXFLAGS && \
    apt-get update && \
    apt-get install -y --no-install-recommends $PYTHON_DEPS && \
    cd /tmp && \
    curl -fsSLO https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tar.xz && \
    tar -xvf Python-$PYTHON_VERSION.tar.xz && \
    cd Python-$PYTHON_VERSION && \
    ./configure --enable-optimizations --enable-shared && \
    make -j$(nproc) install && \
    ldconfig && \
    #ln -s /usr/local/bin/python3 /usr/local/bin/python && \
    cd .. && \
    rm -r /tmp/Python-$PYTHON_VERSION.tar.xz /tmp/Python-$PYTHON_VERSION && \
    rm -rf /usr/local/lib/python${PYTHON_VERSION%.*}/test && \
    python3 -m ensurepip && \
    python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel
    #apt-get remove -y $PYTHON_DEPS # https://github.com/google/oss-fuzz/issues/3888

ENV CODE_COVERAGE_SRC=/opt/code_coverage
# Pin coverage to the same as in the base builder: infra/base-images/base-runner/Dockerfile 5/26/2026
# https://github.com/google/oss-fuzz/blob/master/infra/base-images/base-builder/install_python.sh#L22
RUN git clone https://chromium.googlesource.com/chromium/src/tools/code_coverage $CODE_COVERAGE_SRC && \
    cd /opt/code_coverage && \
    git checkout edba4873b5e8a390e977a64c522db2df18a8b27d && \
    pip3 install --no-cache-dir wheel && \
    # If version "Jinja2==2.10" is in requirements.txt, bump it to a patch version that
    # supports upgrading its MarkupSafe dependency to a Python 3.10 compatible release:
    sed -i 's/Jinja2==2.10/Jinja2==2.10.3/' requirements.txt && \
    pip3 install --no-cache-dir -r requirements.txt && \
    pip3 install --no-cache-dir MarkupSafe==2.0.1 coverage==6.3.2

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && \
    apt-get install -yqq --no-install-recommends \
        libc6-dev \
        libgcc-9-dev \
        libnice-dev \
        patch \
        subversion \
        sudo \
        tzdata \
        wget

################################################################################

RUN curl -fsSL -o /usr/local/bin/clang-jcc \
      https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang-jcc && \
    curl -fsSL -o /usr/local/bin/clang++-jcc \
      https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang++-jcc && \
    chmod 755 /usr/local/bin/clang-jcc /usr/local/bin/clang++-jcc

# ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang-jcc /usr/local/bin/
# ADD https://commondatastorage.googleapis.com/clusterfuzz-builds/jcc/clang++-jcc /usr/local/bin/

# Go, JavaScript, Java, Python, Rust, and Swift installation scripts
RUN cp /opt/oss-fuzz/infra/base-images/base-builder/bazel_build_fuzz_tests \
    /opt/oss-fuzz/infra/base-images/base-builder/cargo \
    /opt/oss-fuzz/infra/base-images/base-builder/compile \
    /opt/oss-fuzz/infra/base-images/base-builder/compile_afl \
    /opt/oss-fuzz/infra/base-images/base-builder/compile_centipede \
    /opt/oss-fuzz/infra/base-images/base-builder/compile_honggfuzz \
    /opt/oss-fuzz/infra/base-images/base-builder/compile_fuzztests.sh \
    /opt/oss-fuzz/infra/base-images/base-builder/compile_go_fuzzer \
    /opt/oss-fuzz/infra/base-images/base-builder/compile_javascript_fuzzer \
    /opt/oss-fuzz/infra/base-images/base-builder/compile_libfuzzer \
    /opt/oss-fuzz/infra/base-images/base-builder/compile_native_go_fuzzer \
    /opt/oss-fuzz/infra/base-images/base-builder/compile_python_fuzzer \
    /opt/oss-fuzz/infra/base-images/base-builder/debug_afl \
    /opt/oss-fuzz/infra/base-images/base-builder/install_go.sh \
    /opt/oss-fuzz/infra/base-images/base-builder/install_javascript.sh \
    /opt/oss-fuzz/infra/base-images/base-builder/install_java.sh \
    /opt/oss-fuzz/infra/base-images/base-builder/install_python.sh \
    /opt/oss-fuzz/infra/base-images/base-builder/install_rust.sh \
    /opt/oss-fuzz/infra/base-images/base-builder/install_swift.sh \
    /opt/oss-fuzz/infra/base-images/base-builder/python_coverage_helper.py \
    /opt/oss-fuzz/infra/base-images/base-builder/srcmap \
    /opt/oss-fuzz/infra/base-images/base-builder/write_labels.py \
    /usr/local/bin/

RUN cp /opt/oss-fuzz/infra/base-images/base-runner/bad_build_check \
    /opt/oss-fuzz/infra/base-images/base-runner/coverage \
    /opt/oss-fuzz/infra/base-images/base-runner/coverage_helper \
    /opt/oss-fuzz/infra/base-images/base-runner/download_corpus \
    /opt/oss-fuzz/infra/base-images/base-runner/jacoco_report_converter.py \
    /opt/oss-fuzz/infra/base-images/base-runner/nyc_report_converter.py \
    /opt/oss-fuzz/infra/base-images/base-runner/rcfilt \
    /opt/oss-fuzz/infra/base-images/base-runner/reproduce \
    /opt/oss-fuzz/infra/base-images/base-runner/run_fuzzer \
    /opt/oss-fuzz/infra/base-images/base-runner/parse_options.py \
    /opt/oss-fuzz/infra/base-images/base-runner/profraw_update.py \
    /opt/oss-fuzz/infra/base-images/base-runner/targets_list \
    /opt/oss-fuzz/infra/base-images/base-runner/test_all.py \
    /opt/oss-fuzz/infra/base-images/base-runner/test_one.py \
    /opt/oss-fuzz/infra/base-images/base-runner/python_coverage_runner_help.py \
    /usr/local/bin/

RUN cp /opt/oss-fuzz/infra/base-images/base-builder/llvmsymbol.diff $SRC && \
    cp /opt/oss-fuzz/infra/base-images/base-builder/bazel.bazelrc /root/.bazelrc

# WORKDIR /

#RUN git clone https://github.com/ossf/fuzz-introspector.git fuzz-introspector && \
#    cd fuzz-introspector && \
#    git checkout 341ebbd72bc9116733bcfcfab5adfd7f9b633e07 && \
#    git submodule init && \
#    git submodule update
    # f9bcb8824a18d60d57e2430c5b43f525d811cae8 # Mar 17, 2025
    # git checkout f9bcb8824a18d60d57e2430c5b43f525d811cae8 && \

#RUN cp /opt/oss-fuzz/infra/base-images/base-clang/checkout_build_install_llvm.sh /root/ && \
#    /root/checkout_build_install_llvm.sh && \
#    rm /root/checkout_build_install_llvm.sh 

# Install six for Bazel rules.
RUN unset CFLAGS CXXFLAGS && pip3 install -v --no-cache-dir \
    six==1.15.0 && rm -rf /tmp/*

# Install Bazel through Bazelisk, which automatically fetches the latest Bazel version.
ENV BAZELISK_VERSION=1.9.0
RUN curl -fsSL https://github.com/bazelbuild/bazelisk/releases/download/v$BAZELISK_VERSION/bazelisk-linux-amd64 -o /usr/local/bin/bazel && \
    chmod +x /usr/local/bin/bazel

#        libssl1.1
#        python-numpy
#        python-is-python3
#        libbz2-dev:i386
#        libc6-dev-i386
#        liblz4-dev:i386
#        liblzma-dev:i386
#        libreadline-dev:i386
#        libunwind-dev:i386
#        libzstd-dev:i386
#        zlib1g-dev:i386

#prereqs for oss-fuzz programs
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && \
    xargs apt-get install -yqq --no-install-recommends <<EOF
apt-utils
autoconf
autoconf-archive
automake
autopoint
binutils-dev
bison
build-essential
bzip2
ccache
cmake
curl
cvs 
cvsps 
default-jdk
docbook-xsl 
ffmpeg
flex
g++
gawk
gcc
gengetopt
gettext
git 
gnutls-dev
gperf    
jq
libacl1
libacl1-dev
libbison-dev
libbrotli-dev
libbsd-dev
libbz2-dev
libcap-ng-dev
libcgi-pm-perl
libconfig-dev
libcunit1
libcunit1-dev
libcurl4-openssl-dev
libcurlpp-dev 
libdbd-sqlite3-perl 
libdbus-1-dev
libedit-dev
liberror-perl 
libexpat-dev
libexpat1-dev 
libffi-dev
libfuse-dev
libgc-dev
libgcrypt20-dev
libgdbm-dev
libgomp1
libgmock-dev
libgmp-dev
libgnutls28-dev
libhttp-date-perl
libini-config-dev
libinih-dev
libio-pty-perl   
libjansson-dev
libjpeg-dev
libjpeg-turbo8
libjpeg-turbo8-dev
libjpeg8
libjpeg8-dev
liblmdb-dev 
liblz4-dev
liblzma-dev
libmailtools-perl
libncurses5-dev 
libncursesw5-dev
libomp-dev 
libpam0g-dev
libpci-dev
libpcre2-dev
libpcre3
libpcre3-dev  
libpng-dev
libpq-dev
libprotobuf-dev
libreadline-dev
libreadline6-dev
libseccomp-dev
libsqlite3-dev
libssh-dev
libssl-dev
libstdc++-9-dev
libsvn-perl
libsystemd-dev
libtool
libtool-bin
libudev-dev
libunwind-dev
libxml2-dev
libxml2-utils
libyaml-dev
libyaml-perl 
libz-dev 
libzstd-dev
lmdb-utils
lrzsz
m4
make
mercurial
nasm
ncurses-dev
ninja-build
nodejs
openssl
patchelf
perl-modules
pkg-config
protobuf-compiler
re2c
rsync
ruby
shtool
subversion
tcl
texinfo
tk-dev
udev
unzip
uuid-dev
wget
xmlto 
xsltproc
yasm
zip
zlib1g-dev
EOF

#        python3
#        python3-all-dev
#        python3-pip
#        libcurl4-gnutls-dev
#        libgio2.0-cil-dev
        
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && \
    xargs apt-get install -yqq --no-install-recommends <<EOF
        asciidoc
        firefox
        gtk-doc-tools
        libdbus-glib-1-dev
        libdrm-dev
        libglib2.0-dev   
        libpolkit-gobject-1-dev   
        libnice-dev
        light-locker-settings
EOF


#RUN pip3 install atheris --no-binary atheris
#        fuzz-introspector 

RUN xargs pip3 install --no-cache-dir <<EOF
        alabaster 
        babel 
        bashlex
        beautifulsoup4
        certifi 
        charset-normalizer 
        configparser
        contourpy
        corpus-replicator
        coverage
        cxxfilt
        cycler
        docutils 
        exceptiongroup
        flake8
        fonttools
        imagesize 
        importlib-metadata 
        importlib-resources
        iniconfig 
        jinja2
        jsonschema
        kiwisolver
        lizard
        lxml
        markupsafe
        matplotlib
        mccabe 
        meson
        mypy
        mypy_extensions 
        networkx 
        ninja
        numpy
        opencv-python-headless
        packaging
        pep8 
        pillow
        platformdirs 
        pluggy 
        psutil
        pyYAML 
        pycodestyle 
        pyflakes 
        pygments 
        pylint
        pyparsing
        pytest 
        python-dateutil
        requests 
        rust-demangler
        setuptools>=65.5.1
        snowballstemmer 
        soupsieve
        sphinx 
        sphinx_rtd_theme
        sphinxcontrib-applehelp 
        sphinxcontrib-devhelp 
        sphinxcontrib-htmlhelp 
        sphinxcontrib-jquery 
        sphinxcontrib-jsmath 
        sphinxcontrib-qthelp 
        sphinxcontrib-serializinghtml 
        toml
        tqdm 
        tree-sitter 
        tree-sitter-c 
        tree-sitter-cpp 
        tree-sitter-go 
        tree-sitter-java 
        tree-sitter-languages 
        tree-sitter-python 
        tree-sitter-rust 
        twisted
        types-Jinja2
        types-jsonschema
        urllib3 
        vncdotool
        yapf
        zipp
        zope.interface
EOF

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && \
    xargs apt-get install -yqq --no-install-recommends <<EOF
        arping
        binutils
        binutils-aarch64-linux-gnu
        binwalk
        bsdmainutils
        bsdutils
        debianutils
        diffutils
        ed
        elfutils
        emacs
        ethtool
        exiftool
        expect
        findutils
        fish
        fortune
        gcc-aarch64-linux-gnu
        gdb
        gdb-multiarch
        gedit
        genisoimage
        gnupg-utils
        hexedit
        htop
        iproute2
        iputils-ping
        ipython3
        keyutils
        kmod
        less
        libc6-arm64-cross
        libc6-dev-arm64-cross
        libtiff-dev
        ltrace
        nano
        ncdu
        neovim
        net-tools
        netcat-openbsd
        nmap
        openssh-server
        parallel
        pcaputils
        pcre2-utils
        psutils
        python3-ipdb
        qemu-system-x86
        qemu-user
        qemu-utils
        screen
        silversearcher-ag
        strace
        tmux
        whiptail
        zsh
EOF
#   wireshark

COPY --chown=hacker:hacker --from=downloads /downloads /downloads
#RUN python3 -m pip install --no-cache-dir "/downloads/cyclonedds-python"

#RUN chown -hR hacker:hacker /opt/oss-fuzz

COPY sbin/sysctl.patch /usr/local/bin/
RUN patch -tuN /usr/local/bin/compile -i /usr/local/bin/sysctl.patch

#COPY sbin/compile.patch /usr/local/bin/
#RUN patch -tuN /usr/local/bin/compile -i /usr/local/bin/compile.patch

COPY sbin/run_fuzzer.patch /usr/local/bin/
RUN patch -tuN /usr/local/bin/run_fuzzer -i /usr/local/bin/run_fuzzer.patch

COPY sbin/run_fuzzer2.patch /usr/local/bin/
RUN patch -tuN /usr/local/bin/run_fuzzer -i /usr/local/bin/run_fuzzer2.patch

#COPY sbin/analysis.patch /usr/local/bin/
#RUN patch -tuN /fuzz-introspector/src/fuzz_introspector/analysis.py -i /usr/local/bin/analysis.patch

COPY sbin/build_seed_corpus.patch /usr/local/bin/
RUN patch -tuN /downloads/openjpeg/tests/fuzzers/build_seed_corpus.sh -i /usr/local/bin/build_seed_corpus.patch

#RUN cp /opt/oss-fuzz/infra/base-images/base-builder/precompile_afl /usr/local/bin/
#COPY sbin/precompile_afl.patch /usr/local/bin/
#RUN patch -tuN /usr/local/bin/precompile_afl -i /usr/local/bin/precompile_afl.patch
#RUN precompile_afl

COPY sbin/ossfuzz \
     sbin/find-drv \
     sbin/fuzzlog \
     sbin/fuzzlog_oss \
     sbin/e \
     sbin/eafl \
     sbin/loc-calc \
     sbin/loc-report \
     sbin/report \
     sbin/fi \
     sbin/fi2 \
     sbin/fi_oss \
     sbin/fi-report \
     sbin/drivers \
     sbin/build-cleanup \
     sbin/build-cleanup2 \
     sbin/build-cleanup-oss \
     sbin/build-srcfolders \
     sbin/loc_count \
     sbin/loc_count2 \
     sbin/loc_count120 \
     sbin/loc_count_oss \
     sbin/oss_help \
     sbin/test-crashes \
     sbin/understanding \
     sbin/understanding_oss \
     sbin/planning \
     sbin/announce \
     sbin/fuzz_report.patch \
     sbin/calltree_view.patch \
     /usr/local/sbin/

RUN chmod +x /usr/local/sbin/* && \
    echo Fuzz-Platform-revision-2026-05-26 >> /etc/os-release

USER hacker

WORKDIR /home/hacker
