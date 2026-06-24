#!/bin/bash
mkdir -p /opt/fuzz-targets && cd  /opt/fuzz-targets
apt-get update && apt-get install -y git
git clone --depth 1 --branch OpenSSL_1_1_1-stable https://github.com/openssl/openssl.git /opt/fuzz-targets/openssl111
git clone --depth 1 --branch master https://github.com/fmtlib/fmt.git /opt/fuzz-targets/fmt
git clone --depth 1 --branch master https://github.com/php/php-src.git /opt/fuzz-targets/php-src
git clone --depth 1 --branch openssl-3.0 https://github.com/openssl/openssl.git /opt/fuzz-targets/openssl30
git clone --depth 1 --jobs $(nproc) https://github.com/ligurio/lua-c-api-corpus /opt/fuzz-targets/corpus_dir
git clone --depth 1 -b develop https://github.com/eclipse/mosquitto /opt/fuzz-targets/mosquitto
git clone --depth 1 -b develop https://github.com/madler/zlib.git && cd zlib && git checkout v1.2.12 && cd ..
git clone --depth 1 -b develop https://github.com/nlohmann/json.git /opt/fuzz-targets/json
git clone --depth 1 https://github.com/DavidKorczynski/binary-samples.git /opt/fuzz-targets/binary-samples
git clone --depth 1 https://github.com/LibVNC/libvncserver.git /opt/fuzz-targets/libvncserver
git clone --depth 1 https://github.com/bblanchon/ArduinoJson.git /opt/fuzz-targets/arduinojson
git clone --depth 1 https://github.com/bshastry/mruby_seeds.git /opt/fuzz-targets/mruby_seeds
git clone --depth 1 https://github.com/c-ares/c-ares.git /opt/fuzz-targets/c-ares
git clone --depth 1 https://github.com/cfengine/core --recursive /opt/fuzz-targets/core
git clone --depth 1 https://github.com/corkami/pocs /opt/fuzz-targets/pocs
git clone --depth 1 https://github.com/curl/curl-fuzzer.git /opt/fuzz-targets/curl_fuzzer
git clone --depth 1 https://github.com/curl/curl.git /opt/fuzz-targets/curl
git clone --depth 1 https://github.com/djmdjm/openssh-fuzz-cases /opt/fuzz-targets/openssh-fuzz-cases
git clone --depth 1 https://github.com/file/file.git /opt/fuzz-targets/file
git clone --depth 1 https://github.com/google/ExoPlayer.git /opt/fuzz-targets/ExoPlayer
git clone --depth 1 https://github.com/google/fuzzer-test-suite /opt/fuzz-targets/fuzzer-test-suite
git clone --depth 1 https://github.com/google/libprotobuf-mutator.git /opt/fuzz-targets/libprotobuf-mutator
git clone --no-checkout --config "advice.detachedHead=false" "https://github.com/google/protobuf.git" /opt/fuzz-targets/external.protobuf
git clone --depth 1 https://github.com/google/zopfli /opt/fuzz-targets/zopfli
git clone --depth 1 https://github.com/guidovranken/LAME-fuzzers /opt/fuzz-targets/LAME-fuzzers
git clone --depth 1 https://github.com/guidovranken/fuzzing-headers.git /opt/fuzz-targets/fuzzing-headers
git clone --depth 1 https://github.com/guidovranken/gfwx-fuzzers.git /opt/fuzz-targets/gfwx
git clone --depth 1 https://github.com/guidovranken/oss-fuzz-fuzzers.git /opt/fuzz-targets/oss-fuzz-fuzzers
git clone --depth 1 https://github.com/guidovranken/python-library-fuzzers.git /opt/fuzz-targets/python-library-fuzzers
git clone --depth 1 https://github.com/hathach/tinyusb.git /opt/fuzz-targets/tinyusb
git clone --depth 1 https://github.com/jedisct1/libsodium.git --branch stable /opt/fuzz-targets/libsodium
git clone --depth 1 https://github.com/json-c/json-c.git /opt/fuzz-targets/json-c
git clone --depth 1 https://github.com/lathiat/avahi /opt/fuzz-targets/avahi
git clone --depth 1 https://github.com/libgd/libgd /opt/fuzz-targets/libgd
git clone --depth 1 https://github.com/libssh2/libssh2.git /opt/fuzz-targets/libssh2
git clone --depth 1 https://github.com/mdempsky/go114-fuzz-build.git /opt/fuzz-targets/go114-fuzz-build
git clone --depth 1 https://github.com/mruby/mruby /opt/fuzz-targets/mruby
git clone --depth 1 https://github.com/ninja-build/ninja /opt/fuzz-targets/ninja
git clone --depth 1 https://github.com/open-source-parsers/jsoncpp /opt/fuzz-targets/jsoncpp
git clone --depth 1 https://github.com/openssh/openssh-portable /opt/fuzz-targets/openssh
git clone --depth 1 https://github.com/openssl/openssl.git /opt/fuzz-targets/openssl && cd /opt/fuzz-targets/openssl && git submodule update --init fuzz/corpora && cd ..
git clone --depth 1 https://github.com/richgel999/miniz.git /opt/fuzz-targets/miniz
git clone --depth 1 https://github.com/strongcourage/fuzzing-corpus /opt/fuzz-targets/fuzzing-corpus
git clone --depth 1 https://github.com/systemd/casync /opt/fuzz-targets/casync
git clone --depth 1 https://github.com/the-tcpdump-group/libpcap.git /opt/fuzz-targets/libpcap
git clone --depth 1 https://github.com/tmux/tmux-fuzzing-corpus.git /opt/fuzz-targets/tmux-fuzzing-corpus
git clone --depth 1 https://github.com/tmux/tmux.git /opt/fuzz-targets/tmux
git clone --depth 1 https://github.com/tristanpenman/valijson /opt/fuzz-targets/valijson && cd /opt/fuzz-targets/valijson && git submodule update --init --depth 1 thirdparty && cd ..
git clone --depth 1 https://github.com/uclouvain/openjpeg /opt/fuzz-targets/openjpeg  
git clone --depth 1 https://github.com/uclouvain/openjpeg-data /opt/fuzz-targets/data  
git clone --depth 1 https://github.com/uriparser/uriparser /opt/fuzz-targets/uriparser
git clone --depth 1 https://github.com/videolan/vlc /opt/fuzz-targets/vlc
git clone --depth 1 https://github.com/wasm3/wasm3 /opt/fuzz-targets/wasm3
git clone --depth 1 https://github.com/xiph/flac.git /opt/fuzz-targets/flac
git clone --depth 1 https://github.com/xiph/ogg.git /opt/fuzz-targets/ogg
git clone --depth 1 https://gitlab.kitware.com/cmake/cmake.git /opt/fuzz-targets/cmake
git clone --depth 1 https://gitlab.xiph.org/xiph/speex.git /opt/fuzz-targets/speex
git clone --depth 1 https://gitlab.xiph.org/xiph/vorbis.git /opt/fuzz-targets/vorbis
git clone --depth=1 --recursive https://github.com/rockdaboot/libpsl.git /opt/fuzz-targets/libpsl
git clone --depth=1 https://git.libssh.org/projects/libssh.git /opt/fuzz-targets/libssh
git clone --depth=1 https://git.lysator.liu.se/nettle/nettle.git /opt/fuzz-targets/nettle
git clone --depth=1 https://git.savannah.gnu.org/git/libunistring.git /opt/fuzz-targets/libunistring
git clone --depth=1 https://github.com/MariaDB/server /opt/fuzz-targets/server
git clone --depth=1 https://github.com/apache/httpd /opt/fuzz-targets/httpd
svn checkout https://svn.apache.org/repos/asf/apr/apr/trunk/ /opt/fuzz-targets/httpd/srclib/apr
git clone --depth=1 https://github.com/the-tcpdump-group/tcpdump.git /opt/fuzz-targets/tcpdump
git clone --depth=1 https://github.com/vdukhovni/postfix /opt/fuzz-targets/postfix
git clone --depth=1 https://gitlab.com/gnutls/gnutls.git /opt/fuzz-targets/gnutls
git clone --depth=1 https://gitlab.com/libidn/libidn2.git /opt/fuzz-targets/libidn2
git clone --recurse-submodules --depth 1 https://github.com/USBGuard/usbguard /opt/fuzz-targets/usbguard
git clone --recurse-submodules https://github.com/google/snappy /opt/fuzz-targets/snappy
git clone --recursive https://github.com/boostorg/boost.git /opt/fuzz-targets/boost
git clone --single-branch --branch 2_2_x_throttle https://github.com/cisco/libsrtp.git /opt/fuzz-targets/libsrtp
git clone --single-branch --branch master https://github.com/meetecho/janus-gateway.git /opt/fuzz-targets/janus-gateway
git clone --single-branch https://github.com/QubesOS/qubes-app-linux-input-proxy /opt/fuzz-targets/qubes-os/app-linux-input-proxy
git clone --single-branch https://github.com/QubesOS/qubes-core-qrexec /opt/fuzz-targets/qubes-os/qubes-core-qrexec
git clone --single-branch https://github.com/QubesOS/qubes-core-qubesdb /opt/fuzz-targets/qubes-os/qubes-core-qubesdb
git clone -b develop https://github.com/zlib-ng/minizip-ng /opt/fuzz-targets/minizip
git clone -b oss_fuzz --depth 1 https://github.com/aawc/unrar.git /opt/fuzz-targets/unrar
git clone git://git.savannah.gnu.org/gnulib.git /opt/fuzz-targets/gnulib
git clone git://sourceware.org/git/bzip2-tests.git /opt/fuzz-targets/bzip2-tests
git clone git://sourceware.org/git/bzip2.git /opt/fuzz-targets/bzip2
git clone https://bitbucket.org/jpommier/pffft /opt/fuzz-targets/pffft
git clone https://git.savannah.gnu.org/git/libidn.git /opt/fuzz-targets/libidn
git clone https://git.savannah.gnu.org/git/wget.git /opt/fuzz-targets/wget
git clone https://git.tukaani.org/xz.git /opt/fuzz-targets/xz
git clone https://github.com/AdaLogics/fuzz-headers /opt/fuzz-targets/fuzz-headers
git clone https://github.com/ClusterLabs/libqb /opt/fuzz-targets/libqb
git clone https://github.com/DaveGamble/cJSON /opt/fuzz-targets/cJSON
git clone https://github.com/Legrandin/pycryptodome.git /opt/fuzz-targets/pycryptodome
git clone https://github.com/OpenSIPS/opensips /opt/fuzz-targets/opensips
git clone https://github.com/PCRE2Project/pcre2 /opt/fuzz-targets/pcre2
git clone https://github.com/danmar/cppcheck.git /opt/fuzz-targets/cppcheck
git clone https://github.com/git/git /opt/fuzz-targets/git
git clone https://github.com/google/oss-fuzz.git /opt/fuzz-targets/example
git clone https://github.com/haproxy/haproxy /opt/fuzz-targets/haproxy
git clone https://github.com/kamailio/kamailio /opt/fuzz-targets/kamailio
git clone https://github.com/libevent/libevent.git /opt/fuzz-targets/libevent
git clone https://github.com/lighttpd/lighttpd1.4 /opt/fuzz-targets/lighttpd1.4
git clone https://github.com/ligurio/lua-c-api-tests /opt/fuzz-targets/testdir
git clone https://github.com/python/cpython.git /opt/fuzz-targets/cpython
git clone https://github.com/python/cpython.git /opt/fuzz-targets/cpython3
git clone https://github.com/ruby/ruby.git /opt/fuzz-targets/ruby
git clone https://github.com/sudo-project/sudo /opt/fuzz-targets/sudo
git clone https://gitlab.com/gnutls/libtasn1.git /opt/fuzz-targets/libtasn1
svn checkout http://svn.xvid.org/trunk --username anonymous --password "" --non-interactive --no-auth-cache /opt/fuzz-targets/trunk
svn checkout https://svn.code.sf.net/p/lame/svn/trunk/lame /opt/fuzz-targets/lame
mkdir -p /opt/fuzz-targets/lzo && wget -O /opt/fuzz-targets/lzo/lzo.tar.gz http://www.oberhumer.com/opensource/lzo/download/lzo-2.10.tar.gz
wget -qO- https://ftp.gnu.org/gnu/libidn/libidn2-latest.tar.gz | tar -xz -C /opt/fuzz-targets
wget -qO- https://ftp.gnu.org/gnu/libunistring/libunistring-latest.tar.gz | tar -xz -C /opt/fuzz-targets
wget https://github.com/libexpat/libexpat/releases/download/R_2_4_1/expat-2.4.1.tar.gz && tar xvfz expat-2.4.1.tar.gz && rm expat-2.4.1.tar.gz
wget https://github.com/unicode-org/icu/releases/download/release-59-2/icu4c-59_2-src.tgz && tar xvfz icu4c-59_2-src.tgz && rm icu4c-59_2-src.tgz
wget https://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz  && tar xvfz afl_testcases.tgz && rm afl_testcases.tgz
mkdir -p /opt/fuzz-targets/snapshot && cd /opt/fuzz-targets/snapshot && wget https://www.mpg123.de/snapshot && cd ..
git clone --depth 1 https://github.com/commonmark/cmark.git cmark
git clone --depth 1 https://github.com/eclipse-cyclonedds/cyclonedds
git clone --depth=1 https://github.com/eclipse-cyclonedds/cyclonedds-python.git ; pip3 install ./cyclonedds-python
git clone --depth 1 https://github.com/tytso/e2fsprogs
git clone --depth 1 git://sourceware.org/git/elfutils.git
git clone --depth 1 https://github.com/file/file.git
git clone --depth 1 https://github.com/DavidKorczynski/binary-samples.git
git clone --depth 1 https://github.com/corkami/pocs
git clone --depth 1 https://gitlab.xiph.org/xiph/vorbis.git vorbis
git clone --depth 1 https://gitlab.xiph.org/xiph/ogg.git ogg
git clone --depth 1 https://gitlab.xiph.org/xiph/theora.git theora
git clone --depth 1 --recursive https://gitlab.freedesktop.org/gstreamer/gstreamer.git gstreamer
git clone --depth 1 git://sourceware.org/git/elfutils.git
git clone https://github.com/Exiv2/exiv2 exiv2
git clone --depth 1 https://gitlab.xiph.org/xiph/vorbis.git vorbis
git clone --depth 1 https://gitlab.xiph.org/xiph/ogg.git ogg
git clone --depth 1 https://gitlab.xiph.org/xiph/theora.git theora
git clone --depth 1 --recursive https://gitlab.freedesktop.org/gstreamer/gstreamer.git gstreamer
git clone --depth=1 https://github.com/google/guetzli 
mkdir afl-testcases && cd afl-testcases/ && curl https://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz | tar -xz && cd ..
git clone --branch master  https://github.com/igraph/igraph
git clone --depth 1 https://github.com/jqlang/jq
git clone --depth 1 https://github.com/liblouis/liblouis
git clone --depth 1 https://github.com/pnggroup/libpng.git
git clone --depth 1 https://github.com/sass/libsass.git libsass
git clone --depth 1 https://gitlab.com/libtiff/libtiff
git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo
git clone https://www.cl.cam.ac.uk/~mgk25/git/jbigkit
#wget https://lcamtuf.coredump.cx/afl/demo/afl_testcases.tgz
wget https://raw.githubusercontent.com/google/AFL/debe27037b9444bbf090a0ffbd5d24889bb887ae/dictionaries/tiff.dict
git clone --depth 1 https://github.com/stefanberger/libtpms libtpms
git clone https://chromium.googlesource.com/webm/libvpx
wget https://storage.googleapis.com/downloads.webmproject.org/test_data/fuzzer/vpx_fuzzer_seed_corpus.zip
git clone https://chromium.googlesource.com/webm/libwebp
git clone https://chromium.googlesource.com/webm/libwebp-test-data
wget https://storage.googleapis.com/downloads.webmproject.org/webp/testdata/fuzzer/fuzz_seed_corpus.zip
# Libxml2 build requires automake 1.16.3
curl -LO http://mirrors.kernel.org/ubuntu/pool/main/a/automake-1.16/automake_1.16.5-1.3_all.deb
git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git
git clone --depth 1 https://github.com/VirusTotal/yara.git
git clone --depth 1 --recursive https://github.com/google/woff2
git clone --depth 1 https://github.com/dbry/WavPack.git wavpack
git clone https://github.com/tats/w3m
curl 'https://www.sqlite.org/src/tarball?uuid=trunk' -o sqlite3.tar.gz 
git clone --depth 1 https://gitlab.xiph.org/xiph/ogg.git
git clone --depth 1 https://gitlab.xiph.org/xiph/speex.git speex
git clone --depth 1 https://github.com/openssl/openssl.git openssl && cd openssl/ && git submodule update --init fuzz/corpora && cd ..
git clone --depth 1 --branch OpenSSL_1_1_1-stable https://github.com/openssl/openssl.git openssl111
git clone --depth 1 --branch openssl-3.0 https://github.com/openssl/openssl.git openssl30
git clone --depth 1 --branch openssl-3.1 https://github.com/openssl/openssl.git openssl31
git clone --depth 1 --branch openssl-3.2 https://github.com/openssl/openssl.git openssl32 && cd openssl32 && git submodule update --init fuzz/corpora && cd ..
git clone --recursive --depth 1 git://git.ghostscript.com/mupdf.git mupdf
git clone --depth 1 https://github.com/mozilla/pdf.js pdf.js 
wget https://raw.githubusercontent.com/rc0r/afl-fuzz/master/dictionaries/pdf.dict
git clone --depth 1 https://github.com/google/boringssl.git boringssl
git clone --recursive --depth 1 -b development https://github.com/Mbed-TLS/mbedtls.git mbedtls
wget https://download.gnome.org/sources/libxml2/2.12/libxml2-2.12.6.tar.xz
git clone --depth 1 --branch v1.61.0 https://github.com/nghttp2/nghttp2
wget http://zlib.net/fossils/zlib-1.2.13.tar.gz
wget https://wrapdb.mesonbuild.com/v2/zlib_1.2.13-2/get_patch/zlib_1.2.13-2_patch.zip
wget --no-clobber https://www.speex.org/samples/audio/male.wav 
wget --no-clobber https://www.speex.org/samples/audio/female.wav 
wget --no-clobber https://www.speex.org/samples/audio/wb_male.wav
