#!/bin/sh

set -e

TAR_DST=/tmp/zig.tar.xz
DST=/tmp/zig

BIN_DIR=/usr/local/bin
LIB_DIR=/usr/local/lib

# chech for utilities
for CMD in jq curl sha256sum
do
    if ! command -v $CMD
    then
        echo need to install $CMD
        exit 1
    fi
done

#!/bin/sh
if [ "$#" -ne 1 ]
then
  echo "only argument is the version you want. Eg. 'master' or '0.6.0'" >&2
  exit 1
fi

rm $TAR_DST -f
rm $DST -rf

MASTER=$(curl -q https://ziglang.org/download/index.json 2>/dev/null | jq ".[\"$1\"].\"$(uname -m)-$(uname | awk '{ print tolower($0) }')\"")
URL=$(echo $MASTER | jq -r .tarball)
SHASUM=$(echo $MASTER | jq -r .shasum)

curl $URL > $TAR_DST
if ! echo $SHASUM /tmp/zig.tar.xz | sha256sum --check --status
then
    echo failed checksum for zig tarball
    exit 1
fi

rm -rf $DST
mkdir $DST
tar -xvf $TAR_DST -C $DST --strip-components=1

rm $BIN_DIR/zig -f
rm $LIB_DIR/zig -rf

mv $DST/zig $BIN_DIR
mv $DST/lib/zig $LIB_DIR
