#!/bin/bash

set -e

forceupdate=false
if [ "$1" = "-f" ]; then
    forceupdate=true
    shift
fi

zig_path="zig"
if [ ! -z "$1" ]; then
    zig_path=$1
    shift
fi

do_fetch() {
    for d in `grep -o '^[[:space:]]*[^/[:space:]][^=]*url *=.*' $1 | cut -d = -f 2`; do
        d=`echo $d | grep -o 'https://[^"]*'`
        echo -e "\n>>> Deal with $d"
        if echo $d | grep -q '\.tar\.gz$'; then
            url=$d
        elif echo $d | grep -q '#[.0-9a-z]*$'; then
            url_base=`echo $d | awk -F \# '{print $1}'`
            url_base=${url_base%.git}
            url_commit=`echo $d | awk -F \# '{print $2}'`
            url="${url_base}/archive/${url_commit}.tar.gz"
        else
            echo ">>> Ignored $d, unable to resolve it!"
            continue
        fi
        hash=`grep -m 1 -A 1 "$d" $1 | grep hash |  awk -F \" '{print $(NF-1)}'`
        if [ -z "$hash" ]; then
          forceupdate=true
        fi
        if ! $forceupdate && [ -e ~/.cache/zig/p/$hash ]; then
          echo ">>> Found $url in cache, ignored"
          continue
        fi
        wget $url
        tarfile=${url##*/}
        hash=`$zig_path fetch --debug-hash $tarfile | tail -n 1`
        echo ">> hash of $d:"
        echo -e "\t$hash"
        rm $tarfile
        if [ -e ~/.cache/zig/p/$hash/build.zig.zon ]; then
            do_fetch ~/.cache/zig/p/$hash/build.zig.zon
        fi
    done

    for d in `grep -o 'path *=.*' $1 | cut -d = -f 2`; do
        path=`echo $d | awk -F \" '{print $(NF-1)}'`
        if [ -e $path/build.zig.zon ]; then
            do_fetch $path/build.zig.zon
        fi
    done
}

zonfile=$1
if [ -z "$zonfile" ]; then
    zonfile=build.zig.zon
fi

if ! [ -e $zonfile ]; then
    echo "can't find build.zig.zon!"
    exit 1
fi

do_fetch $zonfile