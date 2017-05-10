#!/bin/sh

os=`uname`

if [ $# -eq 0 ]; then
    arch=`uname -p`
fi

if [ $# -eq 1 ]; then
    if [ $1 = "clean" ]; then
        MKOPT=clean
        arch=`uname -p`
    else     
        arch=$1 
    fi
fi

if [ $# -eq 2 ]; then
    if [ $1 = "clean" ]; then
        MKOPT=clean
        arch=$2
    fi
    if [ $2 = "clean" ]; then
        MKOPT=clean
        arch=$1
    fi
fi

if [ "x$arch" = "x" ]; then
    echo $0" [i386 | amd64 | 32 | 64] [clean]"
    exit 1
fi

CCOPT=" "

if [ $arch = "i386" -o $arch = "32" ]; then
    CCOPT="-m32"
fi

if [ $arch = "amd64" -o $arch = "x86_64" -o $arch = "64" ]; then
    CCOPT="-m64"
fi

if [ $os = "Darwin" ]; then
    CCOPT=" "
fi

export CCOPT
case ${os} in
    FreeBSD)
    	make -f Makefile.fbsd ${MKOPT}
    	;;
    Linux)
        make -f Makefile.linux ${MKOPT}
        ;;
    CYGWIN*)
        make -f Makefile.cygwin ${MKOPT}
        ;;
    Darwin)
        make -f Makefile.osx ${MKOPT}
        ;;
    *)
    	echo "Not support: ${os}"
    	;;
esac
