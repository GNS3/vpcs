#!/bin/sh

os=`uname`

if [ $# -eq 0 ]; then
    arch=`uname -p`
fi

CCOPT="-O2"
if [ $# -eq 1 ]; then
    case $1 in
        clean)
            MKOPT=clean
            arch=`uname -p`
	    ;;
	debug)
	    CCOPT="-g"
            arch=`uname -p`
	    ;;
	*)
	    arch=$1
    esac
fi

if [ $# -eq 2 ]; then
    case $1 in
        clean)
            MKOPT=clean
            arch=$2
	    ;;
	debug)
	    CCOPT="-g"
	    arch=$2
	    ;;
    esac
    case $2 in
        clean)
            MKOPT=clean
            arch=$1
	    ;;
	debug)
	    CCOPT="-g"
	    arch=$1
	    ;;
    esac
fi

if [ "x$arch" = "x" ]; then
    echo $0" [i386 | amd64 | 32 | 64] [clean | debug]"
    exit 1
fi


if [ $arch = "i386" -o $arch = "32" ]; then
    CCOPT=$CCOPT" -m32"
fi

if [ $arch = "amd64" -o $arch = "x86_64" -o $arch = "64" ]; then
    CCOPT=$CCOPT" -m64"
fi

if [ $os = "Darwin" ]; then
    CCOPT=$CCOPT""
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
    	echo "Not support"
    	;;
esac
