#!/bin/sh

os=`uname`

if [ $# -eq 0 ]; then
    arch=`uname -m`
fi

CCOPT="-O2"
if [ $# -eq 1 ]; then
    case $1 in
        clean)
            MKOPT=clean
            arch=`uname -m`
	    ;;
	debug)
	    CCOPT="-g"
	    MKOPT=debug 
            arch=`uname -m`
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
	    MKOPT=debug
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
	    MKOPT=debug
	    arch=$1
	    ;;
    esac
fi

if [ "x$arch" = "x" ]; then
    echo $0" [i386 | amd64 | arm64 | 32 | 64] [clean | debug]"
    exit 1
fi


case "$arch" in
    i386|32)
        CCOPT=$CCOPT" -m32"
        ;;
    amd64|x86_64|64)
        CCOPT=$CCOPT" -m64"
        ;;
    arm64|aarch64)
        case `uname -m` in
            aarch64|arm64)
                ;;
            *)
                echo "arm64 builds require an ARM64 host" >&2
                exit 1
                ;;
        esac
        ;;
    *)
        echo $0" [i386 | amd64 | arm64 | 32 | 64] [clean | debug]" >&2
        exit 1
        ;;
esac

if [ $os = "Darwin" ]; then
    CCOPT=$CCOPT""
fi

export CCOPT
case ${os} in
    FreeBSD)
    	make -f Makefile.fbsd ${MKOPT}
    	;;
    OpenBSD)
	make -f Makefile.obsd ${MKOPT}
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
