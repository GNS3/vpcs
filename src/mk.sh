#!/bin/sh

os=`uname`

CCOPT="-O2"
if [ $# -eq 1 ]; then
    case $1 in
        clean)
            MKOPT=clean
	    ;;
	debug)
	    CCOPT="-g"
	    MKOPT=debug 
	    ;;
        *)
            echo $0" [clean | debug]"
            exit 1
    esac
fi


export CCOPT
case ${os} in
    FreeBSD|Darwin|Linux)
    	make -f Makefile.unix ${MKOPT}
    	;;
    CYGWIN*)
        make -f Makefile.cygwin ${MKOPT}
        ;;
    *)
    	echo "build script is not supported for OS ${os}"
    	;;
esac
