#! /bin/bash
#   GoodCrypto Web
#   Copyright 2015 GoodCrypto
#   Last modified: 2015-07-05

WEB_TOOLS_DIR=/var/local/projects/goodcrypto/server/src/web/tools

function start() {
    sudo -u goodcrypto /usr/local/bin/supervisord -c $WEB_TOOLS_DIR/supervisord.web.conf
}

function stop() { 
    sudoifnot goodcrypto killmatch supervisord &>/dev/null
    sudoifnot goodcrypto killmatch web/filters.py &>/dev/null
}

function restart() { 
    stop
    start
}

function status() { 
    if (psgrep web/filters.py > /dev/nul) ; then
        echo "goodcrypto web is running"
        true
    else
        echo "goodcrypto web is not running"
        false
    fi
}

function usage() { 
    echo "usage: goodcrypto-web [start | stop | restart | status]"
}


command=$1
shift

case $command in

    start)
        start "$@"
        ;;
        
    stop)
        stop "$@"
        ;;

    restart)
        restart "$@"
        ;;

    status)
        status "$@"
        ;;

    *)
        usage
        ;;
        
esac

