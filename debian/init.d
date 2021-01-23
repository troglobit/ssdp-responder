#! /bin/sh
### BEGIN INIT INFO
# Provides:          ssdpd
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: SSDP responder for Linux
# Description:       Announces UPnP to Windows as an InternetGatewayDevice
### END INIT INFO
. /lib/lsb/init-functions

PATH=/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/ssdpd
OPTS="--quiet --pidfile /var/run/$NAME.pid --exec $DAEMON"
NAME=ssdpd
DESC="SSDP Responder"
rc=255

test -x $DAEMON || exit 0

case "$1" in
    start)
        echo -n "Starting $DESC: "
        modprobe ipip 2> /dev/null || true
        start-stop-daemon --start --oknodo $OPTS
	rc=$?
        echo "$NAME."
        ;;

    stop)
        echo -n "Stopping $DESC: "
        start-stop-daemon --stop --oknodo $OPTS
	rc=$?
        echo "$NAME."
        ;;

    reload|force-reload)
        echo -n "Reloading $DESC: "
        start-stop-daemon --stop --signal HUP $OPTS
	rc=$?
        echo "$NAME."
        ;;

    restart)
        echo -n "Restarting $DESC: "
        start-stop-daemon --stop --oknodo $OPTS
        sleep 1
        start-stop-daemon --start $OPTS --exec $DAEMON
	rc=$?
        echo "$NAME."
        ;;

    status)
        start-stop-daemon --status $OPTS
	rc=$?
	case "$rc" in
            0)
		echo "Program '$NAME' is running."
		;;
            1)
		echo "Program '$NAME' is not running, yet the PID file exists."
		;;
            3)
		echo "Program '$NAME' is not running."
		;;
            4)
		echo "Unable to determine program '$NAME' status."
		;;
	esac
	;;

    *)
        N=/etc/init.d/$NAME
        echo "Usage: $N {start|stop|restart|reload|force-reload|status}" >&2
	rc=1
        ;;
esac

exit $rc
