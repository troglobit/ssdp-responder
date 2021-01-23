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
DESC="SSDP Responder"
NAME=ssdpd

DAEMON=/usr/sbin/ssdpd
PIDFILE=/var/run/$NAME.pid

SCRIPTNAME=/etc/init.d/$NAME

# Common start-stop-demon options
OPTS="--quiet --pidfile  --exec $DAEMON"

# Exit if the package is not installed
[ -x "$DAEMON" ] || exit 0

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Define LSB log_* functions.
. /lib/lsb/init-functions

do_start()
{
        start-stop-daemon --start --oknodo $OPTS -- $SSDPD_OPTIONS
}

do_stop()
{
        start-stop-daemon --stop --oknodo --signal $1 $OPTS
}

case "$1" in
    start)
        log_daemon_msg "Starting $DESC" "$NAME"
        do_start
        case "$?" in
                0) sendsigs_omit
                   log_end_msg 0 ;;
                1) log_progress_msg "already started"
                   log_end_msg 0 ;;
                *) log_end_msg 1 ;;
        esac
        ;;

    stop)
        log_daemon_msg "Stopping $DESC" "$NAME"
        do_stop TERM
        case "$?" in
                0) log_end_msg 0 ;;
                1) log_progress_msg "already stopped"
                   log_end_msg 0 ;;
                *) log_end_msg 1 ;;
        esac
        ;;

    reload|force-reload)
        log_daemon_msg "Stopping $DESC" "$NAME"
        do_stop HUP
        case "$?" in
                0) log_end_msg 0 ;;
                1) log_progress_msg "already stopped"
                   log_end_msg 0 ;;
                *) log_end_msg 1 ;;
        esac
        ;;

    restart)
        $0 stop
        $0 start
        ;;

    status)
        status_of_proc -p $PIDFILE $DAEMON $NAME && exit 0 || exit $?
	;;

    *)
        echo "Usage: $SCRIPTNAME {start|stop|restart|reload|force-reload|status}" >&2
	exit 3
        ;;
esac

exit $rc
