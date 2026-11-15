#!/bin/bash
# serve.sh start|stop: the Django dev server with the write logger, by PID file.
O=$(cd "$(dirname "$0")" && pwd); DJ=$O/../dj/devsite
case $1 in
start) cd $DJ && WLOG=$O/w.log WLOG_SUFFIX=/devsite/db.sqlite3 LD_PRELOAD=$O/wlog.so exec \
         ../venv/bin/python manage.py runserver --noreload 127.0.0.1:8765 > $O/server.log 2>&1 &
       echo $! > $O/server.pid
       for i in $(seq 1 30); do curl -sf -o /dev/null http://127.0.0.1:8765/list && break; sleep 0.5; done ;;
stop)  kill $(cat $O/server.pid) 2>/dev/null; sleep 1 ;;
esac
