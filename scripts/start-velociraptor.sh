#!/bin/bash
# Start Velociraptor server in a fully-detached session.
set -e
cd /home/z/my-project/soc-lab

# Stop any previous instance
if [ -f var/velociraptor.pid ]; then
  OLD_PID=$(cat var/velociraptor.pid 2>/dev/null || true)
  if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "Stopping previous Velociraptor (PID $OLD_PID)..."
    kill "$OLD_PID" 2>/dev/null || true
    sleep 2
  fi
  rm -f var/velociraptor.pid
fi

echo "Starting Velociraptor frontend..."
setsid nohup ./bin/velociraptor --config etc/server.config.yaml frontend \
  > logs/frontend.out 2>&1 < /dev/null &
NEW_PID=$!
echo $NEW_PID > var/velociraptor.pid
disown $NEW_PID 2>/dev/null || true

# Wait briefly, then confirm it's still running
sleep 4
if kill -0 "$NEW_PID" 2>/dev/null; then
  echo "OK - Velociraptor running, PID $NEW_PID"
  echo "RSS: $(ps -p $NEW_PID -o rss= 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')"
else
  echo "FAIL - process exited"
  echo "=== last 30 log lines ==="
  tail -30 logs/frontend.out
  exit 1
fi
