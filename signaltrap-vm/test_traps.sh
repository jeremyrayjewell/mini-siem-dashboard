#!/usr/bin/env bash
# Simple script to exercise trap ports using netcat (nc)
# Usage: ./test_traps.sh 137.66.56.91
HOST=${1:-137.66.56.91}
PORTS=(2222 2121 2323 3306 5432 6379 27017 3389)

for p in "${PORTS[@]}"; do
  echo "-- Testing $HOST:$p --"
  case $p in
    2222) echo -e "SSH-2.0-OpenSSH_7.6p1\r\n" | nc -w 2 $HOST $p || true ;;
    2121) (sleep 1; echo -e "USER test\r\nPASS test\r\n") | nc -w 2 $HOST $p || true ;;
    2323) echo "test" | nc -w 2 $HOST $p || true ;;
    6379) echo -en "PING\r\n" | nc -w 2 $HOST $p || true ;;
    27017) echo -en "\x00\x00\x00\x00" | nc -w 2 $HOST $p || true ;;
    *) echo | nc -w 2 $HOST $p || true ;;
  esac
  sleep 0.2
done

echo "Done. Check flyctl logs and /data/tcp_events.json for entries."