#!/bin/sh

TIMEOUT=60
QUIET=0
HOST=""
PORT=""

while [ $# -gt 0 ]; do
  case "$1" in
    -q)
      QUIET=1
      shift
      ;;
    -t)
      TIMEOUT="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *)
      HOST=$(printf "%s\n" "$1" | cut -d : -f 1)
      PORT=$(printf "%s\n" "$1" | cut -d : -f 2)
      shift
      break
      ;;
  esac
done

if [ "$QUIET" -ne 1 ]; then
  echo "Esperando hasta $TIMEOUT segundos por $HOST:$PORT..."
fi

i=0
while [ $i -lt "$TIMEOUT" ]; do
  nc -z "$HOST" "$PORT" >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    if [ "$QUIET" -ne 1 ]; then
      echo "$HOST:$PORT está listo"
    fi
    exec "$@"
    exit 0
  fi
  i=$((i+1))
  sleep 1
done

echo "❌ Tiempo de espera agotado para $HOST:$PORT" >&2
exit 1
