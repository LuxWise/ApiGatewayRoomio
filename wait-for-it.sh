#!/bin/sh

# Script original de Eficode (licencia MIT):
# https://github.com/vishnubob/wait-for-it

TIMEOUT=6000
QUIET=0
PROXY=()
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
    --proxy=*)
      PROXY=("--proxy" "${1#*=}")
      shift
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
  echo "Esperando hasta $TIMEOUT segundos para $HOST:$PORT..."
fi

for i in $(seq "$TIMEOUT"); do
  if nc -z "${PROXY[@]}" "$HOST" "$PORT" >/dev/null 2>&1; then
    if [ "$QUIET" -ne 1 ]; then
      echo "$HOST:$PORT está listo!"
    fi
    exec "$@"
  fi
  sleep 1
done

echo "Tiempo de espera agotado para $HOST:$PORT" >&2
exit 1