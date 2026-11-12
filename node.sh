#!/bin/bash
# usage: ./node.sh PORT   (starts/restarts a Hardhat node on PORT; Linux and macOS)
PORT=${1:-8545}
PID=$(cat /tmp/hh_$PORT.pid 2>/dev/null)
if [ -n "$PID" ] && ps -o command= -p "$PID" | grep -q hardhat; then kill -- -"$PID"; sleep 1; fi
cd "$(dirname "$0")" || exit 1
# setsid through Python (macOS has no setsid command): the node gets its own session, so it outlives this
# shell, and its process group is the whole node (npx and its children), which the kill above stops.
nohup python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
  npx hardhat node --port "$PORT" > /tmp/hh_$PORT.log 2>&1 &
echo $! > /tmp/hh_$PORT.pid
for i in $(seq 1 40); do
  curl -s -X POST -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' http://127.0.0.1:$PORT >/dev/null && echo up && exit 0
  sleep 1
done
echo fail; exit 1
