#!/bin/sh
# Stands in for cloudflared in the HA test: logs when it connects and when it is told to drain.
echo "fake-cloudflared connected args=$*"
trap 'echo "fake-cloudflared draining"; sleep 1; echo "fake-cloudflared exited"; exit 0' TERM
while true; do sleep 1; done
