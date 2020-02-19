#!/bin/bash

trap "exit 130" SIGINT
trap "exit 137" SIGKILL
trap "exit 143" SIGTERM

set -o nounset
set -o pipefail


main () {
  python3 /opt/scripts/build_config.py
  if [[ $? -ne 0 ]]
  then
      echo "Config build failed; verify config and then restart the container."
      sleep 120
      exit 1
  fi
  cat /opt/hpfeeds-bhr.cfg
  python3 /opt/hpfeeds-bhr/feedhandler.py /opt/hpfeeds-bhr.cfg
}

main "$@"
