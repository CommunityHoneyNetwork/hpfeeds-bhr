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
      echo "Authorization failed; please verify BHR_HOST and BHR_TOKEN, then restart the container."
      echo "BHR_HOST=${BHR_HOST}"
      echo "BHR_TOKEN=${BHR_TOKEN}"
      sleep 120
      exit 1
  else
      echo "Successfully pinged BHR host with token"
  fi
  cat /opt/hpfeeds-bhr.cfg
  python3 /opt/hpfeeds-bhr/feedhandler.py /opt/hpfeeds-bhr.cfg
}

main "$@"
