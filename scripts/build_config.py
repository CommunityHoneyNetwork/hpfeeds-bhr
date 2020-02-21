import os
import sys
import uuid
import random
import logging
import configparser
from hpfeeds.add_user import create_user


def main():
    logging.info("Running build_config.py")
    for VAR in ["MONGODB_HOST", "MONGODB_PORT", "HPFEEDS_HOST", "HPFEEDS_PORT", "HPFEEDS_OWNER", "IDENT", "SECRET",
                "CHANNELS", "INCLUDE_HP_TAGS", "IGNORE_CIDR", "BHR_CACHE_DB", "BHR_CACHE_EXPIRE"]:
        logging.debug('From environment, {} is set to: {}'.format(VAR, os.environ.get(VAR)))

    MONGODB_HOST = os.environ.get("MONGODB_HOST", "mongodb")
    MONGODB_PORT = os.environ.get("MONGODB_PORT", "27017")
    HPFEEDS_HOST = os.environ.get("HPFEEDS_HOST", "hpfeeds3")
    HPFEEDS_PORT = os.environ.get("HPFEEDS_PORT", "10000")
    HPFEEDS_OWNER = os.environ.get("HPFEEDS_OWNER", "chn")
    IDENT = os.environ.get("IDENT", "")
    SECRET = os.environ.get("SECRET", "")
    CHANNELS = os.environ.get("CHANNELS",
                              "amun.events,conpot.events,thug.events,beeswarm.hive,dionaea.capture,dionaea.connections,thug.files,beeswarm.feeder,cuckoo.analysis,kippo.sessions,cowrie.sessions,glastopf.events,glastopf.files,mwbinary.dionaea.sensorunique,snort.alerts,wordpot.events,p0f.events,suricata.events,shockpot.events,elastichoney.events,rdphoney.sessions,uhp.events")
    INCLUDE_HP_TAGS = os.environ.get("INCLUDE_HP_TAGS", "false")

    IGNORE_CIDR = os.environ.get("IGNORE_CIDR", "false")
    BHR_CACHE_DB = os.environ.get("BHR_CACHE_DB", "2")
    BHR_CACHE_EXPIRE = os.environ.get("BHR_CACHE_EXPIRE", "300")

    if IDENT:
        ident = IDENT
    else:
        ident = "hpfeeds-bhr-" + str(random.randint(0, 32767))

    if SECRET:
        secret = SECRET
    else:
        secret = str(uuid.uuid4()).replace("-", "")

    config = configparser.ConfigParser()
    config.read("/opt/hpfeeds-bhr.cfg.template")
    config['hpfeeds']['ident'] = ident
    config['hpfeeds']['secret'] = secret
    config['hpfeeds']['hp_host'] = HPFEEDS_HOST
    config['hpfeeds']['hp_port'] = HPFEEDS_PORT
    config['hpfeeds']['owner'] = HPFEEDS_OWNER
    config['hpfeeds']['channels'] = CHANNELS
    config['hpfeeds']['ignore_cidr'] = IGNORE_CIDR
    config['hpfeeds']['include_hp_tags'] = INCLUDE_HP_TAGS

    config['bhr']['bhr_cache_db'] = BHR_CACHE_DB
    config['bhr']['bhr_cache_expire'] = BHR_CACHE_EXPIRE

    create_user(host=MONGODB_HOST, port=int(MONGODB_PORT), owner=HPFEEDS_OWNER,
                ident=ident, secret=secret, publish="", subscribe=CHANNELS)

    print("Writing config...")

    with open("/opt/hpfeeds-bhr.cfg", 'w') as config_file:
        config.write(config_file)
    sys.exit(0)


if __name__ == "__main__":
    main()
