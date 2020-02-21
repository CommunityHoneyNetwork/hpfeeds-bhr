import os
import sys
import hpfeeds
from configparser import ConfigParser
import processors
import logging
from IPy import IP
from bhr_client.rest import login as bhr_login
import requests.exceptions
import redis

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s][%(filename)s] - %(message)s'
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(handler)


class RedisCache(object):
    """
    Implement a simple cache using Redis.
    """

    def __init__(self, host='redis', port=6379, db=1, expire=300):
        # This code will have implication of no more than one instance of BHR
        # In case of multiples, false cache hits will result due to db selected
        self.r = redis.Redis(host=host, port=port, db=db)
        self.expire_t = expire

    def iscached(self,ip):
        a = self.r.get(ip)
        logger.debug('Checked for {} in cache and received: {}'.format(ip, a))
        if a:
            return True
        else:
            return False

    def setcache(self,ip):
        a = self.r.set(name=ip, value=0, ex=self.expire_t)
        logger.debug('Sent {} to cache and received: {}'.format(ip, a))


def parse_ignore_cidr_option(cidrlist):
    """
    Given a comma-seperated list of CIDR addresses, split them and validate they're valid CIDR notation
    :param cidrlist: string representing a comma seperated list of CIDR addresses
    :return: a list containing IPy.IP objects representing the ignore_cidr addresses
    """
    l = list()
    for c in cidrlist.split(','):
        try:
            s = c.strip(' ')
            i = IP(s)
            l.append(i)
        except ValueError as e:
            logger.warning('Received invalid CIDR in ignore_cidr: {}'.format(e))
    return l


def handle_message(msg, bhr, cache, include_hp_tags=False, duration=3600):
    logger.debug('Handling message: {}'.format(msg))

    if cache.iscached(msg['src_ip']):
        logger.info('Skipped submitting {} due to cache hit'.format(msg['src_ip']))
        return

    if msg['signature'] == 'Connection to Honeypot':
        logger.debug('Found signature: {}'.format(msg['signature']))

        try:
            app = msg['app']
            msg_tags = ['honeypot']
            if include_hp_tags and msg['tags']:
                msg_tags = msg['tags']

            why = ','.join(msg_tags)
            if why and why[-1] == ',':
                why = why[:-1]

            indicator = msg['src_ip']
        except Exception as e:
            logger.error(e)

        logger.info('Submitting indicator: {0}'.format(indicator))

        try:
            logger.debug(
                'Submitting with: cidr={}, source={}, why={}, duration={}'.format(indicator, app, why, duration))
            r = bhr.block(cidr=indicator, source=app, why=why, duration=duration)
            logger.debug('Indicator submitted with id {}'.format(r))
            cache.setcache(indicator)
            logger.info(
                'Successfully sent {} to BHR for {} seconds and cached for {} seconds'.format(indicator, duration,
                                                                                              cache.expire_t))
            return True
        except (requests.exceptions.HTTPError, Exception) as e:
            if isinstance(e, requests.exceptions.HTTPError):
                logger.warning('Indicator {} is on the system safelist and was NOT blocked!'.format(indicator))
                logger.debug('HTTPError was: {}'.format(e.__dict__))
                cache.setcache(indicator)
            else:
                logger.error('Error submitting indicator: {0}'.format(repr(e)))
            return False

    return


def parse_config(config_file):
    if not os.path.isfile(config_file):
        sys.exit("Could not find configuration file: {0}".format(config_file))

    parser = ConfigParser()
    parser.read(config_file)

    config = {}

    config['hpf_feeds'] = parser.get('hpfeeds', 'channels').split(',')
    config['hpf_ident'] = parser.get('hpfeeds', 'ident')
    config['hpf_secret'] = parser.get('hpfeeds', 'secret')
    config['hpf_port'] = parser.getint('hpfeeds', 'hp_port')
    config['hpf_host'] = parser.get('hpfeeds', 'hp_host')
    config['include_hp_tags'] = parser.getboolean('hpfeeds', 'include_hp_tags')
    config['ignore_cidr'] = parser.get('hpfeeds', 'ignore_cidr')

    config['bhr_host'] = parser.get('bhr', 'bhr_host')
    config['bhr_ident'] = parser.get('bhr', 'bhr_ident')
    config['bhr_token'] = parser.get('bhr', 'bhr_token')
    config['bhr_username'] = parser.get('bhr', 'bhr_username')
    config['bhr_password'] = parser.get('bhr', 'bhr_password')
    config['bhr_ssl_no_verify'] = parser.getboolean('bhr', 'bhr_ssl_no_verify')
    config['bhr_timeout'] = parser.getint('bhr', 'bhr_timeout')
    config['bhr_duration'] = parser.getint('bhr', 'bhr_duration')
    config['bhr_cache_db'] = parser.getint('bhr', 'bhr_cache_db')
    config['bhr_cache_expire'] = parser.getint('bhr', 'bhr_cache_expire')

    logger.debug('Parsed config: {0}'.format(repr(config)))
    return config


def main():
    if len(sys.argv) < 2:
        return 1

    if os.environ.get('DEBUG').upper() == 'TRUE':
        logger.setLevel(logging.DEBUG)

    config = parse_config(sys.argv[1])
    host = config['hpf_host']
    port = config['hpf_port']
    channels = [c for c in config['hpf_feeds']]
    ident = config['hpf_ident']
    secret = config['hpf_secret']
    include_hp_tags = config['include_hp_tags']
    ignore_cidr_l = parse_ignore_cidr_option(config['ignore_cidr'])

    bhr_host = config['bhr_host']
    bhr_ident = config['bhr_ident']
    bhr_token = config['bhr_token']
    bhr_username = config['bhr_username']
    bhr_password = config['bhr_password']
    bhr_ssl_no_verify = config['bhr_ssl_no_verify']
    bhr_timeout = config['bhr_timeout']
    bhr_duration = config['bhr_duration']
    bhr_cache_db = config['bhr_cache_db']
    bhr_cache_expire = config['bhr_cache_expire']

    processor = processors.HpfeedsMessageProcessor(ignore_cidr_list=ignore_cidr_l)
    cache = RedisCache(db=bhr_cache_db, expire=bhr_cache_expire)
    logger.info('Set up Redis cache with database {} and expire time of {}'.format(bhr_cache_db, bhr_cache_expire))

    logger.info('Configuring BHR')
    try:
        # Don't send ident until bug is fixed in pip package
        bhr = bhr_login(host=bhr_host, token=bhr_token, username=bhr_username, password=bhr_password,
                        ssl_no_verify=bhr_ssl_no_verify, timeout=bhr_timeout)
        logger.info('Configured BHR: {}'.format(repr(bhr.__dict__)))
        logger.debug('Configured BHR Sessions: {}'.format(repr(bhr.s.__dict__)))
    except Exception as e:
        logger.error('Logging into BHR failed: {}'.format(repr(e)))
        return 1
    try:
        logger.info('Initializing HPFeeds connection with {0}, {1}, {2}, {3}'.format(host, port, ident, secret))
        hpc = hpfeeds.client.new(host, port, ident, secret)
    except hpfeeds.FeedException as e:
        logger.error('Experienced FeedException: {0}'.format(repr(e)))
        return 1

    def on_message(identifier, channel, payload):
        for msg in processor.process(identifier, channel, payload.decode('utf-8'), ignore_errors=True):
            handle_message(msg, bhr, cache, include_hp_tags, duration=bhr_duration)

    def on_error(payload):
        logger.error("Handling error: {}".format(payload))
        hpc.stop()

    hpc.subscribe(channels)
    try:
        hpc.run(on_message, on_error)
    except:
        pass
    finally:
        hpc.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
