import os
import sys
import json
from datetime import datetime
import hpfeeds
from ConfigParser import ConfigParser
import processors
import logging
from IPy import IP
from bhr_client.rest import login as bhr_login

logging.basicConfig(level=logging.DEBUG)


def parse_ignore_cidr_option(cidrlist):
    '''
    Given a comma-seperated list of CIDR addresses, split them and validate they're valid CIDR notation
    :param cidrlist: string representing a comma seperated list of CIDR addresses
    :return: a list containing IPy.IP objects representing the ignore_cidr addresses
    '''
    l = list()
    for c in cidrlist.split(','):
        try:
            s = c.strip(' ')
            i = IP(s)
            l.append(i)
        except ValueError as e:
            logging.warn('Received invalid CIDR in ignore_cidr: {}'.format(e))
    return l



def handle_message(msg, host, token, tags, ssl, include_hp_tags=False):

    logging.debug('Found signature: {}'.format(msg['signature']))

    app = msg['app']
    msg_tags = []
    if include_hp_tags and msg['tags']:
        msg_tags = msg['tags']

    if ssl:
        bhr_ssl = False
    else:
        bhr_ssl = True

    if msg['signature'] == 'Connection to Honeypot':
        indicator = msg['src_ip']

        data = {
            'indicator': indicator,
            'source' : app,
            'why' : str(tags + msg_tags),
            'duration' : 3600,
            'ssl_no_verify': bhr_ssl
        }
        submit_to_bhr(data, host, token)

    return


def submit_to_bhr(data, host, token):
    logging.debug('Initializing BHR instance to host={}, with ssl_no_verify={}'.format(host, data['ssl_no_verify']))

    try:
        bhr = bhr_login(host=host, token=token, ident='chn-bhr')
    except Exception as e:
        logging.debug('Exception when submitting block to BHR: {}'.format(e))
        logging.debug('Further, bhr returned: {}'.format(bhr))

    logging.info('Submitting indicator: {0}'.format(data))
    try:
        r = bhr.block(cidr=data['indicator'],source=data['source'],why=data['why'],duration=data['duration'])
        logging.debug('Indicator submitted with id {}'.format(r))
        return True
    except Exception as e:
        logging.error('Error submitting indicator: {0}'.format(repr(e)))
        return False


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

    config['bhr_token'] = parser.get('bhr', 'bhr_token')
    config['bhr_host'] = parser.get('bhr', 'bhr_host')
    config['bhr_tags'] = parser.get('bhr', 'bhr_tags').split(',')
    config['bhr_verify_ssl'] = parser.getboolean('bhr', 'bhr_verify_ssl')

    logging.debug('Parsed config: {0}'.format(repr(config)))
    return config


def main():
    if len(sys.argv) < 2:
        return 1

    config = parse_config(sys.argv[1])
    host = config['hpf_host']
    port = config['hpf_port']
    channels = [c.encode('utf-8') for c in config['hpf_feeds']]
    ident = config['hpf_ident'].encode('utf-8')
    secret = config['hpf_secret'].encode('utf-8')
    include_hp_tags = config['include_hp_tags']
    ignore_cidr_l = parse_ignore_cidr_option(config['ignore_cidr'])

    bhr_token = config['bhr_token']
    bhr_host = config['bhr_host']
    bhr_tags = config['bhr_tags']
    bhr_verify_ssl = config['bhr_verify_ssl']

    processor = processors.HpfeedsMessageProcessor(ignore_cidr_list=ignore_cidr_l)
    logging.debug('Initializing HPFeeds connection with {0}, {1}, {2}, {3}'.format(host,port,ident,secret))
    logging.debug('Configuring BHR with: Host: {}, Tags: {}, SSL_Verify: {}, Token: {}'.format(bhr_host, bhr_tags, bhr_verify_ssl, bhr_token))
    try:
        hpc = hpfeeds.new(host, port, ident, secret)
    except hpfeeds.FeedException as e:
        logging.error('Experienced FeedException: {0}'.format(repr(e)))
        return 1

    def on_message(identifier, channel, payload):
        for msg in processor.process(identifier, channel, payload, ignore_errors=True):
            handle_message(msg, bhr_host, bhr_token, bhr_tags, bhr_verify_ssl, include_hp_tags)

    def on_error(payload):
        sys.stderr.write("Handling error.")
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
