# -*- coding: utf-8 -*-
"""
Script to whitelist Tor exit IP's on a CloudFlare account
"""
import os
import sys
import json
import requests
import argparse
import logging

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(fmt="%(asctime)s [%(levelname)s]: "
                                           "%(message)s"))

logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


CLOUDFLARE_ACCESS_RULE_LIMIT = 200


def retrieve_top_tor_exit_ips(limit=CLOUDFLARE_ACCESS_RULE_LIMIT):
    """
    Retrieve exit information from Onionoo sorted by consensus weight
    """
    exit_ips = set()
    params = {
        'running': True,
        'flag': 'Exit',
        'fields': 'or_addresses',
        'order': '-consensus_weight',
        'limit': limit
    }
    r = requests.get("https://onionoo.torproject.org/details", params=params)
    r.raise_for_status()
    res = r.json()
    for relay in res.get('relays'):
        or_address = relay.get('or_addresses')[0]
        exit_ips.add(or_address.split(':')[0])
    return list(exit_ips)


def add_whitelist_rule(session, ip, zone_id=None):
    """
    Make request to CloudFlare API to whitelist an IP.
    """

    data = {
        "mode": "whitelist",
        "notes": "tor_exit",
        "configuration": {"value": ip, "target": "ip"},
    }

    # If zone_id, only apply rule to current zone/domain
    if zone_id:
        data.update({"group": {"id": "zone"}})
        r = session.post('https://api.cloudflare.com/client/v4/zones/{}'
                         '/firewall/packages/access_rules/rules'.format(
                            zone_id), data=json.dumps(data))
    else:
        # Apply whitelist rules across all domains owned by this user.
        data.update({"group": {"id": "owner"}})
        r = session.post('https://api.cloudflare.com/client/v4/zones/{}'
                         '/firewall/packages/access_rules/rules'.format(
                            zone_id), data=json.dumps(data))
    r.raise_for_status
    res = r.json()
    if res.get('success'):
        logger.debug("Successfully white-listed IP %s" % ip)
        return True
    else:
        logger.error("Unknown error occurred: {}".format(res.get('errors')))
        exit(1)


def remove_access_rule(session, rule_id):
    """
    Remove an existing access rule via the CloudFlare API
    """
    r = session.delete('https://api.cloudflare.com/client/v4/user/firewall/'
                       'packages/access_rules/rules/{}'.format(rule_id))
    r.raise_for_status


def parse_cmd_args():
    """
    Parses and returns command line arguments.
    """

    parser = argparse.ArgumentParser(
        description="%s whitelists Tor exit IP's on CloudFlare. The API "
        "token and email address can also be specified in the environment "
        "variables CLOUDFLARE_API_TOKEN and CLOUDFLARE_EMAIL." % sys.argv[0])

    parser.add_argument("-t", "--token", type=str, required=True,
                        default=os.environ.get('CLOUDFLARE_API_TOKEN', None),
                        help="CloudFlare API token (available from your "
                             "'My Account' page).")

    parser.add_argument("-e", "--email", required=True,
                        default=os.environ.get('CLOUDFLARE_EMAIL', None),
                        help="CloudFlare account email address")

    parser.add_argument("-z", "--zone", help="Zone (domain) to whitelist. "
                        "Default is the first enabled zone.")

    return parser.parse_args()


def main():
    """
    Load latest exit list and whitelist current Tor IP's
    """
    args = parse_cmd_args()
    session = requests.session()

    # Set headers required for each API request
    session.headers.update({
        'Content-Type': 'application/json',
        'X-Auth-Key': args.token,
        'X-Auth-Email': args.email
    })

    # Make request to test CloudFlare connection.
    try:
        r = session.get('https://api.cloudflare.com/client/v4/user')
        r.raise_for_status()
        res = r.json()
    except requests.RequestException:
        logger.exception('Error connecting to CloudFlare account.')
        sys.exit(1)

    else:
        if res.get('success'):
            logger.info("Successfully authenticated to the CloudFlare API")
        else:
            logger.error("Error occurred: %s" % res.get('errors'))
            sys.exit(1)

    # Determine Zone/Domain to whitelist.
    params = {'status': 'active'}
    if args.zone:
        params.update({'name': args.zone})

    try:
        r = session.get('https://api.cloudflare.com/client/v4/zones',
                        params=params)
        r.raise_for_status()
        res = r.json()
    except requests.RequestException:
        logger.exception("Error retrieving client zone information")
        sys.exit(1)
    else:
        if res.get('success') and res.get('result'):
            zone_id = res.get('result')[0].get('id')
            logger.info("Selected zone '%s'" % res['result'][0].get('name'))
        else:
            logger.error("Could not find suitable zone to whitelist")
            sys.exit(1)

    # Extract current Tor whitelist
    tor_rules = {}
    rules_endpoint = ('https://api.cloudflare.com/client/v4/zones/{}'
                      '/firewall/packages/access_rules/rules'.format(zone_id))
    rules = session.get(rules_endpoint, params={'per_page': 50}).json()
    total_rules_count = rules['result_info']['total_count']

    # Load currently active rule set by iterating the paginated result
    for page in range(1, rules['result_info']['total_pages'] + 1):
        # Don't request the first page again
        if page is not 1:
            rules = session.get(rules_endpoint,
                                params={'per_page': 50, 'page': page}).json()

        for rule in rules['result']:
            if rule['notes'] == 'tor_exit' and rule['mode'] == 'whitelist':
                tor_rules[rule['id']] = rule['configuration']['value']

    num_tor_rules = len(tor_rules)
    logger.debug("Found {} existing Tor whitelist access rules".format(
                 num_tor_rules))

    # Retrieve list of top Tor exits
    try:
        exit_addresses = retrieve_top_tor_exit_ips()
    except requests.RequestException:
        logger.exception("Error when retrieving Tor exit list")
        sys.exit(1)
    else:

        if not exit_addresses:
            logger.error('Did not retrieve any Tor exit IPs from Onionoo')
            sys.exit(1)
        else:
            logger.debug('Retrieved {} exit IP addresses from Onionoo'.format(
                         len(exit_addresses)))

    # Calculate the max number of Tor rules that we can insert.
    max_num_tor_rules = (CLOUDFLARE_ACCESS_RULE_LIMIT + num_tor_rules -
                         - total_rules_count)
    exit_addresses = exit_addresses[:max_num_tor_rules]

    # Remove all Tor rules that are no longer needed
    for rule_id, ip_address in tor_rules.items():
        if ip_address not in exit_addresses:
            try:
                remove_access_rule(session, rule_id)
            except requests.RequestException:
                logger.exception('Error deleting access rule.')
            else:
                logger.debug('Removed access rule for IP {}'.format(
                             ip_address))

    # Insert new rules
    num_rules_added = 0
    for exit_address in exit_addresses:
        if exit_address not in tor_rules.values():
            # Rule for this exit does not already exist, insert it
            try:
                add_whitelist_rule(session, exit_address, zone_id)
            except requests.RequestException:
                logger.exception('Error creating access rule.')
            else:
                num_rules_added += 1
                logger.debug("Added whitelist rule for IP {}".format(
                             exit_address))

    # Confirm number of rules
    rules = session.get(rules_endpoint).json()
    rules['result_info']['total_count']

    num_tor_rules = (rules['result_info']['total_count'] -
                     (total_rules_count - num_tor_rules))

    logger.info("Done! Added {} new rules. There are now {} Tor exit relay "
                "whitelist rules".format(num_rules_added, num_tor_rules))
    sys.exit(0)

if __name__ == '__main__':
    main()
