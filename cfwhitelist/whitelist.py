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


class CloudFlareAPIError(requests.RequestException):
    """
    Exception when CloudFlare request doesn't succeed
    """

CLOUDFLARE_ACCESS_RULE_LIMIT = 200


def retrieve_top_tor_exit_ips(limit=CLOUDFLARE_ACCESS_RULE_LIMIT):
    """
    Retrieve exit information from Onionoo sorted by consensus weight
    """
    exits = {}
    params = {
        'running': True,
        'flag': 'Exit',
        'fields': 'or_addresses,exit_probability',
        'order': '-consensus_weight',
        'limit': limit
    }
    r = requests.get("https://onionoo.torproject.org/details", params=params)
    r.raise_for_status()
    res = r.json()
    for relay in res.get('relays'):
        or_address = relay.get('or_addresses')[0].split(':')[0]
        exit_probability = relay.get('exit_probability', 0.0)
        # Try calculate combined weight for all relays on each IP
        exits[or_address] = exits.get(or_address, 0.0) + exit_probability
    return sorted(exits, key=exits.get, reverse=True)


def fetch_access_rules(session, page_num=1, zone_id=None, per_page=50):
    """
    Fetch current access rules from the CloudFlare API
    """

    # If zone_id, only apply rule to current zone/domain
    params = {'page': page_num, 'per_page': per_page}
    if zone_id:
        r = session.get('https://api.cloudflare.com/client/v4/zones/{}'
                        '/firewall/access_rules/rules'.format(
                            zone_id), params=params)
    else:
        r = session.get('https://api.cloudflare.com/client/v4/user'
                        '/firewall/access_rules/rules', params=params)
    r.raise_for_status()
    res = r.json()
    if not res['success']:
        raise CloudFlareAPIError(res['errors'])
    else:
        return res


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
                         '/firewall/access_rules/rules'.format(
                             zone_id), data=json.dumps(data))
    else:
        # Apply whitelist rules across all domains owned by this user.
        data.update({"group": {"id": "owner"}})
        r = session.post('https://api.cloudflare.com/client/v4/user'
                         '/firewall/access_rules/rules',
                         data=json.dumps(data))
    r.raise_for_status()
    res = r.json()
    if not res['success']:
        raise CloudFlareAPIError(res['errors'])


def remove_access_rule(session, rule_id, zone_id=None):
    """
    Remove an existing access rule via the CloudFlare API
    """
    if zone_id:
        r = session.delete('https://api.cloudflare.com/client/v4/zones/{}'
                           '/firewall/access_rules/rules/{}'.format(
                               zone_id, rule_id))
    else:
        # Apply rule across all zones
        r = session.delete('https://api.cloudflare.com/client/v4/user'
                           '/firewall/access_rules/rules/{}'.format(
                               rule_id))
    r.raise_for_status()
    res = r.json()
    if not res['success']:
        raise CloudFlareAPIError(res['errors'])


def parse_cmd_args():
    """
    Parses and returns command line arguments.
    """

    parser = argparse.ArgumentParser(
        description="cloudflare-whitelist whitelists Tor exit IP's on "
        "CloudFlare. The API token and email address can also be specified "
        "in the environment variables CLOUDFLARE_API_TOKEN and "
        "CLOUDFLARE_EMAIL.",
        epilog="Cloudflare limits the number of access rules on your "
        "account depending on your account level and number of domains. "
        "The addition of a second domain a free CloudFlare account should "
        "allow for up to 400 rules. With a Pro account you should be able to "
        "add up to 1000 access rules rules.")

    parser.add_argument("-t", "--token", type=str,
                        default=os.environ.get('CLOUDFLARE_API_TOKEN', None),
                        help="CloudFlare API token (available from your "
                             "'My Account' page).")

    parser.add_argument("-e", "--email", type=str,
                        default=os.environ.get('CLOUDFLARE_EMAIL', None),
                        help="CloudFlare account email address")

    parser.add_argument("-z", "--zone", help="Zone (domain) to whitelist. "
                        "Default is to whitelist across all zones owned by "
                        "your CloudFlare account.")

    parser.add_argument("--clear-rules", action='store_true',
                        help="Remove all currently active Tor rules. Must be "
                        "run for each zone if rules are specifed per zone/"
                        "domain.")

    parser.add_argument("-v", "--verbosity", type=str, default="info",
                        help="Minimum verbosity level for logging.  Available "
                             "in ascending order: debug, info, warning, "
                             "error, critical).  The default is info.")

    parser.add_argument("--rule-limit", type=int,
                        default=CLOUDFLARE_ACCESS_RULE_LIMIT,
                        help="Maximum number of access rules which can be "
                        "added to your CloudFlare account. "
                        "(default: %(default)s)")

    return parser.parse_args()


def main():
    """
    Load latest exit list and whitelist current Tor IP's
    """
    args = parse_cmd_args()
    session = requests.session()

    logger.setLevel(logging.__dict__[args.verbosity.upper()])

    if not (args.token or args.email):
        logger.error('A CloudFlare API token and email must be specified')
        sys.exit(1)

    # Set headers required for each API request
    session.headers.update({
        'Content-Type': 'application/json',
        'X-Auth-Key': args.token,
        'X-Auth-Email': args.email
    })

    # Make request to test CloudFlare connection.
    try:
        r = session.get('https://api.cloudflare.com/client/v4/user')
        res = r.json()
        r.raise_for_status()
    except requests.RequestException:
        if res.get('errors'):
            # CloudFlare API doesn't give a proper HTTP status code for
            # incorrect credentials
            if any(error.get('code') == 9103 for error in res.get('errors')):
                logger.error("Your Cloudflare API or email address appears "
                             "to be incorrect.")
            else:
                logger.exception("Error connecting to CloudFlare account.")
        sys.exit(1)

    else:
        if res.get('success'):
            logger.info("Successfully authenticated to the CloudFlare API")
        else:
            logger.error("Error occurred: %s", res.get('errors'))
            sys.exit(1)

    # Determine Zone/Domain information if a zone is specified
    if args.zone:
        try:
            r = session.get('https://api.cloudflare.com/client/v4/zones',
                            params={'status': 'active', 'name': args.zone})
            r.raise_for_status()
            res = r.json()
        except requests.RequestException:
            logger.exception("Error retrieving client zone information")
            sys.exit(1)
        else:
            if res.get('success') and res.get('result'):
                zone_id = res.get('result')[0]['id']
                logger.info("Selected zone '%s'", res['result'][0]['name'])
            else:
                logger.error("Could not find the specified domain/zone")
                sys.exit(1)
    else:
        zone_id = None
        logger.info("No zone specified. Whitelist will be applied across all "
                    "domains.")

    # Extract currently active Tor whitelist
    tor_rules = {}
    rules = fetch_access_rules(session, 1, zone_id=zone_id)
    total_rules_count = rules['result_info']['total_count']

    # Load currently active rule set by iterating the paginated result
    for page in range(1, rules['result_info']['total_pages'] + 1):
        # Don't request the first page again
        if page is not 1:
            rules = fetch_access_rules(session, page, zone_id=zone_id)

        for rule in rules['result']:
            if rule['notes'] == 'tor_exit' and rule['mode'] == 'whitelist':
                # If no zone_id specified, select rules applied to all sites
                if not zone_id and rule['scope']['type'] == 'user':
                    tor_rules[rule['id']] = (rule['configuration']['value'])
                elif zone_id and rule['scope']['type'] == 'zone':
                    tor_rules[rule['id']] = (rule['configuration']['value'])
                else:
                    logger.debug('Tor rule %s (IP: %s) did not match '
                                 'selected zone', rule['id'],
                                 rule['configuration']['value'])

    num_tor_rules = len(tor_rules)
    logger.debug("Found %d matching Tor access rules", num_tor_rules)

    # Remove all the active Tor rules if --clear-rules is specified
    if args.clear_rules:
        for rule_id, ip_address in tor_rules.items():
            try:
                remove_access_rule(session, rule_id, zone_id)
            except requests.RequestException:
                logger.exception('Error deleting access rule %s (IP: %s)',
                                 rule_id, ip_address)
            else:
                logger.debug('Removed access rule for IP %s', ip_address)
        logger.info("Removed %d matching Tor access rules.", num_tor_rules)
        sys.exit(0)

    # Retrieve list of top Tor exits
    try:
        # Retrieve some extra relay IP's, some IP's have multiple fast exits
        exit_addresses = retrieve_top_tor_exit_ips(int(args.rule_limit * 1.5))
    except requests.RequestException:
        logger.exception("Error when retrieving Tor exit list")
        sys.exit(1)
    else:
        if not exit_addresses:
            logger.error('Did not retrieve any Tor exit IPs from Onionoo')
            sys.exit(1)
        else:
            logger.info('Retrieved %d exit IP addresses from Onionoo',
                        len(exit_addresses))

    # Calculate the max number of Tor rules that we can insert.
    max_num_tor_rules = (args.rule_limit -
                         (total_rules_count - num_tor_rules))
    exit_addresses = exit_addresses[:max_num_tor_rules]

    logger.debug("Can create a maximum of %d access rules", max_num_tor_rules)

    # Remove all Tor rules that are no longer needed
    for rule_id in list(tor_rules.keys()):
        ip_address = tor_rules[rule_id]
        if ip_address not in exit_addresses:
            try:
                remove_access_rule(session, rule_id, zone_id)
            except requests.RequestException:
                logger.exception('Error deleting access rule %s (IP: %s)',
                                 rule_id, ip_address)
            else:
                del tor_rules[rule_id]
                logger.debug('Removed access rule for IP %s', ip_address)

    # Insert new rules
    num_rules_added = 0
    for exit_address in exit_addresses:
        if exit_address not in tor_rules.values():
            # Rule for this exit does not already exist, insert it
            try:
                add_whitelist_rule(session, exit_address, zone_id)
            except CloudFlareAPIError as errors:
                if any(error.get('code') == 81019 for error in errors.args[0]):
                    # Hit the access rule limit
                    logger.error(
                        'Cloudflare access rule quota has been exceeded: You '
                        'may be trying to add more access rules than your '
                        'account currently allows. Please check the '
                        '--rule-limit option.')
                    break
                else:
                    logger.exception('Unknown error creating access rule.')
                    raise
            else:
                num_rules_added += 1
                logger.debug("Added whitelist rule for IP %s", exit_address)

    # Confirm number of rules
    num_tor_rules = (len(tor_rules) + num_rules_added)

    logger.info("Done! Added %d new rules. There are now %d Tor exit relay "
                "rules", num_rules_added, num_tor_rules)
    sys.exit(0)

if __name__ == '__main__':
    main()
