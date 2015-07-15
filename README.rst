Automatic CloudFlare Tor Exit Whitelister
=========================================

CloudFlare provides an external service to defend your site against denial of service attacks. Unfortunately Tor users are often inconvenienced by repeated requests to solve CAPTCHA's due to CloudFlare's threat scoring approach.

CloudFlare does not currently provide a means of allowing Tor visitors. Website operators should be able to take advantage of the increased stability and DoS resistance that CloudFlare provides without blocking their anonymous users.

On the `\[tor\-talk\] <https://lists.torproject.org/pipermail/tor-talk/2015-May/037815.html>`_ mailing list, Moritz Bartl proposed the idea that operators could explicitly white list Tor exit IP addresses in their control panel as a stop-gap measure to avoid blocking their users.

This script is a rough proof-of-concept which whitelist's Tor exit IP addresses via the CloudFlare REST API. Problematically CloudFlare currently enforces a maximum limit of 200 access rules per user or zone. However the top 200 Tor exit IP addresses currently represent ~95% of the exit probability. as such using this should still significantly reduce the user experience for Tor users.

All feedback and bug reports very welcome!

Installation
------------

::

    $ pip install cloudflare-whitelist

Usage
-----

Your CloudFlare API token and email can also be specified in the environment variables CLOUDFLARE_API_TOKEN and CLOUDFLARE_EMAIL.

::

    $ cloudflare-whitelist -t 'API_TOKEN' -e 'CLOUDFLARE_EMAIL'

By default the whitelist rules are applied across all zones owned by your account. If instead you would like to only whitelist on a particular domain you should specify it with the --zone option.

It is probably sufficient to run this script via `cron` once per day.
