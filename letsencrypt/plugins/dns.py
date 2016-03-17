"""Manual DNS plugin."""
from __future__ import absolute_import

import logging
import socket
import sys
import time

import dns.resolver
import tldextract
import zope.component
import zope.interface

from acme import challenges

from letsencrypt import errors
from letsencrypt import interfaces
from letsencrypt.plugins import common


logger = logging.getLogger(__name__)


class Authenticator(common.Plugin):
    """DNS Manual Authenticator.

    This plugin requires user's manual intervention in setting up DNS
    records for solving dns-01 challenges and thus does not need to be
    run as a privileged process.

    """
    zope.interface.implements(interfaces.IAuthenticator)
    zope.interface.classProvides(interfaces.IPluginFactory)
    hidden = True

    description = "Manually configure DNS records"

    CHALLENGE_PREFIX = '_acme-challenge'

    MESSAGE_TEMPLATE = """\
Make sure your DNS zone file for {domain} contains the following record
before continuing:

{subdomain} 60 IN TXT "{validation}"

(Where 60 is the TTL in seconds - this may be any value you like.)
"""

    # a disclaimer about your current IP being transmitted to Let's Encrypt's servers.
    IP_DISCLAIMER = """\
NOTE: The IP of this machine will be publicly logged as having requested this certificate. \
If you're running letsencrypt in manual DNS mode on a machine that is not your server, \
please ensure you're okay with that.

Are you OK with your IP being logged?
"""

    @classmethod
    def add_parser_arguments(cls, add):
        add("manual-wait", action="store_true",
            help="Don't check DNS records at the domain root, wait for user interaction")
        add("public-ip-logging-ok", action="store_true",
            help="Automatically allows public IP logging.")

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        if self.config.noninteractive_mode and self.conf("manual-wait"):
            raise errors.PluginError("Running manual DNS mode non-interactively is not supported")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return ("This plugin requires user's manual intervention in setting "
                "up a DNS record for solving dns-01 challenges and thus "
                "does not need to be run as a privileged process. ")

    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.DNS01]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        responses = []
        # TODO: group achalls by the same socket.gethostbyname(_ex)
        # and prompt only once per server (one "echo -n" per domain)
        for achall in achalls:
            responses.append(self._perform_single(achall))
        return responses

    def _perform_single(self, achall):
        # same path for each challenge response would be easier for
        # users, but will not work if multiple domains point at the
        # same server: default command doesn't support virtual hosts
        response, validation = achall.response_and_validation()

        if not self.conf("public-ip-logging-ok"):
            if not zope.component.getUtility(interfaces.IDisplay).yesno(
                    self.IP_DISCLAIMER, "Yes", "No",
                    cli_flag="--manual-public-ip-logging-ok"):
                raise errors.PluginError("Must agree to IP logging to proceed")

        extract = tldextract.extract(achall.domain)
        domain = extract.registered_domain
        subdomain = self.CHALLENGE_PREFIX + ('' if not extract.subdomain else '.' + extract.subdomain)

        self._notify_and_wait(validation, response, domain, subdomain)

        if not response.simple_verify(
                achall.chall, achall.domain,
                achall.account_key.public_key()):
            logger.warning("Self-verify of challenge failed.")

        return response

    @classmethod
    def _dns_wait(cls, fqdn, domain, validation):
        while True:
            try:
                # Query direct from the main NS, lest we pull in old records
                # that are then cached for the TTL.
                resolver = dns.resolver.Resolver(configure=False)
                for record in dns.resolver.query(domain, 'NS'):
                    host = record.target.to_unicode().rstrip('.')
                    ip = socket.gethostbyname(host)
                    resolver.nameservers.append(ip)
                try:
                    txt_records = resolver.query(fqdn, 'TXT')
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):  # pragma: no cover
                    pass
                else:
                    for record in txt_records:
                        for string in record.strings:
                            if string == validation:
                                return
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                # Domain may be waiting to be registered still
                pass
            time.sleep(15)

    def _notify_and_wait(self, validation, response, domain, subdomain):  # pylint: disable=no-self-use
        message = self.MESSAGE_TEMPLATE.format(
            validation=validation, response=response,
            domain=domain, subdomain=subdomain
            )
        fqdn = '{}.{}'.format(subdomain, domain)
        sys.stdout.write(message)
        if self.conf("manual-wait"):
            raw_input("Press ENTER to continue")
        else:
            sys.stdout.write('Waiting for DNS records to update...\n')
            self._dns_wait(fqdn, domain, validation)

    def cleanup(self, achalls):
        pass
