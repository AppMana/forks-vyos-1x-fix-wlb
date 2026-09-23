# Copyright VyOS maintainers and contributors <maintainers@vyos.io>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os

from unittest import TestCase

from vyos.template import render_to_string
from vyos.wanloadbalance import nft_rule

templates = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'templates')


def render_wlb(rule):
    def health(table):
        return {'state': True, 'table_number': table, 'mark': hex(table)}

    lb = {
        'first_install': {},
        'firewall_group': {},
        'interface_health': {'eth0': {}, 'eth1': {}},
        'health_state': {
            'eth0': dict(health(201), if_addr='203.0.113.10'),
            'eth1': dict(health(202), if_addr='192.0.2.10'),
        },
        'enable_local_traffic': {},
        'rule': {'10': rule},
    }
    return render_to_string('load-balancing/nftables-wlb.j2', lb, location=templates)


class TestWanLoadBalanceTemplate(TestCase):
    weighted = {
        'inbound_interface': 'eth2',
        'protocol': 'all',
        'interface': {'eth0': {'weight': '1'}, 'eth1': {'weight': '1'}},
    }

    def selection_rules(self, text):
        return [l.strip() for l in text.splitlines() if 'jump wlb_mangle_isp_' in l]

    def test_tracked_connection_keeps_its_first_choice(self):
        # conntrack reports "ct state new" for every original direction
        # packet until the peer replies (UDP before the answer, TCP SYN
        # retransmits). Such packets must not pick an interface again:
        # the connection's source NAT is already bound to the first one
        rules = [r for r in self.selection_rules(render_wlb(self.weighted))
                 if 'untracked' not in r]
        self.assertEqual(len(rules), 4)  # ip, ip6 x prerouting, output
        for rule in rules:
            self.assertIn('ct state new ct mark != { 0xc9, 0xca }', rule)

    def test_untracked_ipv6_flow_is_not_balanced_per_packet(self):
        # Without conntrack every packet of a flow is evaluated on its own,
        # so the interface has to be a function of the flow
        rules = [r for r in self.selection_rules(render_wlb(self.weighted))
                 if 'untracked' in r]
        self.assertEqual(len(rules), 2)  # ip6 prerouting, output
        for rule in rules:
            self.assertNotIn('numgen random', rule)
            self.assertIn('ct state untracked', rule)
            self.assertIn('jhash ip6 saddr . ip6 daddr mod 2 seed 0x0 vmap', rule)


    def test_source_nat_follows_egress_interface(self):
        # With only-default-route a marked connection is routed by the main
        # table when it has a more specific route, which can leave through
        # another WAN than the mark names. It still needs that WAN's address
        text = render_wlb(self.weighted)
        nat = text[text.index('chain wlb_nat_postrouting'):text.index('chain wlb_mangle_prerouting')]
        rules = [l.strip() for l in nat.splitlines() if 'snat to' in l]
        self.assertEqual(rules, [
            'ct mark { 0xc9, 0xca } oifname eth0 counter snat to 203.0.113.10',
            'ct mark { 0xc9, 0xca } oifname eth1 counter snat to 192.0.2.10',
        ])


class TestWanLoadBalanceNftRule(TestCase):
    def test_ipv4_address_range_is_rendered(self):
        # The CLI accepts ipv4range and !ipv4range for source/destination
        # address (include/ipv4-address-prefix-range.xml.i)
        for address, match in [
            ('192.0.2.1-192.0.2.10', 'ip saddr  192.0.2.1-192.0.2.10'),
            ('!192.0.2.1-192.0.2.10', 'ip saddr != 192.0.2.1-192.0.2.10'),
        ]:
            rule_conf = {
                'inbound_interface': 'eth2',
                'source': {'address': address},
            }
            self.assertEqual(
                nft_rule(rule_conf, '10', restore_mark=True),
                f'iifname "eth2" {match} counter meta mark set ct mark',
            )

    def test_ipv4_address_range_is_skipped_for_ipv6(self):
        rule_conf = {
            'inbound_interface': 'eth2',
            'source': {'address': '192.0.2.1-192.0.2.10'},
        }
        self.assertEqual(nft_rule(rule_conf, '10', restore_mark=True, ip_name='ip6'), '')
