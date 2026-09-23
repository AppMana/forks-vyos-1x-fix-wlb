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

from unittest import TestCase

from vyos.wanloadbalance import nft_rule


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
