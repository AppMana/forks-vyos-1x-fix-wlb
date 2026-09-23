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
from unittest.mock import patch

from helper import prepare_module

resolver = prepare_module(
    os.path.join(os.path.dirname(__file__), '..', 'services', 'vyos-domain-resolver'),
    'vyos_domain_resolver',
)


class TestDomainResolverWanLoadBalance(TestCase):
    def test_domain_group_fills_both_wlb_tables(self):
        # nftables-wlb.j2 declares D_<name> in the ip and in the ip6
        # vyos_wanloadbalance table; both must receive the resolved addresses
        config = {
            'group': {'domain_group': {'example': {'address': ['example.com']}}},
            'ip_fqdn': {},
            'ip6_fqdn': {},
        }
        valid_sets = [
            ('ip vyos_wanloadbalance', 'D_example'),
            ('ip6 vyos_wanloadbalance', 'D_example'),
        ]

        def resolve(domains, ipv6=False):
            return ['2001:db8::1'] if ipv6 else ['192.0.2.1']

        with patch.object(resolver, 'nft_valid_sets', return_value=valid_sets), \
             patch.object(resolver, 'resolve', side_effect=resolve), \
             patch.object(resolver, 'run', return_value=0) as run:
            resolver.update_fqdn(config, 'firewall')

        nft_input = run.call_args.kwargs['input']
        self.assertIn('add element ip vyos_wanloadbalance D_example { 192.0.2.1 }', nft_input)
        self.assertIn('add element ip6 vyos_wanloadbalance D_example { 2001:db8::1 }', nft_input)
