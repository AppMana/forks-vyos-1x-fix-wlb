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

import json
import os

from unittest import TestCase
from unittest.mock import patch

from helper import prepare_module

daemon = prepare_module(
    os.path.join(os.path.dirname(__file__), '..', 'helpers', 'vyos-load-balancer.py'),
    'vyos_load_balancer',
)


class FakeRoutes:
    """Answer the daemon's `ip -j route show` queries from a routing table
    model and record every command passed to run()."""

    def __init__(self, main6, tables6, tables4):
        self.main6 = main6        # ifname -> list of main table IPv6 default routes
        self.tables6 = tables6    # table number -> list of IPv6 default routes
        self.tables4 = tables4    # table number -> list of IPv4 default routes
        self.commands = []

    def rc_cmd(self, command):
        words = command.split()
        if command.startswith('ip -j -6 route show default dev '):
            return 0, json.dumps(self.main6.get(words[-1], []))
        if command.startswith('ip -j -6 route show default table '):
            return 0, json.dumps(self.tables6.get(int(words[-1]), []))
        if command.startswith('ip -j route show default table '):
            return 0, json.dumps(self.tables4.get(int(words[-1]), []))
        raise AssertionError(f'unexpected command: {command}')

    def run(self, command, **kwargs):
        self.commands.append(command)
        words = command.split()
        if command.startswith('ip -6 route replace table '):
            self.tables6[int(words[5])] = [{'dst': 'default', 'dev': words[-1]}]
        elif command.startswith('ip -6 route del table '):
            self.tables6[int(words[5])] = []
        return 0


class TestWanLoadBalanceIPv6DefaultRoute(TestCase):
    def loop_once(self, lb, routes):
        # The per-interface route maintenance of the daemon main loop
        with patch.object(daemon, 'rc_cmd', side_effect=routes.rc_cmd), \
             patch.object(daemon, 'run', side_effect=routes.run):
            daemon.ipv6_default_route_update(lb, 'eth0')
            daemon.restore_default_route(lb, 'eth0')

    def test_route_withdrawn_from_interface_leaves_wlb_table(self):
        gateway = {'dst': 'default', 'gateway': 'fe80::1', 'dev': 'eth0'}
        routes = FakeRoutes(
            main6={'eth0': [gateway]},
            tables6={},
            tables4={201: [{'dst': 'default'}]},
        )
        lb = {
            'health_state': {'eth0': {'table_number': 201, 'mark': '0xc9'}},
            'interface_health': {'eth0': {'nexthop': '203.0.113.1'}},
        }

        self.loop_once(lb, routes)
        self.assertIn('ip -6 route replace table 201 default via fe80::1 dev eth0', routes.commands)
        self.assertNotEqual(routes.tables6[201], [])

        # The upstream router withdraws its IPv6 default route (RA router
        # lifetime 0 or expiry): eth0 no longer has an IPv6 default
        routes.main6['eth0'] = []
        routes.commands.clear()
        self.loop_once(lb, routes)
        self.assertEqual(routes.tables6[201], [])

        # A later pass must not reinstall the withdrawn route
        routes.commands.clear()
        self.loop_once(lb, routes)
        self.assertEqual(routes.tables6[201], [])
        self.assertEqual(routes.commands, [])
