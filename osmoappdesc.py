#!/usr/bin/env python3

# (C) 2021 by sysmocom - s.m.f.c. GmbH <info@sysmocom.de>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

app_configs = {
    "osmo-hnbgw": ["doc/examples/osmo-hnbgw/osmo-hnbgw.cfg"]
}

apps = [(4261, "src/osmo-hnbgw/osmo-hnbgw", "OsmoHNBGW", "osmo-hnbgw")
        ]

vty_command = ["./src/osmo-hnbgw/osmo-hnbgw", "-c",
               "doc/examples/osmo-hnbgw/osmo-hnbgw.cfg"]

vty_app = apps[0]
