-- Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; version 2 of the License.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

-- wireshark dissector for GUE variant 1

do
  local ip = Dissector.get("ip")
  local ipv6 = Dissector.get("ipv6")

  local guev1 = Proto("guev1", "GUE variant 1")
  local proto = ProtoField.new("Protocol", "guev1.proto", ftypes.UINT8, nil, base.DEC, 0xF0)
  guev1.fields = {proto}

  local proto_field = Field.new("guev1.proto")

  function guev1.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol:set("GUEv1")

    local subtree = tree:add(guev1, tvb(0,1))
    subtree:add(proto, tvb(0,1))

    if proto_field()() == 6 then
      ipv6:call(tvb, pinfo, tree)
    else
      ip:call(tvb, pinfo, tree)
    end
  end

  local udp_table = DissectorTable.get("udp.port")
  udp_table:add(6080, guev1)
end
