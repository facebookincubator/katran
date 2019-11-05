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
