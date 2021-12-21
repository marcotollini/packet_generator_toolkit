from objects import TemplateFields, TemplateField

defaultIpfix:TemplateFields = [
    TemplateField(fieldType="IN_BYTES", values=[b"\x00\x00\x00\x01", b"\x00\x00\x00\x01"]),
    TemplateField(fieldType="IN_PKTS", values=[b"\x00\x00\x00\x01", b"\x00\x00\x00\x01"]),
    TemplateField(fieldType="PROTOCOL", values=[6, 6]),
    TemplateField(fieldType="IPV4_SRC_ADDR", values=["1.1.1.1", "3.3.3.3"]),
    TemplateField(fieldType="IPV4_DST_ADDR", values=["2.2.2.2", "4.4.4.4"]),
    TemplateField(fieldType="INPUT_SNMP", values=[b"\x00\x62", b"\x00\x62"]),
    TemplateField(fieldType="OUTPUT_SNMP", values=[b"\x00\x63", b"\x00\x63"]),
    TemplateField(fieldType="SRC_AS", values=[65511, 65511]),
    TemplateField(fieldType="DST_AS", values=[65512, 65512]),
    TemplateField(fieldType="VPN_ROUTE_DISTINGUISHER", values=[b"\x00\x00\x27\x0f\x3b\x9a\xc9\xff", b"\x00\x00\x27\x0f\x3b\x9a\xc9\xff"]),
]