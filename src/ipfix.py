from objects import DefaultInput, dataIpfix, TemplateFields

from scapy.all import IP,UDP,NetflowHeader,NetflowHeaderV9,NetflowFlowsetV9,NetflowTemplateV9,NetflowTemplateFieldV9,GetNetflowRecordV9,NetflowDataflowsetV9,send


NetflowV9TemplateFieldDefaultLengthsAdditional = {
    "VPN_ROUTE_DISTINGUISHER": 8
}

# Fields: https://github.com/secdev/scapy/blob/master/scapy/layers/netflow.py
def __convert_additional_field_to_length(fieldType):
    if fieldType in NetflowV9TemplateFieldDefaultLengthsAdditional:
        return NetflowV9TemplateFieldDefaultLengthsAdditional[fieldType]
    return None

def craft_ip(src_ip:str, dst_ip:str):
    return IP(src=src_ip,dst=dst_ip)

def craft_udp(src_port:int, dest_port:int):
    return UDP(sport=src_port,dport=dest_port)

def craft_ipfix_template(flowSetID:int, templateID:int, template_fields:TemplateFields):
    templates = []
    for tf in template_fields:
        fieldLength = __convert_additional_field_to_length(tf.fieldType)
        if tf.fieldLength is not None:
            fieldLength = tf.fieldLength

        if fieldLength is not None:
            template = NetflowTemplateFieldV9(fieldType=tf.fieldType, fieldLength=fieldLength)
        else:
            template = NetflowTemplateFieldV9(fieldType=tf.fieldType)

        templates.append(template)

    return NetflowFlowsetV9(
        templates=[NetflowTemplateV9(
            template_fields=templates,
            templateID=templateID,
            fieldCount=len(templates)
        )],
        flowSetID=flowSetID
    )

def craft_ipfix_data(recordClass, templateID:int, template_fields:TemplateFields):
    data = [{tf.fieldType: tf.values[i] for tf in template_fields} for i in range(len(template_fields[0].values))]

    records = [recordClass(**d) for d in data]

    return NetflowDataflowsetV9(
        templateID=templateID,
        records=records
    )

def craft_packet(defaultInput: DefaultInput, data: dataIpfix):
    ip = craft_ip(defaultInput.src_ip, defaultInput.dst_ip)
    udp = craft_udp(defaultInput.src_port, defaultInput.dest_port)
    header = ip/udp

    netflow_header = NetflowHeader()/NetflowHeaderV9()

    flowset = craft_ipfix_template(data.flowSetID, data.templateID,data.template_fields)

    recordClass = GetNetflowRecordV9(flowset, data.flowSetID)

    dataFS = craft_ipfix_data(recordClass, data.templateID, data.template_fields)

    pkt = header / netflow_header / flowset / dataFS

    return pkt
