from typing import Union, Any

class DefaultInput:
    def __init__(self, src_ip:str, dst_ip:str, src_port:int, dest_port:int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dest_port = dest_port

class TemplateField:
    def __init__(self, fieldType:Union[int, str], values: list[Any], fieldLength:int = None):
        self.fieldType = fieldType
        self.values = values
        self.fieldLength = fieldLength
TemplateFields = list[TemplateField]

class dataIpfix:
    def __init__(self, templateID:int, flowSetID:int=256, template_fields:TemplateFields = []):
        self.templateID = templateID # shourld be > 255
        self.flowSetID = flowSetID
        self.template_fields = template_fields