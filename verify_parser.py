from ngap_analyzer.packet_parser import PacketParser

p = PacketParser()
ngap_layer = {
    'ngap.procedureCode': [{'raw': '14'}],
    'ngap.AMF_UE_NGAP_ID': [{'raw': '302'}],
    'ngap.radioNetwork': [{'raw': '21'}],
    'ngap.nas': [{'raw': '1'}],
}
print('procedureCode', p._extract_int(ngap_layer, ['ngap.procedureCode']))
print('AMF', p._extract_int(ngap_layer, ['ngap.AMF_UE_NGAP_ID']))
print('radioNetwork', p._extract_str(ngap_layer, ['ngap.radioNetwork']))
print('nas', p._extract_str(ngap_layer, ['ngap.nas']))
