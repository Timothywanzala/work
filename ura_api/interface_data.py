# import base64

def create_interface_data(encrypted_string_data, signed_bytes)-> dict:
    # encrypted_string_data = base64.b64encode(encrypted_string).decode('utf-8')
    # signed_bytes = base64.b64encode(signed_data).decode('utf-8')

    interface_data ={
                "data": {
                "content": "",
                "signature": "",
                "dataDescription": {
                "codeType": "0",
                "encryptCode": "1",
                "zipCode": "0"
                }
                },
                "globalInfo": {
                "appId": "AP01",
                "version": "1.1.20191201",
                "dataExchangeId": "9230489223014123",
                "interfaceCode": "T101",
                "requestCode": "TP",
                "requestTime": "2024-07-25 15:22:37",
                "responseCode": "TA",
                "userName": "admin",
                "deviceMAC": "FFFFFFFFFFFF",
                "deviceNo": "1008686938_01",
                "tin": "1008686938",
                "brn": "",
                "taxpayerID": "1",
                "longitude": "116.397128",
                "latitude": "39.916527",
                "agentType": "0",
                "extendField": {
                "responseDateFormat": "dd/MM/yyyy",
                "responseTimeFormat": "dd/MM/yyyy HH:mm:ss",
                "referenceNo": "21PL010020807" ,
                "operatorName": "administrator",
                "offlineInvoiceException": {
                "errorCode": "",
                "errorMsg": ""
                }
                }
                },
                "returnStateInfo": {
                "returnCode": "",
                "returnMessage": ""
                }
                }
    return interface_data