class GlobalInfo(BaseModel):
    appId: str
    version: str
    dataExchangeId: str
    interfaceCode: str
    requestCode: str
    requestTime: str
    responseCode: str
    userName: str
    deviceMAC: str
    deviceNo: str
    tin: str
    brn: str
    taxpayerID: str
    longitude: str
    latitude: str
    agentType: str
    extendField: dict

class ReturnStateInfo(BaseModel):
    returnCode: str
    returnMessage: str

class InterfaceJSON(BaseModel):
    data: dict
    globalInfo: GlobalInfo
    returnStateInfo: ReturnStateInfo