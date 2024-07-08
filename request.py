class InputNumber(BaseModel):
    oriInvoiceNo: str
    invoiceNo: str
    deviceNo: str
    buyerTin: str
    buyerNinBrn: str
    buyerLegalName: str
    combineKeywords: str
    invoiceType: str
    invoiceKind: str
    isInvalid: str
    isRefund: str
    startDate: str = "dd/mm/yyyy"
    endDate: str = "dd/mm/yyyy"
    pageNo: str
    pageSize: str
    referenceNo: str
    branchName: str
    queryType: str
    dataSource: str
    sellerTinOrNin: str
    sellerLegalOrBusinessName: str
