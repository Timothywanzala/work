from pydantic import BaseModel
from typing import List

class NumberDetails(BaseModel):
    dateFormat: str = "dd/MM/yyyy"
    nowTime: str = "dd/mm/yyyy hh:mm:ss"
    pageCount: int
    pageNo: int
    pageSize: int
    totalSize: int
    branchId: str
    branchName: str
    businessName: str
    buyerBusinessName: str
    buyerLegalName: str
    buyerTin: str
    currency: str
    dataSource: str
    dateFormat: str = "dd/MM/yyyy"
    deviceNo: str
    grossAmount: str
    id: str
    invoiceIndustryCode: str
    invoiceKind: str
    invoiceNo: str
    invoiceType: str
    isInvalid: str
    isRefund: str
    issuedDate: str = "dd/mm/yyyy hh:mm:ss"
    issuedDateStr: str = "dd/mm/yyyy"
    legalName: str
    nowTime: str = "dd/mm/yyyy hh:mm:ss"
    operator: str
    pageIndex: int = 0
    pageNo: int = 0
    pageSize: int = 0
    referenceNo: str
    taxAmount: str
    uploadingTime: str = "dd/mm/yyyy hh:mm:ss"
    userName: str


