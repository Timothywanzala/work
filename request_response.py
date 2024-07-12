# request_response.py

from pydantic import BaseModel
from typing import List

class RequestData(BaseModel):
    oriInvoiceNo: str
    invoiceNo: str
    deviceNo: str
    # Add other fields as per your request format

class ResponseRecord(BaseModel):
    # Define fields as per your response format
    branchId: str
    branchName: str
    businessName: str
    # Add other fields as per your response format

class ResponseData(BaseModel):
    dateFormat: str
    nowTime: str
    page: dict
    records: List[ResponseRecord]
