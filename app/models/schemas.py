"""Pydantic schemas for request validation and response serialization."""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


# Health & Stats Schemas
class HealthResponse(BaseModel):
    status: str = "healthy"
    app_name: str
    version: str
    author: str
    timestamp: datetime
    modules: Dict[str, str]


class StatsResponse(BaseModel):
    total_analyses: int
    url_analyses: int
    pcap_analyses: int
    total_detections: int
    critical_detections: int
    total_iocs: int
    active_investigations: int
    max_risk_score: float


# Detection Schema
class DetectionResponse(BaseModel):
    id: Optional[int] = None
    analysis_id: Optional[int] = None
    investigation_id: Optional[str] = None
    detection_type: str
    source: Optional[str] = None
    destination: Optional[str] = None
    evidence: str
    severity: str
    confidence: str = "high"
    points: float = 0.0

    model_config = ConfigDict(from_attributes=True)


# Network Flow Schema
class NetworkFlowResponse(BaseModel):
    id: Optional[int] = None
    analysis_id: Optional[int] = None
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    duration: float
    tcp_flags: str

    model_config = ConfigDict(from_attributes=True)


# IOC Schema
class IOCResponse(BaseModel):
    id: Optional[int] = None
    analysis_id: Optional[int] = None
    investigation_id: Optional[str] = None
    value: str
    canonical_value: str
    type: str  # IPv4, DOMAIN, URL, HASH, EMAIL
    source: str
    confidence: str = "medium"
    classification: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# Correlation Schema
class CorrelationResponse(BaseModel):
    id: Optional[int] = None
    investigation_id: Optional[str] = None
    correlation_type: str
    ioc_value: str
    source_a: str
    source_b: str
    evidence: str
    confidence: str = "high"
    points: float = 15.0
    time_delta_seconds: Optional[float] = None

    model_config = ConfigDict(from_attributes=True)


# Timeline Event Schema
class TimelineEventResponse(BaseModel):
    id: Optional[int] = None
    investigation_id: Optional[str] = None
    timestamp: datetime
    event_type: str
    source: Optional[str] = None
    destination: Optional[str] = None
    ioc_value: Optional[str] = None
    title: str
    details: Optional[str] = None
    points: float = 0.0

    model_config = ConfigDict(from_attributes=True)


# URL Analysis Schemas
class URLAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Target URL string to analyze offline")


class RiskFactor(BaseModel):
    name: str
    points: float
    reason: str


class URLAnalyzeResponse(BaseModel):
    id: int
    target: str
    status: str
    risk_score: float
    severity: str
    summary: str
    features: Dict[str, Any]
    factors: List[RiskFactor]
    detections: List[DetectionResponse]
    iocs: List[IOCResponse]

    model_config = ConfigDict(from_attributes=True)


# PCAP Analysis Schemas
class PCAPAnalyzeResponse(BaseModel):
    id: int
    filename: str
    file_hash: str
    packet_count: int
    flow_count: int
    duration_seconds: float
    risk_score: float
    severity: str
    summary: str
    protocols: Dict[str, int]
    flows: List[NetworkFlowResponse]
    detections: List[DetectionResponse]
    iocs: List[IOCResponse]

    model_config = ConfigDict(from_attributes=True)


# Generic Analysis Record Schema
class AnalysisCreateRequest(BaseModel):
    analysis_type: str = Field(..., pattern="^(URL|PCAP)$")
    target: str = Field(..., min_length=1)


class AnalysisResponse(BaseModel):
    id: int
    analysis_type: str
    target: str
    status: str
    risk_score: float
    severity: str
    summary: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class AnalysisDetailResponse(AnalysisResponse):
    details_json: Dict[str, Any] = {}
    detections: List[DetectionResponse] = []
    flows: List[NetworkFlowResponse] = []
    iocs: List[IOCResponse] = []

    model_config = ConfigDict(from_attributes=True)


# Investigation Schemas
class InvestigationCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    analysis_ids: List[int] = Field(default_factory=list, description="IDs of analyses to link")
    explanation: Optional[str] = None


class InvestigationResponse(BaseModel):
    id: str
    title: str
    status: str
    risk_score: float
    severity: str
    explanation: Optional[str] = None
    created_at: datetime
    analyses_count: int = 0
    detections_count: int = 0
    iocs_count: int = 0
    correlations_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class InvestigationDetailResponse(BaseModel):
    id: str
    title: str
    status: str
    risk_score: float
    severity: str
    explanation: Optional[str] = None
    recommendations: List[str] = []
    created_at: datetime
    analyses: List[AnalysisResponse] = []
    detections: List[DetectionResponse] = []
    iocs: List[IOCResponse] = []
    correlations: List[CorrelationResponse] = []
    timeline: List[TimelineEventResponse] = []

    model_config = ConfigDict(from_attributes=True)


# Report Schema
class ReportResponse(BaseModel):
    id: int
    investigation_id: str
    report_type: str
    filename: str
    file_path: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
