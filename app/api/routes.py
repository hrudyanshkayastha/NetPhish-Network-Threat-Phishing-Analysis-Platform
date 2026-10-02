"""REST API endpoints for NetPhish platform.

Author: Hrudyansh Kayastha
"""

import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional, Dict, Any
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Query,
    status,
)
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from sqlalchemy.orm import Session

from app.config import (
    APP_NAME,
    APP_VERSION,
    AUTHOR,
    MAX_UPLOAD_SIZE_BYTES,
    ALLOWED_PCAP_EXTENSIONS,
    SAMPLES_DIR,
    REPORTS_DIR,
)
from app.database.db import (
    get_db,
    Analysis,
    NetworkFlow,
    Detection,
    IOC,
    Correlation,
    Investigation,
    TimelineEvent,
    Report,
    utc_now,
)
from app.models.schemas import (
    HealthResponse,
    StatsResponse,
    AnalysisResponse,
    AnalysisDetailResponse,
    URLAnalyzeRequest,
    URLAnalyzeResponse,
    PCAPAnalyzeResponse,
    IOCResponse,
    DetectionResponse,
    NetworkFlowResponse,
    CorrelationResponse,
    TimelineEventResponse,
    InvestigationCreateRequest,
    InvestigationResponse,
    InvestigationDetailResponse,
    ReportResponse,
)
from app.url_analysis.analyzer import analyze_url_target
from app.pcap_analysis.analyzer import analyze_pcap_file
from app.investigations.service import create_investigation_dossier
from app.reporting.generator import generate_json_report, generate_html_report

router = APIRouter(prefix="/api", tags=["NetPhish API"])


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Returns platform operational health and loaded module statuses."""
    return HealthResponse(
        status="healthy",
        app_name=APP_NAME,
        version=APP_VERSION,
        author=AUTHOR,
        timestamp=utc_now(),
        modules={
            "url_analyzer": "operational",
            "pcap_analyzer": "operational",
            "ioc_intelligence": "operational",
            "correlation_engine": "operational",
            "risk_scoring": "operational",
            "investigation_management": "operational",
            "forensic_reporting": "operational",
        },
    )


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)) -> StatsResponse:
    """Returns aggregated platform metrics across analyses, detections, and cases."""
    total_analyses = db.query(Analysis).count()
    url_analyses = db.query(Analysis).filter(Analysis.analysis_type == "URL").count()
    pcap_analyses = db.query(Analysis).filter(Analysis.analysis_type == "PCAP").count()
    total_detections = db.query(Detection).count()
    critical_detections = db.query(Detection).filter(Detection.severity == "CRITICAL").count()
    total_iocs = db.query(IOC).count()
    active_investigations = db.query(Investigation).filter(Investigation.status != "CLOSED").count()

    analyses = db.query(Analysis.risk_score).all()
    max_risk = max([a[0] for a in analyses], default=0.0)

    return StatsResponse(
        total_analyses=total_analyses,
        url_analyses=url_analyses,
        pcap_analyses=pcap_analyses,
        total_detections=total_detections,
        critical_detections=critical_detections,
        total_iocs=total_iocs,
        active_investigations=active_investigations,
        max_risk_score=round(max_risk, 1),
    )


@router.get("/analyses", response_model=List[AnalysisResponse])
def list_analyses(
    analysis_type: Optional[str] = Query(None, description="Filter by type (URL/PCAP)"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> List[AnalysisResponse]:
    """Retrieves paginated list of submitted analyses."""
    query = db.query(Analysis)
    if analysis_type:
        query = query.filter(Analysis.analysis_type == analysis_type.upper())
    if severity:
        query = query.filter(Analysis.severity == severity.upper())
    return query.order_by(Analysis.id.desc()).offset(offset).limit(limit).all()


@router.get("/analyses/{analysis_id}", response_model=AnalysisDetailResponse)
def get_analysis_detail(analysis_id: int, db: Session = Depends(get_db)) -> AnalysisDetailResponse:
    """Retrieves full details for a specific analysis record."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis ID {analysis_id} not found.")

    return AnalysisDetailResponse(
        id=analysis.id,
        analysis_type=analysis.analysis_type,
        target=analysis.target,
        status=analysis.status,
        risk_score=analysis.risk_score,
        severity=analysis.severity,
        summary=analysis.summary,
        created_at=analysis.created_at,
        completed_at=analysis.completed_at,
        details_json=analysis.details_json or {},
        detections=[DetectionResponse.model_validate(d) for d in analysis.detections],
        flows=[NetworkFlowResponse.model_validate(f) for f in analysis.flows],
        iocs=[IOCResponse.model_validate(i) for i in analysis.iocs],
    )


@router.delete("/analyses/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_analysis(analysis_id: int, db: Session = Depends(get_db)):
    """Deletes an analysis record and associated cascading child objects."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis ID {analysis_id} not found.")
    db.delete(analysis)
    db.commit()


@router.post("/url/analyze", response_model=URLAnalyzeResponse)
def analyze_url_endpoint(req: URLAnalyzeRequest, db: Session = Depends(get_db)) -> URLAnalyzeResponse:
    """Performs deterministic offline static lexical analysis on a target URL."""
    try:
        res = analyze_url_target(req.url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"URL parsing failed: {str(e)}")

    analysis = Analysis(
        analysis_type="URL",
        target=res["target"],
        status="COMPLETED",
        risk_score=res["risk_score"],
        severity=res["severity"],
        summary=res["summary"],
        details_json={
            "canonical_url": res["canonical_url"],
            "features": res["features"],
            "factors": res["factors"],
            "parsed": res["parsed"],
        },
        created_at=utc_now(),
        completed_at=utc_now(),
    )
    db.add(analysis)
    db.flush()

    for d in res["detections"]:
        db_det = Detection(
            analysis_id=analysis.id,
            detection_type=d["detection_type"],
            source=d.get("source"),
            destination=d.get("destination"),
            evidence=d["evidence"],
            severity=d["severity"],
            confidence=d.get("confidence", "high"),
            points=d.get("points", 0.0),
        )
        db.add(db_det)

    for i in res["iocs"]:
        db_ioc = IOC(
            analysis_id=analysis.id,
            value=i["value"],
            canonical_value=i["canonical_value"],
            type=i["type"],
            source=i.get("source", "URL_ANALYSIS"),
            confidence=i.get("confidence", "medium"),
            classification=str(i.get("classification")) if i.get("classification") is not None else None,
            first_seen=utc_now(),
            last_seen=utc_now(),
        )
        db.add(db_ioc)

    db.commit()
    db.refresh(analysis)

    return URLAnalyzeResponse(
        id=analysis.id,
        target=analysis.target,
        status=analysis.status,
        risk_score=analysis.risk_score,
        severity=analysis.severity,
        summary=analysis.summary,
        features=res["features"],
        factors=res["factors"],
        detections=[DetectionResponse.model_validate(d) for d in analysis.detections],
        iocs=[IOCResponse.model_validate(i) for i in analysis.iocs],
    )


@router.post("/pcap/analyze", response_model=PCAPAnalyzeResponse)
async def analyze_pcap_endpoint(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> PCAPAnalyzeResponse:
    """Parses and analyzes an uploaded PCAP/PCAPNG capture file completely offline."""
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED_PCAP_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Allowed extensions: {', '.join(sorted(ALLOWED_PCAP_EXTENSIONS))}",
        )

    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp_file:
        tmp_path = Path(tmp_file.name)
        file_size = 0
        while content := await file.read(1024 * 1024):  # 1MB chunks
            file_size += len(content)
            if file_size > MAX_UPLOAD_SIZE_BYTES:
                tmp_file.close()
                tmp_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds maximum upload limit of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB.",
                )
            tmp_file.write(content)

    try:
        res = analyze_pcap_file(str(tmp_path))
    except Exception as e:
        tmp_path.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail=f"PCAP analysis failed: {str(e)}")
    finally:
        tmp_path.unlink(missing_ok=True)

    analysis = Analysis(
        analysis_type="PCAP",
        target=file.filename or "capture.pcap",
        status="COMPLETED",
        risk_score=res["risk_score"],
        severity=res["severity"],
        summary=res["summary"],
        details_json={
            "file_hash": res["file_hash"],
            "packet_count": res["packet_count"],
            "flow_count": res["flow_count"],
            "duration_seconds": res["duration_seconds"],
            "protocols": res["protocols"],
            "factors": res.get("factors", []),
        },
        created_at=utc_now(),
        completed_at=utc_now(),
    )
    db.add(analysis)
    db.flush()

    # Save network flows (capped at 500 per capture to avoid DB exhaustion)
    for f in res["flows"][:500]:
        db_flow = NetworkFlow(
            analysis_id=analysis.id,
            src_ip=f["src_ip"],
            dst_ip=f["dst_ip"],
            src_port=f["src_port"],
            dst_port=f["dst_port"],
            protocol=f["protocol"],
            packet_count=f["packet_count"],
            byte_count=f["byte_count"],
            duration=f["duration"],
            tcp_flags=f.get("tcp_flags", ""),
        )
        db.add(db_flow)

    for d in res["detections"]:
        db_det = Detection(
            analysis_id=analysis.id,
            detection_type=d["detection_type"],
            source=d.get("source"),
            destination=d.get("destination"),
            evidence=d["evidence"],
            severity=d["severity"],
            confidence=d.get("confidence", "high"),
            points=d.get("points", 0.0),
        )
        db.add(db_det)

    for i in res["iocs"]:
        db_ioc = IOC(
            analysis_id=analysis.id,
            value=i["value"],
            canonical_value=i["canonical_value"],
            type=i["type"],
            source=i.get("source", "PCAP_FLOW"),
            confidence=i.get("confidence", "medium"),
            classification=str(i.get("classification")) if i.get("classification") is not None else None,
            first_seen=utc_now(),
            last_seen=utc_now(),
        )
        db.add(db_ioc)

    db.commit()
    db.refresh(analysis)

    return PCAPAnalyzeResponse(
        id=analysis.id,
        filename=analysis.target,
        file_hash=res["file_hash"],
        packet_count=res["packet_count"],
        flow_count=res["flow_count"],
        duration_seconds=res["duration_seconds"],
        risk_score=res["risk_score"],
        severity=res["severity"],
        summary=res["summary"],
        protocols=res["protocols"],
        flows=[NetworkFlowResponse.model_validate(f) for f in analysis.flows],
        detections=[DetectionResponse.model_validate(d) for d in analysis.detections],
        iocs=[IOCResponse.model_validate(i) for i in analysis.iocs],
    )


@router.get("/iocs", response_model=List[IOCResponse])
def list_iocs(
    ioc_type: Optional[str] = Query(None, description="Filter by type (IPv4, DOMAIN, URL, HASH, EMAIL)"),
    source: Optional[str] = Query(None, description="Filter by source"),
    confidence: Optional[str] = Query(None, description="Filter by confidence"),
    search: Optional[str] = Query(None, description="Substring search on value"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> List[IOCResponse]:
    """Retrieves paginated normalized Indicators of Compromise."""
    query = db.query(IOC)
    if ioc_type:
        query = query.filter(IOC.type == ioc_type.upper())
    if source:
        query = query.filter(IOC.source == source)
    if confidence:
        query = query.filter(IOC.confidence == confidence.lower())
    if search:
        query = query.filter(IOC.canonical_value.ilike(f"%{search}%"))
    return query.order_by(IOC.id.desc()).offset(offset).limit(limit).all()


@router.get("/iocs/{ioc_id}", response_model=IOCResponse)
def get_ioc_detail(ioc_id: int, db: Session = Depends(get_db)) -> IOCResponse:
    """Retrieves a single IOC record by ID."""
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail=f"IOC ID {ioc_id} not found.")
    return ioc


@router.post("/investigations", response_model=InvestigationDetailResponse)
def create_investigation_endpoint(
    req: InvestigationCreateRequest,
    db: Session = Depends(get_db),
) -> InvestigationDetailResponse:
    """Creates an investigation case uniting multiple analyses with cross-source correlation."""
    try:
        inv = create_investigation_dossier(
            db=db,
            title=req.title,
            analysis_ids=req.analysis_ids,
            explanation=req.explanation,
        )
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))

    return InvestigationDetailResponse(
        id=inv.id,
        title=inv.title,
        status=inv.status,
        risk_score=inv.risk_score,
        severity=inv.severity,
        explanation=inv.explanation,
        recommendations=inv.recommendations_json or [],
        created_at=inv.created_at,
        analyses=[AnalysisResponse.model_validate(a) for a in inv.analyses],
        detections=[DetectionResponse.model_validate(d) for d in inv.detections],
        iocs=[IOCResponse.model_validate(i) for i in inv.iocs],
        correlations=[CorrelationResponse.model_validate(c) for c in inv.correlations],
        timeline=[TimelineEventResponse.model_validate(t) for t in inv.timeline_events],
    )


@router.get("/investigations", response_model=List[InvestigationResponse])
def list_investigations(
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> List[InvestigationResponse]:
    """Retrieves paginated investigation cases."""
    query = db.query(Investigation)
    if status_filter:
        query = query.filter(Investigation.status == status_filter.upper())
    if severity:
        query = query.filter(Investigation.severity == severity.upper())

    invs = query.order_by(Investigation.created_at.desc()).offset(offset).limit(limit).all()
    results = []
    for inv in invs:
        results.append(
            InvestigationResponse(
                id=inv.id,
                title=inv.title,
                status=inv.status,
                risk_score=inv.risk_score,
                severity=inv.severity,
                explanation=inv.explanation,
                created_at=inv.created_at,
                analyses_count=len(inv.analyses),
                detections_count=len(inv.detections),
                iocs_count=len(inv.iocs),
                correlations_count=len(inv.correlations),
            )
        )
    return results


@router.get("/investigations/{investigation_id}", response_model=InvestigationDetailResponse)
def get_investigation_detail(investigation_id: str, db: Session = Depends(get_db)) -> InvestigationDetailResponse:
    """Retrieves complete investigation case dossier."""
    inv = db.query(Investigation).filter(Investigation.id == investigation_id).first()
    if not inv:
        raise HTTPException(status_code=404, detail=f"Investigation '{investigation_id}' not found.")

    return InvestigationDetailResponse(
        id=inv.id,
        title=inv.title,
        status=inv.status,
        risk_score=inv.risk_score,
        severity=inv.severity,
        explanation=inv.explanation,
        recommendations=inv.recommendations_json or [],
        created_at=inv.created_at,
        analyses=[AnalysisResponse.model_validate(a) for a in inv.analyses],
        detections=[DetectionResponse.model_validate(d) for d in inv.detections],
        iocs=[IOCResponse.model_validate(i) for i in inv.iocs],
        correlations=[CorrelationResponse.model_validate(c) for c in inv.correlations],
        timeline=[TimelineEventResponse.model_validate(t) for t in inv.timeline_events],
    )


@router.get("/reports/{investigation_id}/json")
def get_json_report(investigation_id: str, db: Session = Depends(get_db)):
    """Exports or downloads a standardized JSON forensic report."""
    try:
        report_data = generate_json_report(db, investigation_id)
        return JSONResponse(content=report_data)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))


@router.get("/reports/{investigation_id}/html", response_class=HTMLResponse)
def get_html_report(investigation_id: str, db: Session = Depends(get_db)):
    """Renders or downloads a standalone dark SOC HTML forensic dossier."""
    try:
        filepath = generate_html_report(db, investigation_id)
        with open(filepath, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))


@router.get("/samples")
def list_samples() -> Dict[str, Any]:
    """Lists preloaded synthetic verification captures and URLs."""
    pcap_samples = []
    url_samples = []

    if SAMPLES_DIR.exists():
        for p in SAMPLES_DIR.iterdir():
            if p.suffix.lower() in ALLOWED_PCAP_EXTENSIONS:
                pcap_samples.append({
                    "filename": p.name,
                    "size_bytes": p.stat().st_size,
                    "path": str(p),
                })
            elif p.suffix.lower() == ".txt" and "url" in p.name.lower():
                with open(p, "r", encoding="utf-8") as f:
                    urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                url_samples.append({
                    "filename": p.name,
                    "count": len(urls),
                    "urls": urls[:20],
                })

    return {
        "pcap_samples": pcap_samples,
        "url_samples": url_samples,
    }
