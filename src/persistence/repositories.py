"""
UniShield AI -- Persistence Repositories
========================================
Handles CRUD operations and object mapping between 
Domain Objects (DetectionResult, Incident) and SQLAlchemy ORMs.
"""

from typing import List, Optional
import datetime
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from src.persistence.models import IncidentModel, AlertModel, EvidenceModel, IncidentAlertModel
from src.detectors.base import DetectionResult, Evidence, Severity, ThreatClass
from src.correlation.correlation_models import Incident
from src.utils.logging import get_logger

logger = get_logger(__name__)

class AlertRepository:
    def __init__(self, db: Session):
        self.db = db

    def _to_domain(self, model: AlertModel) -> DetectionResult:
        evidences = []
        for ev in model.evidence:
            try:
                obs = float(ev.observed) if ev.observed and ev.observed.replace('.','',1).isdigit() else ev.observed
                base = float(ev.baseline) if ev.baseline and ev.baseline.replace('.','',1).isdigit() else ev.baseline
            except Exception:
                obs = ev.observed
                base = ev.baseline
                
            evidences.append(Evidence(
                feature=ev.feature,
                observed=obs,
                baseline=base,
                deviation=ev.deviation,
                score=ev.score,
                detector=ev.detector,
                reason=ev.reason
            ))

        return DetectionResult(
            result_id=model.id,
            timestamp=model.timestamp.isoformat() if model.timestamp else "",
            threat_class=ThreatClass(model.threat_class),
            sub_type=model.sub_type,
            detection_score=model.detection_score,
            confidence=model.confidence,
            severity=Severity(model.severity),
            detector=model.detector,
            model=model.model,
            model_version=model.model_version,
            ml_available=model.ml_available,
            processing_latency=model.processing_latency,
            evidence=evidences,
            source_ip=model.source_ip,
            destination_ip=model.destination_ip,
            source_port=model.source_port,
            destination_port=model.destination_port,
            protocol=model.protocol,
            flow_id=model.flow_id,
            is_suppressed=model.is_suppressed,
            suppression_reason=model.suppression_reason,
            meta=model.meta_data
        )

    def save(self, alert: DetectionResult) -> AlertModel:
        import time
        from src.utils.prometheus_metrics import DATABASE_OPERATIONS_TOTAL, DATABASE_ERRORS_TOTAL, DATABASE_LATENCY_SECONDS
        
        t0 = time.time()
        try:
            db_alert = self.db.query(AlertModel).filter(AlertModel.id == alert.result_id).first()
            if not db_alert:
                db_alert = AlertModel(
                    id=alert.result_id,
                    timestamp=datetime.datetime.fromisoformat(alert.timestamp.replace("Z", "+00:00")),
                    threat_class=alert.threat_class.value,
                    sub_type=alert.sub_type,
                    detection_score=alert.detection_score,
                    confidence=alert.confidence,
                    severity=alert.severity.value if alert.severity else None,
                    detector=alert.detector,
                    model=alert.model,
                    model_version=alert.model_version,
                    ml_available=alert.ml_available,
                    processing_latency=alert.processing_latency,
                    source_ip=alert.source_ip,
                    destination_ip=alert.destination_ip,
                    source_port=alert.source_port,
                    destination_port=alert.destination_port,
                    protocol=alert.protocol,
                    flow_id=alert.flow_id,
                    correlation_id=getattr(alert, "correlation_id", None),
                    is_suppressed=alert.is_suppressed,
                    suppression_reason=alert.suppression_reason,
                    meta_data=alert.meta
                )
                for ev in alert.evidence:
                    db_ev = EvidenceModel(
                        feature=ev.feature,
                        observed=str(ev.observed),
                        baseline=str(ev.baseline) if ev.baseline is not None else None,
                        deviation=ev.deviation,
                        score=ev.score,
                        detector=ev.detector,
                        reason=ev.reason
                    )
                    db_alert.evidence.append(db_ev)
                self.db.add(db_alert)
                self.db.commit()
                self.db.refresh(db_alert)
                
            DATABASE_OPERATIONS_TOTAL.labels(operation="save_alert").inc()
            DATABASE_LATENCY_SECONDS.labels(operation="save_alert").observe(time.time() - t0)
            return db_alert
        except Exception as e:
            DATABASE_ERRORS_TOTAL.labels(operation="save_alert").inc()
            self.db.rollback()
            raise e

    def get_recent(
        self, 
        limit: int = 50,
        offset: int = 0,
        source_ip: Optional[str] = None, 
        severity: Optional[str] = None, 
        threat_class: Optional[str] = None
    ) -> List[DetectionResult]:
        query = self.db.query(AlertModel)
        
        if source_ip:
            query = query.filter(AlertModel.source_ip == source_ip)
        if severity:
            query = query.filter(AlertModel.severity == severity)
        if threat_class:
            query = query.filter(AlertModel.threat_class == threat_class)
            
        models = query.order_by(AlertModel.timestamp.desc()).offset(offset).limit(limit).all()
        return [self._to_domain(m) for m in models]

    def get_detector_stats(self) -> List[dict]:
        from sqlalchemy import cast, Integer
        """Aggregate alert metrics grouped by detector."""
        stats = self.db.query(
            AlertModel.detector,
            func.count(AlertModel.id).label("count"),
            func.avg(AlertModel.confidence).label("avg_confidence"),
            func.avg(AlertModel.processing_latency).label("avg_latency"),
            func.max(cast(AlertModel.ml_available, Integer)).label("uses_ml")
        ).group_by(AlertModel.detector).all()
        
        return [
            {
                "detector": s.detector,
                "count": s.count,
                "avg_confidence": float(s.avg_confidence) if s.avg_confidence else 0.0,
                "avg_latency": float(s.avg_latency) if s.avg_latency else 0.0,
                "uses_ml": bool(s.uses_ml)
            } for s in stats
        ]


class IncidentRepository:
    def __init__(self, db: Session, alert_repo: AlertRepository = None):
        self.db = db
        self.alert_repo = alert_repo or AlertRepository(db)

    def _to_domain(self, model: IncidentModel) -> Incident:
        inc = Incident(
            incident_id=model.id,
            status=model.status,
            first_seen=model.first_seen.isoformat() if model.first_seen else "",
            last_seen=model.last_seen.isoformat() if model.last_seen else "",
        )
        inc.risk_score = model.risk_score
        inc.risk_level = model.risk_level
        inc.sources = set(model.sources)
        inc.destinations = set(model.destinations)
        inc.detectors = set(model.detectors)
        inc.potential_progression = model.potential_progression
        
        # Load alerts
        alerts_domain = []
        for alert_model in model.alerts:
            alerts_domain.append(self.alert_repo._to_domain(alert_model))
            
        # Sort alerts by timestamp
        alerts_domain.sort(key=lambda x: x.timestamp)
        inc.alerts = alerts_domain
        
        return inc

    def save(self, incident: Incident) -> IncidentModel:
        import time
        from src.utils.prometheus_metrics import DATABASE_OPERATIONS_TOTAL, DATABASE_ERRORS_TOTAL, DATABASE_LATENCY_SECONDS
        
        t0 = time.time()
        try:
            db_inc = self.db.query(IncidentModel).filter(IncidentModel.id == incident.incident_id).first()
            
            first = datetime.datetime.fromisoformat(incident.first_seen.replace("Z", "+00:00")) if isinstance(incident.first_seen, str) else incident.first_seen
            last = datetime.datetime.fromisoformat(incident.last_seen.replace("Z", "+00:00")) if isinstance(incident.last_seen, str) else incident.last_seen

            if not db_inc:
                db_inc = IncidentModel(
                    id=incident.incident_id,
                    status=incident.status,
                    risk_score=incident.risk_score,
                    risk_level=incident.risk_level,
                    first_seen=first,
                    last_seen=last,
                    sources=list(incident.sources),
                    destinations=list(incident.destinations),
                    detectors=list(incident.detectors),
                    correlation_id=getattr(incident, "correlation_id", None),
                    potential_progression=incident.potential_progression
                )
                self.db.add(db_inc)
            else:
                db_inc.status = incident.status
                db_inc.risk_score = incident.risk_score
                db_inc.risk_level = incident.risk_level
                db_inc.last_seen = last
                db_inc.sources = list(incident.sources)
                db_inc.destinations = list(incident.destinations)
                db_inc.detectors = list(incident.detectors)
                db_inc.potential_progression = incident.potential_progression

            # Link alerts
            for alert in incident.alerts:
                db_alert = self.db.query(AlertModel).filter(AlertModel.id == alert.result_id).first()
                if not db_alert:
                    db_alert = self.alert_repo.save(alert)
                    
                # Create link if not exists
                link = self.db.query(IncidentAlertModel).filter_by(
                    incident_id=db_inc.id,
                    alert_id=db_alert.id
                ).first()
                
                if not link:
                    db_inc.alerts.append(db_alert)
                    
            self.db.commit()
            self.db.refresh(db_inc)
            
            DATABASE_OPERATIONS_TOTAL.labels(operation="save_incident").inc()
            DATABASE_LATENCY_SECONDS.labels(operation="save_incident").observe(time.time() - t0)
            return db_inc
        except Exception as e:
            DATABASE_ERRORS_TOTAL.labels(operation="save_incident").inc()
            self.db.rollback()
            raise e

    def get_active(self, source_ip: Optional[str] = None) -> List[Incident]:
        query = self.db.query(IncidentModel).filter(IncidentModel.status.in_(["NEW", "INVESTIGATING"]))
        models = query.all()
        
        domain_models = [self._to_domain(m) for m in models]
        
        if source_ip:
            # Filter in Python to avoid Postgres specific JSON array ANY() operators
            domain_models = [inc for inc in domain_models if source_ip in inc.sources]
            
        return domain_models
        
    def get_all(self, limit: int = 100, offset: int = 0) -> List[Incident]:
        models = self.db.query(IncidentModel).order_by(IncidentModel.last_seen.desc()).offset(offset).limit(limit).all()
        return [self._to_domain(m) for m in models]
        
    def get_by_id(self, incident_id: str) -> Optional[Incident]:
        m = self.db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
        if m:
            return self._to_domain(m)
        return None
