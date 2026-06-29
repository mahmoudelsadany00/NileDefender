import logging
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint, JSON, create_engine, func, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.exc import IntegrityError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
Base = declarative_base()


# ============================================================================
# DATABASE MODELS
# ============================================================================

class ScanHistory(Base):
    __tablename__ = 'scan_history'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String, nullable=False, index=True)  
    scan_date = Column(DateTime, default=func.now())
    scan_type = Column(String, default='full') 
    status = Column(String, default='running')  
    
    # Relationships
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Scan(id={self.id}, domain={self.domain}, status={self.status})>"


class Subdomain(Base):
    __tablename__ = 'subdomains'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scan_history.id'), nullable=False)
    subdomain = Column(String, nullable=False, index=True)
    is_alive = Column(Integer, default=0)  # 0=unknown, 1=alive, 2=dead
    status_code = Column(Integer)
    title = Column(String)
    
    __table_args__ = (
        UniqueConstraint('scan_id', 'subdomain', name='unique_subdomain_per_scan'),
    )
    
    scan = relationship("ScanHistory", back_populates="subdomains")
    
    def __repr__(self):
        return f"<Subdomain(subdomain={self.subdomain}, alive={self.is_alive})>"


class Endpoint(Base):
    __tablename__ = 'endpoints'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scan_history.id'), nullable=False)
    url = Column(Text, nullable=False)
    method = Column(String, nullable=False, default='GET')  # GET or POST
    parameters = Column(JSON)  # GET parameters
    body_params = Column(JSON)  # POST body parameters
    extra_headers = Column(JSON)  # Custom headers
    source = Column(String)  # 'form_crawler', 'url_parser', 'wayback', etc.
    has_parameters = Column(Integer, default=0)  # 0=no params, 1=has params
    
    # New fields for better vulnerability testing
    form_details = Column(JSON)  # Form metadata (enctype, id, class)
    param_types = Column(JSON)  # Parameter types (text, password, hidden, etc.)
    
    __table_args__ = (
        UniqueConstraint('scan_id', 'url', 'method', name='unique_endpoint_per_scan'),
    )
    
    scan = relationship("ScanHistory", back_populates="endpoints")
    
    def __repr__(self):
        return f"<Endpoint(method={self.method}, url={self.url[:50]})>"


class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scan_history.id'), nullable=False)
    vulnerability_type = Column(String, nullable=False, index=True)  # 'XSS', 'SQLi', etc.
    severity = Column(String, nullable=False, index=True)  # 'Critical', 'High', 'Medium', 'Low'
    url = Column(Text, nullable=False)
    method = Column(String, default='GET')  # HTTP method used
    parameter = Column(String)  # Vulnerable parameter name
    payload = Column(Text)  # Payload used
    evidence = Column(Text)  # Proof/evidence
    vulnerability_data = Column(Text)  # Full details (raw sqlmap log text)
    discovered_at = Column(DateTime, default=func.now())
    
    __table_args__ = (
        UniqueConstraint('scan_id', 'vulnerability_type', 'url', 'parameter', 
                        name='unique_vulnerability_per_scan'),
    )
    
    scan = relationship("ScanHistory", back_populates="vulnerabilities")
    
    def __repr__(self):
        return f"<Vulnerability(type={self.vulnerability_type}, severity={self.severity})>"


# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db(db_path='sqlite:///niledefender.db'):
    try:
        # Simple engine creation with thread-safe settings for SQLite
        if 'sqlite' in db_path:
            engine = create_engine(
                db_path, 
                echo=False,
                connect_args={'check_same_thread': False}
            )
        else:
            engine = create_engine(db_path, echo=False)
        
        Base.metadata.create_all(engine)
        logger.info(f"[DB] Database initialized: {db_path}")
        return engine
    except Exception as e:
        logger.error(f"[DB] Error initializing database: {e}")
        raise


def get_session(engine):
    Session = sessionmaker(bind=engine)
    return Session()


# ============================================================================
# SCAN MANAGEMENT
# ============================================================================

def create_scan(session, domain, scan_type='full'):
    try:
        new_scan = ScanHistory(domain=domain, scan_type=scan_type, status='running')
        session.add(new_scan)
        session.commit()
        logger.info(f"[DB] Created scan ID {new_scan.id} for {domain}")
        return new_scan.id
    except Exception as e:
        session.rollback()
        logger.error(f"[DB] Error creating scan: {e}")
        raise


def update_scan_status(session, scan_id, status):
    try:
        scan = session.query(ScanHistory).filter_by(id=scan_id).first()
        if scan:
            scan.status = status
            session.commit()
            logger.info(f"[DB] Scan {scan_id} status: {status}")
    except Exception as e:
        session.rollback()
        logger.error(f"[DB] Error updating status: {e}")


# ============================================================================
# SUBDOMAIN MANAGEMENT
# ============================================================================

def save_subdomain(session, scan_id, subdomain, is_alive=0, status_code=None, title=None):
    try:
        new_subdomain = Subdomain(
            scan_id=scan_id,
            subdomain=subdomain,
            is_alive=is_alive,
            status_code=status_code,
            title=title
        )
        session.add(new_subdomain)
        session.commit()
        
    except IntegrityError:
        session.rollback()
        # Update existing
        existing = session.query(Subdomain).filter_by(
            scan_id=scan_id, subdomain=subdomain
        ).first()
        if existing:
            existing.is_alive = is_alive
            existing.status_code = status_code
            existing.title = title
            session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"[DB] Error saving subdomain: {e}")


# ============================================================================
# ENDPOINT MANAGEMENT
# ============================================================================

def save_endpoint(session, scan_id, url, method='GET', parameters=None, 
                 body_params=None, extra_headers=None, source='crawler',
                 form_details=None, param_types=None):
    try:
        has_params = 1 if (parameters or body_params) else 0
        
        new_endpoint = Endpoint(
            scan_id=scan_id,
            url=url,
            method=method,
            parameters=parameters,
            body_params=body_params,
            extra_headers=extra_headers,
            source=source,
            has_parameters=has_params,
            form_details=form_details,
            param_types=param_types
        )
        session.add(new_endpoint)
        session.commit()
        
    except IntegrityError:
        session.rollback()
    except Exception as e:
        session.rollback()
        logger.error(f"[DB] Error saving endpoint: {e}")


# ============================================================================
# VULNERABILITY MANAGEMENT
# ============================================================================

def save_vulnerability(session, scan_id, vuln_type, severity, url, 
                      method='GET', parameter=None, payload=None, 
                      evidence=None, vuln_data=None):
    try:
        new_vuln = Vulnerability(
            scan_id=scan_id,
            vulnerability_type=vuln_type,
            severity=severity,
            url=url,
            method=method,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            vulnerability_data=vuln_data
        )
        session.add(new_vuln)
        session.commit()
        logger.info(f"[DB] Saved: {vuln_type} ({severity}) at {url[:100]}")
        
    except IntegrityError:
        session.rollback()
    except Exception as e:
        session.rollback()
        logger.error(f"[DB] Error saving vulnerability: {e}")


# ============================================================================
# QUERY FUNCTIONS
# ============================================================================

def get_scan_by_id(session, scan_id):
    return session.query(ScanHistory).filter_by(id=scan_id).first()


def get_all_scans(session):
    return session.query(ScanHistory).order_by(ScanHistory.scan_date.desc()).all()


def get_subdomains(session, scan_id, alive_only=False):
    query = session.query(Subdomain).filter_by(scan_id=scan_id)
    if alive_only:
        query = query.filter_by(is_alive=1)
    return query.all()


def get_endpoints(session, scan_id, with_params_only=False, method=None):
    query = session.query(Endpoint).filter_by(scan_id=scan_id)
    if with_params_only:
        query = query.filter_by(has_parameters=1)
    if method:
        query = query.filter_by(method=method)
    return query.all()


def get_vulnerabilities(session, scan_id, vuln_type=None, severity=None):
    query = session.query(Vulnerability).filter_by(scan_id=scan_id)
    if vuln_type:
        query = query.filter_by(vulnerability_type=vuln_type)
    if severity:
        query = query.filter_by(severity=severity)
    return query.all()


def get_vulnerability_stats(session, scan_id):
    vulns = get_vulnerabilities(session, scan_id)
    
    stats = {
        'total': len(vulns),
        'by_type': {},
        'by_severity': {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
    }
    
    for vuln in vulns:
        if vuln.vulnerability_type not in stats['by_type']:
            stats['by_type'][vuln.vulnerability_type] = 0
        stats['by_type'][vuln.vulnerability_type] += 1
        
        if vuln.severity in stats['by_severity']:
            stats['by_severity'][vuln.severity] += 1
    
    return stats


def get_scan_results(session, scan_id):
    scan = get_scan_by_id(session, scan_id)
    if not scan:
        return None
    
    subdomains = get_subdomains(session, scan.id)
    endpoints = get_endpoints(session, scan.id)
    vulnerabilities = get_vulnerabilities(session, scan.id)
    stats = get_vulnerability_stats(session, scan.id)
    
    return {
        'scan': {
            'id': scan.id,
            'domain': scan.domain,
            'scan_date': scan.scan_date.isoformat() if scan.scan_date else None,
            'scan_type': scan.scan_type,
            'status': scan.status
        },
        'subdomains': [
            {
                'subdomain': s.subdomain,
                'is_alive': s.is_alive,
                'status_code': s.status_code,
                'title': s.title
            }
            for s in subdomains
        ],
        'endpoints': [
            {
                'url': e.url,
                'method': e.method,
                'parameters': e.parameters,
                'body_params': e.body_params,
                'extra_headers': e.extra_headers,
                'source': e.source,
                'form_details': e.form_details,
                'param_types': e.param_types
            }
            for e in endpoints
        ],
        'vulnerabilities': [
            {
                'type': v.vulnerability_type,
                'severity': v.severity,
                'url': v.url,
                'method': v.method,
                'parameter': v.parameter,
                'payload': v.payload,
                'evidence': v.evidence,
                'discovered_at': v.discovered_at.isoformat() if v.discovered_at else None
            }
            for v in vulnerabilities
        ],
        'statistics': stats
    }


def delete_scan(session, scan_id):
    try:
        scan = get_scan_by_id(session, scan_id)
        if scan:
            session.delete(scan)
            session.commit()
            logger.info(f"[DB] Deleted scan {scan_id}")
            return True
        return False
    except Exception as e:
        session.rollback()
        logger.error(f"[DB] Error deleting scan: {e}")
        return False
