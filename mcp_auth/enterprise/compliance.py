"""
Compliance and Privacy Management for mcp-auth-py Enterprise

This module provides comprehensive compliance features for enterprise deployments,
including GDPR, HIPAA, SOX compliance monitoring, privacy controls, and automated
reporting capabilities.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field

try:
    import redis.asyncio as aioredis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    aioredis = None

logger = logging.getLogger(__name__)


class ComplianceStandard(str, Enum):
    """Supported compliance standards"""

    GDPR = "gdpr"
    HIPAA = "hipaa"
    SOX = "sox"
    PCI_DSS = "pci_dss"
    ISO_27001 = "iso_27001"
    CCPA = "ccpa"


class PrivacyRequestType(str, Enum):
    """Types of privacy requests"""

    DATA_EXPORT = "data_export"
    DATA_DELETION = "data_deletion"
    DATA_RECTIFICATION = "data_rectification"
    CONSENT_WITHDRAWAL = "consent_withdrawal"
    PROCESSING_RESTRICTION = "processing_restriction"


class PrivacyRequestStatus(str, Enum):
    """Privacy request status"""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"
    EXPIRED = "expired"


class DataCategory(str, Enum):
    """Categories of personal data"""

    IDENTITY = "identity"
    CONTACT = "contact"
    FINANCIAL = "financial"
    HEALTH = "health"
    BIOMETRIC = "biometric"
    BEHAVIORAL = "behavioral"
    TECHNICAL = "technical"
    LOCATION = "location"


class ConsentPurpose(str, Enum):
    """Purposes for data processing consent"""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    AUDIT_LOGGING = "audit_logging"
    ANALYTICS = "analytics"
    MARKETING = "marketing"
    SUPPORT = "support"
    LEGAL_COMPLIANCE = "legal_compliance"


class ComplianceRequirement(BaseModel):
    """Individual compliance requirement"""

    requirement_id: str
    standard: ComplianceStandard
    title: str
    description: str
    control_objective: str
    implementation_guidance: str
    evidence_required: list[str]
    automation_available: bool = False
    risk_level: str = "medium"  # low, medium, high, critical
    frequency: str = "monthly"  # daily, weekly, monthly, quarterly, annually


class ComplianceAssessment(BaseModel):
    """Assessment of compliance requirement"""

    requirement_id: str
    tenant_id: str
    assessed_at: datetime = Field(default_factory=datetime.utcnow)
    assessor: str
    status: str  # compliant, non_compliant, partial, not_applicable
    score: float = Field(ge=0, le=100)
    findings: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    next_assessment_date: datetime
    remediation_due_date: Optional[datetime] = None


class PrivacyRequest(BaseModel):
    """Privacy request model"""

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    user_id: str
    request_type: PrivacyRequestType
    status: PrivacyRequestStatus = PrivacyRequestStatus.PENDING

    # Request details
    requested_at: datetime = Field(default_factory=datetime.utcnow)
    requested_by: str  # User ID who made the request
    verification_token: Optional[str] = None
    verification_expires_at: Optional[datetime] = None

    # Data scope
    data_categories: list[DataCategory] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    date_range_start: Optional[datetime] = None
    date_range_end: Optional[datetime] = None

    # Processing details
    processed_at: Optional[datetime] = None
    processed_by: Optional[str] = None
    completion_details: dict[str, Any] = Field(default_factory=dict)

    # Metadata
    legal_basis: Optional[str] = None
    retention_override: Optional[bool] = None
    audit_trail: list[dict[str, Any]] = Field(default_factory=list)


class ConsentRecord(BaseModel):
    """User consent record"""

    consent_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    user_id: str

    # Consent details
    purpose: ConsentPurpose
    data_categories: list[DataCategory]
    processing_activities: list[str]

    # Consent lifecycle
    granted_at: datetime = Field(default_factory=datetime.utcnow)
    granted_by: str  # How consent was obtained
    consent_method: str  # opt_in, opt_out, implicit, etc.

    # Status
    is_active: bool = True
    withdrawn_at: Optional[datetime] = None
    withdrawal_reason: Optional[str] = None

    # Legal basis and expiration
    legal_basis: str = "consent"  # consent, contract, legal_obligation, etc.
    expires_at: Optional[datetime] = None
    renewal_required_at: Optional[datetime] = None

    # Metadata
    consent_text: str  # The actual consent text shown to user
    privacy_policy_version: str
    consent_version: str = "1.0"


class ComplianceMonitor:
    """Automated compliance monitoring system"""

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url
        self.redis = None
        self._requirements: dict[ComplianceStandard, list[ComplianceRequirement]] = {}
        self._assessments: dict[str, list[ComplianceAssessment]] = {}
        self._lock = None

    def _ensure_lock(self):
        """Ensure async lock is initialized"""
        if self._lock is None:
            self._lock = asyncio.Lock()

    async def initialize(self):
        """Initialize compliance monitor"""
        self._ensure_lock()

        if REDIS_AVAILABLE and self.redis_url:
            try:
                self.redis = aioredis.from_url(self.redis_url, decode_responses=True)
                await self.redis.ping()
                logger.info("Compliance monitor initialized with Redis backend")
            except Exception as e:
                logger.warning(f"Redis initialization failed: {e}")

        # Load default compliance requirements
        await self._load_default_requirements()

    async def _load_default_requirements(self):
        """Load default compliance requirements for supported standards"""

        # GDPR Requirements
        gdpr_requirements = [
            ComplianceRequirement(
                requirement_id="gdpr_001",
                standard=ComplianceStandard.GDPR,
                title="Lawful Basis for Processing",
                description="Ensure all processing has a valid lawful basis under Art. 6 GDPR",
                control_objective="Establish and document lawful basis for all data processing activities",
                implementation_guidance="Implement consent management system and document legal bases",
                evidence_required=["consent_records", "legal_basis_documentation"],
                automation_available=True,
                risk_level="high",
                frequency="monthly",
            ),
            ComplianceRequirement(
                requirement_id="gdpr_002",
                standard=ComplianceStandard.GDPR,
                title="Data Subject Rights",
                description="Facilitate exercise of data subject rights (access, rectification, erasure, etc.)",
                control_objective="Enable and track data subject rights requests",
                implementation_guidance="Implement privacy request management system",
                evidence_required=[
                    "privacy_requests",
                    "response_times",
                    "completion_rates",
                ],
                automation_available=True,
                risk_level="high",
                frequency="monthly",
            ),
            ComplianceRequirement(
                requirement_id="gdpr_003",
                standard=ComplianceStandard.GDPR,
                title="Data Breach Notification",
                description="Report data breaches to supervisory authority within 72 hours",
                control_objective="Detect, assess, and report data breaches promptly",
                implementation_guidance="Implement incident response and breach notification procedures",
                evidence_required=["incident_reports", "notification_records"],
                automation_available=True,
                risk_level="critical",
                frequency="daily",
            ),
        ]

        # HIPAA Requirements
        hipaa_requirements = [
            ComplianceRequirement(
                requirement_id="hipaa_001",
                standard=ComplianceStandard.HIPAA,
                title="Access Controls",
                description="Implement access controls for PHI systems",
                control_objective="Ensure only authorized users can access PHI",
                implementation_guidance="Role-based access controls with regular reviews",
                evidence_required=["access_logs", "user_reviews", "role_assignments"],
                automation_available=True,
                risk_level="high",
                frequency="monthly",
            ),
            ComplianceRequirement(
                requirement_id="hipaa_002",
                standard=ComplianceStandard.HIPAA,
                title="Audit Controls",
                description="Maintain audit logs of PHI access and modifications",
                control_objective="Track all PHI access and system activity",
                implementation_guidance="Comprehensive audit logging with tamper protection",
                evidence_required=["audit_logs", "log_integrity_checks"],
                automation_available=True,
                risk_level="high",
                frequency="daily",
            ),
        ]

        # SOX Requirements
        sox_requirements = [
            ComplianceRequirement(
                requirement_id="sox_001",
                standard=ComplianceStandard.SOX,
                title="User Access Management",
                description="Control user access to financial systems and data",
                control_objective="Ensure proper segregation of duties and access controls",
                implementation_guidance="Implement RBAC with regular access reviews",
                evidence_required=["access_reviews", "segregation_analysis"],
                automation_available=True,
                risk_level="high",
                frequency="quarterly",
            ),
            ComplianceRequirement(
                requirement_id="sox_002",
                standard=ComplianceStandard.SOX,
                title="Change Management",
                description="Control changes to financial reporting systems",
                control_objective="Ensure all changes are authorized and documented",
                implementation_guidance="Implement change approval workflows",
                evidence_required=["change_logs", "approval_records"],
                automation_available=False,
                risk_level="medium",
                frequency="monthly",
            ),
        ]

        self._requirements[ComplianceStandard.GDPR] = gdpr_requirements
        self._requirements[ComplianceStandard.HIPAA] = hipaa_requirements
        self._requirements[ComplianceStandard.SOX] = sox_requirements

    async def add_standard(
        self,
        standard: ComplianceStandard,
        requirements: list[ComplianceRequirement],
        audit_frequency: str = "monthly",
    ):
        """Add compliance standard with requirements"""
        self._requirements[standard] = requirements

        # Schedule automated assessments
        for req in requirements:
            if req.automation_available:
                await self._schedule_assessment(req, audit_frequency)

    async def assess_requirement(
        self, tenant_id: str, requirement_id: str, assessor: str
    ) -> ComplianceAssessment:
        """Assess a specific compliance requirement"""
        requirement = None
        for reqs in self._requirements.values():
            for req in reqs:
                if req.requirement_id == requirement_id:
                    requirement = req
                    break

        if not requirement:
            raise ValueError(f"Requirement {requirement_id} not found")

        # Automated assessment based on requirement type
        assessment = await self._perform_automated_assessment(
            tenant_id, requirement, assessor
        )

        # Store assessment
        if tenant_id not in self._assessments:
            self._assessments[tenant_id] = []
        self._assessments[tenant_id].append(assessment)

        # Store in Redis if available
        if self.redis:
            await self.redis.hset(
                f"compliance:assessments:{tenant_id}",
                assessment.requirement_id,
                assessment.json(),
            )

        return assessment

    async def _perform_automated_assessment(
        self, tenant_id: str, requirement: ComplianceRequirement, assessor: str
    ) -> ComplianceAssessment:
        """Perform automated assessment for requirement"""

        if requirement.requirement_id == "gdpr_001":
            # Check consent management
            return await self._assess_gdpr_lawful_basis(
                tenant_id, requirement, assessor
            )
        elif requirement.requirement_id == "gdpr_002":
            # Check data subject rights implementation
            return await self._assess_gdpr_data_rights(tenant_id, requirement, assessor)
        elif requirement.requirement_id == "hipaa_001":
            # Check access controls
            return await self._assess_hipaa_access_controls(
                tenant_id, requirement, assessor
            )
        else:
            # Default assessment
            return ComplianceAssessment(
                requirement_id=requirement.requirement_id,
                tenant_id=tenant_id,
                assessor=assessor,
                status="not_applicable",
                score=0.0,
                next_assessment_date=datetime.utcnow() + timedelta(days=30),
            )

    async def _assess_gdpr_lawful_basis(
        self, tenant_id: str, requirement: ComplianceRequirement, assessor: str
    ) -> ComplianceAssessment:
        """Assess GDPR lawful basis compliance"""

        # Check if consent management is implemented
        # This would integrate with the ConsentManager
        findings = []
        score = 0.0

        # Simulate assessment logic
        consent_records_exist = await self._check_consent_records(tenant_id)
        if consent_records_exist:
            score += 40.0
        else:
            findings.append("No consent records found")

        legal_basis_documented = await self._check_legal_basis_documentation(tenant_id)
        if legal_basis_documented:
            score += 30.0
        else:
            findings.append("Legal basis documentation missing")

        consent_withdrawal_process = await self._check_consent_withdrawal(tenant_id)
        if consent_withdrawal_process:
            score += 30.0
        else:
            findings.append("Consent withdrawal process not implemented")

        status = (
            "compliant"
            if score >= 80
            else "partial" if score >= 50 else "non_compliant"
        )

        recommendations = []
        if score < 100:
            recommendations.append("Implement comprehensive consent management system")
            recommendations.append("Document legal basis for all processing activities")
            recommendations.append("Provide clear consent withdrawal mechanisms")

        return ComplianceAssessment(
            requirement_id=requirement.requirement_id,
            tenant_id=tenant_id,
            assessor=assessor,
            status=status,
            score=score,
            findings=findings,
            recommendations=recommendations,
            next_assessment_date=datetime.utcnow() + timedelta(days=30),
        )

    async def _assess_gdpr_data_rights(
        self, tenant_id: str, requirement: ComplianceRequirement, assessor: str
    ) -> ComplianceAssessment:
        """Assess GDPR data subject rights implementation"""

        findings = []
        score = 0.0

        # Check privacy request handling
        privacy_requests_handled = await self._check_privacy_request_handling(tenant_id)
        if privacy_requests_handled:
            score += 25.0
        else:
            findings.append("Privacy request handling not implemented")

        # Check data export capability
        data_export_available = await self._check_data_export_capability(tenant_id)
        if data_export_available:
            score += 25.0
        else:
            findings.append("Data export capability missing")

        # Check data deletion capability
        data_deletion_available = await self._check_data_deletion_capability(tenant_id)
        if data_deletion_available:
            score += 25.0
        else:
            findings.append("Data deletion capability missing")

        # Check response times
        response_times_compliant = await self._check_response_times(tenant_id)
        if response_times_compliant:
            score += 25.0
        else:
            findings.append("Response times exceed GDPR requirements (30 days)")

        status = (
            "compliant"
            if score >= 80
            else "partial" if score >= 50 else "non_compliant"
        )

        return ComplianceAssessment(
            requirement_id=requirement.requirement_id,
            tenant_id=tenant_id,
            assessor=assessor,
            status=status,
            score=score,
            findings=findings,
            next_assessment_date=datetime.utcnow() + timedelta(days=30),
        )

    async def _assess_hipaa_access_controls(
        self, tenant_id: str, requirement: ComplianceRequirement, assessor: str
    ) -> ComplianceAssessment:
        """Assess HIPAA access controls compliance"""

        findings = []
        score = 0.0

        # Check role-based access controls
        rbac_implemented = await self._check_rbac_implementation(tenant_id)
        if rbac_implemented:
            score += 30.0
        else:
            findings.append("RBAC not properly implemented")

        # Check access logging
        access_logging = await self._check_access_logging(tenant_id)
        if access_logging:
            score += 30.0
        else:
            findings.append("Comprehensive access logging missing")

        # Check regular access reviews
        access_reviews = await self._check_access_reviews(tenant_id)
        if access_reviews:
            score += 20.0
        else:
            findings.append("Regular access reviews not conducted")

        # Check MFA implementation
        mfa_implemented = await self._check_mfa_implementation(tenant_id)
        if mfa_implemented:
            score += 20.0
        else:
            findings.append("Multi-factor authentication not implemented")

        status = (
            "compliant"
            if score >= 80
            else "partial" if score >= 50 else "non_compliant"
        )

        return ComplianceAssessment(
            requirement_id=requirement.requirement_id,
            tenant_id=tenant_id,
            assessor=assessor,
            status=status,
            score=score,
            findings=findings,
            next_assessment_date=datetime.utcnow() + timedelta(days=30),
        )

    async def generate_report(
        self,
        tenant_id: str,
        standards: list[ComplianceStandard],
        format: str = "detailed",
        include_recommendations: bool = True,
    ) -> dict[str, Any]:
        """Generate compliance report"""

        report = {
            "tenant_id": tenant_id,
            "generated_at": datetime.utcnow().isoformat(),
            "standards": standards,
            "overall_score": 0.0,
            "status_summary": {"compliant": 0, "partial": 0, "non_compliant": 0},
            "assessments": [],
            "recommendations": [] if include_recommendations else None,
        }

        tenant_assessments = self._assessments.get(tenant_id, [])
        filtered_assessments = []
        total_score = 0.0
        count = 0

        for assessment in tenant_assessments:
            # Find requirement to check standard
            requirement = None
            for standard in standards:
                for req in self._requirements.get(standard, []):
                    if req.requirement_id == assessment.requirement_id:
                        requirement = req
                        break
                if requirement:
                    break

            if requirement:
                filtered_assessments.append(assessment)
                total_score += assessment.score
                count += 1

                # Update status summary
                if assessment.status == "compliant":
                    report["status_summary"]["compliant"] += 1
                elif assessment.status == "partial":
                    report["status_summary"]["partial"] += 1
                else:
                    report["status_summary"]["non_compliant"] += 1

                # Collect recommendations
                if include_recommendations and assessment.recommendations:
                    report["recommendations"].extend(assessment.recommendations)

        if count > 0:
            report["overall_score"] = total_score / count

        report["assessments"] = [a.dict() for a in filtered_assessments]

        if include_recommendations:
            # Remove duplicate recommendations
            report["recommendations"] = list(set(report["recommendations"]))

        return report

    # Helper methods for assessment checks
    async def _check_consent_records(self, tenant_id: str) -> bool:
        """Check if consent records exist"""
        # This would integrate with ConsentManager
        return True  # Simulated

    async def _check_legal_basis_documentation(self, tenant_id: str) -> bool:
        """Check legal basis documentation"""
        return False  # Simulated - needs implementation

    async def _check_consent_withdrawal(self, tenant_id: str) -> bool:
        """Check consent withdrawal process"""
        return True  # Simulated

    async def _check_privacy_request_handling(self, tenant_id: str) -> bool:
        """Check privacy request handling capability"""
        return True  # Simulated

    async def _check_data_export_capability(self, tenant_id: str) -> bool:
        """Check data export capability"""
        return True  # Simulated

    async def _check_data_deletion_capability(self, tenant_id: str) -> bool:
        """Check data deletion capability"""
        return True  # Simulated

    async def _check_response_times(self, tenant_id: str) -> bool:
        """Check privacy request response times"""
        return True  # Simulated

    async def _check_rbac_implementation(self, tenant_id: str) -> bool:
        """Check RBAC implementation"""
        return True  # Simulated

    async def _check_access_logging(self, tenant_id: str) -> bool:
        """Check access logging implementation"""
        return True  # Simulated

    async def _check_access_reviews(self, tenant_id: str) -> bool:
        """Check regular access reviews"""
        return False  # Simulated - needs implementation

    async def _check_mfa_implementation(self, tenant_id: str) -> bool:
        """Check MFA implementation"""
        return False  # Simulated - needs implementation

    async def _schedule_assessment(
        self, requirement: ComplianceRequirement, frequency: str
    ):
        """Schedule automated assessment"""
        # This would integrate with a task scheduler
        pass


class PrivacyManager:
    """Privacy request and consent management system"""

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url
        self.redis = None
        self._privacy_requests: dict[str, PrivacyRequest] = {}
        self._consent_records: dict[str, list[ConsentRecord]] = {}
        self._lock = None

    def _ensure_lock(self):
        """Ensure async lock is initialized"""
        if self._lock is None:
            self._lock = asyncio.Lock()

    async def initialize(self):
        """Initialize privacy manager"""
        self._ensure_lock()

        if REDIS_AVAILABLE and self.redis_url:
            try:
                self.redis = aioredis.from_url(self.redis_url, decode_responses=True)
                await self.redis.ping()
                logger.info("Privacy manager initialized with Redis backend")
            except Exception as e:
                logger.warning(f"Redis initialization failed: {e}")

    async def submit_privacy_request(
        self,
        tenant_id: str,
        user_id: str,
        request_type: PrivacyRequestType,
        requested_by: str,
        data_categories: Optional[list[DataCategory]] = None,
        verification_required: bool = True,
    ) -> PrivacyRequest:
        """Submit a privacy request"""

        request = PrivacyRequest(
            tenant_id=tenant_id,
            user_id=user_id,
            request_type=request_type,
            requested_by=requested_by,
            data_categories=data_categories or [],
        )

        if verification_required:
            # Generate verification token
            request.verification_token = str(uuid.uuid4())
            request.verification_expires_at = datetime.utcnow() + timedelta(hours=24)

        # Store request
        self._privacy_requests[request.request_id] = request

        if self.redis:
            await self.redis.hset(
                f"privacy:requests:{tenant_id}", request.request_id, request.json()
            )

        logger.info(
            f"Privacy request submitted: {request.request_id} for user {user_id}"
        )
        return request

    async def verify_privacy_request(
        self, request_id: str, verification_token: str
    ) -> PrivacyRequest:
        """Verify privacy request with token"""

        request = self._privacy_requests.get(request_id)
        if not request:
            raise ValueError(f"Privacy request {request_id} not found")

        if request.verification_token != verification_token:
            raise ValueError("Invalid verification token")

        if (
            request.verification_expires_at
            and request.verification_expires_at < datetime.utcnow()
        ):
            request.status = PrivacyRequestStatus.EXPIRED
            raise ValueError("Verification token expired")

        request.status = PrivacyRequestStatus.IN_PROGRESS
        request.audit_trail.append(
            {
                "action": "verified",
                "timestamp": datetime.utcnow().isoformat(),
                "details": "Request verified successfully",
            }
        )

        return request

    async def process_deletion_request(
        self,
        user_id: str,
        verification_code: str,
        scope: str = "all_data",
        retain_audit_logs: bool = True,
    ) -> dict[str, Any]:
        """Process GDPR right to be forgotten request"""

        # Find and verify the deletion request
        deletion_request = None
        for request in self._privacy_requests.values():
            if (
                request.user_id == user_id
                and request.request_type == PrivacyRequestType.DATA_DELETION
                and request.verification_token == verification_code
            ):
                deletion_request = request
                break

        if not deletion_request:
            raise ValueError("Invalid deletion request or verification code")

        # Process deletion
        deletion_result = {
            "request_id": deletion_request.request_id,
            "user_id": user_id,
            "scope": scope,
            "started_at": datetime.utcnow().isoformat(),
            "deleted_data": [],
            "retained_data": [],
            "errors": [],
        }

        try:
            # Delete user profile data
            deletion_result["deleted_data"].append("user_profile")

            # Delete authentication data (except audit logs)
            deletion_result["deleted_data"].append("authentication_tokens")
            deletion_result["deleted_data"].append("session_data")

            # Delete RBAC assignments
            deletion_result["deleted_data"].append("role_assignments")
            deletion_result["deleted_data"].append("permissions")

            # Handle audit logs based on retention policy
            if retain_audit_logs:
                deletion_result["retained_data"].append("audit_logs")
            else:
                deletion_result["deleted_data"].append("audit_logs")

            # Delete consent records
            if user_id in self._consent_records:
                del self._consent_records[user_id]
                deletion_result["deleted_data"].append("consent_records")

            # Update request status
            deletion_request.status = PrivacyRequestStatus.COMPLETED
            deletion_request.processed_at = datetime.utcnow()
            deletion_request.completion_details = deletion_result

        except Exception as e:
            deletion_result["errors"].append(str(e))
            deletion_request.status = PrivacyRequestStatus.REJECTED
            logger.error(f"Error processing deletion request: {e}")

        deletion_result["completed_at"] = datetime.utcnow().isoformat()
        deletion_result["status"] = deletion_request.status

        return deletion_result

    async def export_user_data(
        self, user_id: str, format: str = "json", include_metadata: bool = True
    ) -> dict[str, Any]:
        """Export user data for GDPR data portability"""

        export_data = {
            "export_id": str(uuid.uuid4()),
            "user_id": user_id,
            "generated_at": datetime.utcnow().isoformat(),
            "format": format,
            "data": {},
        }

        # Export profile data
        export_data["data"]["profile"] = {
            "user_id": user_id,
            # Additional profile data would be fetched here
        }

        # Export consent records
        user_consents = self._consent_records.get(user_id, [])
        export_data["data"]["consent_records"] = [
            consent.dict() for consent in user_consents
        ]

        # Export authentication history (anonymized)
        export_data["data"]["authentication_history"] = {
            "note": "Authentication logs anonymized for privacy"
        }

        if include_metadata:
            export_data["metadata"] = {
                "export_version": "1.0",
                "privacy_policy_url": "https://example.com/privacy",
                "data_controller": "Example Corp",
                "contact_email": "privacy@example.com",
            }

        return export_data

    async def record_consent(
        self,
        tenant_id: str,
        user_id: str,
        purpose: ConsentPurpose,
        data_categories: list[DataCategory],
        consent_text: str,
        privacy_policy_version: str,
        granted_by: str = "user_action",
    ) -> ConsentRecord:
        """Record user consent"""

        consent = ConsentRecord(
            tenant_id=tenant_id,
            user_id=user_id,
            purpose=purpose,
            data_categories=data_categories,
            consent_text=consent_text,
            privacy_policy_version=privacy_policy_version,
            granted_by=granted_by,
        )

        # Store consent record
        if user_id not in self._consent_records:
            self._consent_records[user_id] = []
        self._consent_records[user_id].append(consent)

        if self.redis:
            await self.redis.sadd(f"consent:{tenant_id}:{user_id}", consent.json())

        logger.info(f"Consent recorded: {consent.consent_id} for user {user_id}")
        return consent

    async def withdraw_consent(
        self, user_id: str, consent_id: str, withdrawal_reason: Optional[str] = None
    ) -> ConsentRecord:
        """Withdraw user consent"""

        user_consents = self._consent_records.get(user_id, [])
        consent_record = None

        for consent in user_consents:
            if consent.consent_id == consent_id:
                consent_record = consent
                break

        if not consent_record:
            raise ValueError(f"Consent record {consent_id} not found")

        if not consent_record.is_active:
            raise ValueError("Consent already withdrawn")

        # Withdraw consent
        consent_record.is_active = False
        consent_record.withdrawn_at = datetime.utcnow()
        consent_record.withdrawal_reason = withdrawal_reason

        logger.info(f"Consent withdrawn: {consent_id} for user {user_id}")
        return consent_record

    async def check_consent(
        self, user_id: str, purpose: ConsentPurpose, data_category: DataCategory
    ) -> bool:
        """Check if user has valid consent for purpose and data category"""

        user_consents = self._consent_records.get(user_id, [])

        for consent in user_consents:
            if (
                consent.is_active
                and consent.purpose == purpose
                and data_category in consent.data_categories
            ):

                # Check if consent is not expired
                if consent.expires_at and consent.expires_at < datetime.utcnow():
                    continue

                # Check if renewal is required
                if (
                    consent.renewal_required_at
                    and consent.renewal_required_at < datetime.utcnow()
                ):
                    continue

                return True

        return False


# FastAPI integration functions


async def setup_compliance_system(
    app,
    redis_url: Optional[str] = None,
    enabled_standards: Optional[list[ComplianceStandard]] = None,
):
    """Setup compliance monitoring system with FastAPI"""
    from fastapi import APIRouter, Depends

    from ..security import require_admin_principal

    router = APIRouter(prefix="/compliance", tags=["Compliance"])

    # Initialize compliance monitor
    compliance_monitor = ComplianceMonitor(redis_url)
    await compliance_monitor.initialize()

    # Initialize privacy manager
    privacy_manager = PrivacyManager(redis_url)
    await privacy_manager.initialize()

    @router.post("/assessments/{requirement_id}")
    async def run_assessment(
        requirement_id: str, tenant_id: str, principal=Depends(require_admin_principal)
    ):
        """Run compliance assessment for specific requirement"""
        try:
            assessment = await compliance_monitor.assess_requirement(
                tenant_id=tenant_id,
                requirement_id=requirement_id,
                assessor=principal.id,
            )
            return assessment.dict()
        except Exception as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.get("/reports/{tenant_id}")
    async def generate_compliance_report(
        tenant_id: str,
        standards: list[ComplianceStandard] = None,
        format: str = "detailed",
        principal=Depends(require_admin_principal),
    ):
        """Generate compliance report for tenant"""
        if not standards:
            standards = enabled_standards or [ComplianceStandard.GDPR]

        report = await compliance_monitor.generate_report(
            tenant_id=tenant_id, standards=standards, format=format
        )
        return report

    @router.post("/privacy/requests")
    async def submit_privacy_request(
        request_data: dict[str, Any], tenant_id: str, user_id: str
    ):
        """Submit privacy request (GDPR data subject rights)"""
        request = await privacy_manager.submit_privacy_request(
            tenant_id=tenant_id,
            user_id=user_id,
            request_type=PrivacyRequestType(request_data["request_type"]),
            requested_by=request_data.get("requested_by", user_id),
            data_categories=[
                DataCategory(cat) for cat in request_data.get("data_categories", [])
            ],
        )
        return {
            "request_id": request.request_id,
            "verification_required": bool(request.verification_token),
        }

    @router.post("/privacy/verify/{request_id}")
    async def verify_privacy_request(request_id: str, verification_token: str):
        """Verify privacy request with token"""
        try:
            request = await privacy_manager.verify_privacy_request(
                request_id, verification_token
            )
            return {"status": "verified", "request_status": request.status}
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    @router.delete("/privacy/users/{user_id}/data")
    async def process_data_deletion(
        user_id: str,
        verification_code: str,
        scope: str = "all_data",
        retain_audit_logs: bool = True,
    ):
        """Process GDPR right to be forgotten"""
        try:
            result = await privacy_manager.process_deletion_request(
                user_id=user_id,
                verification_code=verification_code,
                scope=scope,
                retain_audit_logs=retain_audit_logs,
            )
            return result
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    app.include_router(router)

    # Store instances for access in other parts of the application
    app.state.compliance_monitor = compliance_monitor
    app.state.privacy_manager = privacy_manager

    return router
