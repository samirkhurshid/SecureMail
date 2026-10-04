"""
FastAPI Router for Organization Management & Multi-Tenant Sandboxing
=====================================================================
Provides endpoints for enterprise team management, employee invitations,
role updates, and organization-sandboxed scan metrics.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Depends, Request, status

from app.auth import get_current_user, CurrentUser
from app.services import organization_service, audit_service
from app.services.rbac_service import has_permission, get_user_role, ROLE_ADMIN, ROLE_SOC_ANALYST
from app.utils.logger import setup_logger

logger = setup_logger(__name__)
router = APIRouter()


class InviteMemberRequest(BaseModel):
    email: str = Field(..., description="Employee corporate email address to invite")
    role: str = Field(default="user", description="Designated role (user, soc_analyst, auditor)")
    display_name: Optional[str] = Field(default="", description="Employee full name")


class UpdateRoleRequest(BaseModel):
    email: str = Field(..., description="Target employee email")
    role: str = Field(..., description="New role (user, soc_analyst, auditor, admin)")


class RemoveMemberRequest(BaseModel):
    email: str = Field(..., description="Target employee email to remove")


@router.get("/overview", summary="Get organization metadata, team roster, and sandbox telemetry")
async def get_org_overview(user: CurrentUser = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Returns organization profile, member list, and aggregated telemetry for the user's sandbox.
    """
    try:
        overview = organization_service.get_organization_overview(user.email, user.uid)
        return {
            "status": "success",
            "data": overview
        }
    except Exception as e:
        logger.error(f"Error fetching org overview for {user.email}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/invite", summary="Invite an employee to the organization with assigned role")
async def invite_employee(
    body: InviteMemberRequest,
    user: CurrentUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Invites a member to the organization sandbox. Restricted to Admin & SOC Analysts.
    """
    role = get_user_role(user.uid, user.email)
    if role not in (ROLE_ADMIN, ROLE_SOC_ANALYST):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Organization Administrators or SOC Analysts can invite members."
        )

    try:
        overview = organization_service.get_organization_overview(user.email, user.uid)
        org_id = overview.get("org_id", "org_parul_soc")
        res = organization_service.invite_member(
            org_id=org_id,
            email=str(body.email),
            role=body.role,
            invited_by_email=user.email,
            display_name=body.display_name or ""
        )

        audit_service.log_audit_event(
            event_type="ROLE_ASSIGN",
            user_id=user.uid,
            user_email=user.email,
            user_role=role,
            resource_id=str(body.email),
            details={"action": "MEMBER_INVITED", "org_id": org_id, "role": body.role}
        )
        return res
    except Exception as e:
        logger.error(f"Error inviting member {body.email}: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.patch("/members/role", summary="Update an organization member's role")
async def update_employee_role(
    body: UpdateRoleRequest,
    user: CurrentUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Updates an employee's role. Restricted to Organization Administrators.
    """
    role = get_user_role(user.uid, user.email)
    if role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Organization Administrators can modify member roles."
        )

    try:
        overview = organization_service.get_organization_overview(user.email, user.uid)
        org_id = overview.get("org_id", "org_parul_soc")
        res = organization_service.update_member_role(
            org_id=org_id,
            email=str(body.email),
            new_role=body.role,
            updated_by_email=user.email
        )

        audit_service.log_audit_event(
            event_type="ROLE_ASSIGN",
            user_id=user.uid,
            user_email=user.email,
            user_role=role,
            resource_id=str(body.email),
            details={"action": "ROLE_UPDATED", "org_id": org_id, "new_role": body.role}
        )
        return res
    except Exception as e:
        logger.error(f"Error updating member role {body.email}: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/members", summary="Remove an employee from the organization sandbox")
async def remove_employee(
    body: RemoveMemberRequest,
    user: CurrentUser = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Removes a member from the organization. Restricted to Organization Administrators.
    """
    role = get_user_role(user.uid, user.email)
    if role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Organization Administrators can remove members."
        )

    try:
        overview = organization_service.get_organization_overview(user.email, user.uid)
        org_id = overview.get("org_id", "org_parul_soc")
        res = organization_service.remove_member(
            org_id=org_id,
            email=str(body.email),
            removed_by_email=user.email
        )

        audit_service.log_audit_event(
            event_type="ROLE_ASSIGN",
            user_id=user.uid,
            user_email=user.email,
            user_role=role,
            resource_id=str(body.email),
            details={"action": "MEMBER_REMOVED", "org_id": org_id}
        )
        return res
    except Exception as e:
        logger.error(f"Error removing member {body.email}: {e}")
        raise HTTPException(status_code=400, detail=str(e))
