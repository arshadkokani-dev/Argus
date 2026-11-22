from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.plans import get_plan_limits
from app.db.session import get_db
from app.models.target import Target
from app.models.user import User
from app.schemas.target import TargetCreate, TargetResponse
from app.services.verifier import verify_domain_ownership


router = APIRouter(prefix="/api/v1/targets", tags=["Targets"])


@router.get("", response_model=list[TargetResponse])
def list_targets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return (
        db.query(Target)
        .filter(Target.user_id == current_user.id)
        .order_by(Target.created_at.desc())
        .all()
    )


@router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(
    payload: TargetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    limits = get_plan_limits(current_user.plan_tier)
    current_count = db.query(Target).filter(Target.user_id == current_user.id).count()
    if current_count >= limits["max_targets"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Your {current_user.plan_tier.value} plan allows up to {limits['max_targets']} website(s). Upgrade to add more.",
        )

    duplicate = (
        db.query(Target)
        .filter(Target.user_id == current_user.id, Target.domain == payload.domain)
        .first()
    )
    if duplicate:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You have already registered this domain.",
        )

    new_target = Target(
        user_id=current_user.id,
        domain=payload.domain,
        base_url=f"https://{payload.domain}",
        verification_method=payload.verification_method,
    )
    db.add(new_target)
    db.commit()
    db.refresh(new_target)
    return new_target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    target_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.user_id == current_user.id)
        .first()
    )
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found.",
        )

    db.delete(target)
    db.commit()

@router.post("/{target_id}/verify", response_model=TargetResponse)
async def verify_target(
    target_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.user_id == current_user.id)
        .first()
    )
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found.",
        )

    if target.is_verified:
        return target

    verified = await verify_domain_ownership(
        domain=target.domain,
        expected_token=target.verification_token,
        method=target.verification_method,
    )
    if not verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Verification failed. Ensure '{target.verification_token}' is published via {target.verification_method.value}.",
        )

    target.is_verified = True
    db.commit()
    db.refresh(target)
    return target