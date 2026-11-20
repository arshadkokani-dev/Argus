from app.models.user import PlanTier

PLAN_LIMITS: dict[PlanTier, dict] = {
    PlanTier.FREE: {
        "max_targets": 1,
        "monthly_scans": 3,
        "ai_explanations": False,
        "fix_verification": False,
    },
    PlanTier.PRO: {
        "max_targets": 5,
        "monthly_scans": 50,
        "ai_explanations": True,
        "fix_verification": True,
    },
    PlanTier.AGENCY: {
        "max_targets": 20,
        "monthly_scans": 200,
        "ai_explanations": True,
        "fix_verification": True,
    },
}


def get_plan_limits(plan_tier: PlanTier) -> dict:
    return PLAN_LIMITS.get(plan_tier, PLAN_LIMITS[PlanTier.FREE])
