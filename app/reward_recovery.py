"""Crash-safe reconciliation for reward-backed temporary access.

Reward redemption spans SQLite and RouterOS. A reservation is debited before the
RouterOS write, so interruption recovery must distinguish a grant that was
actually proven on RouterOS from one that never crossed the validated write
boundary. The durable RouterOS scheduler reference is the recovery evidence.
"""


def reward_redemption_reference(redemption_id: int) -> str:
    return f"redemption:{int(redemption_id)}"


def temporary_state_proves_reward(state: dict, redemption_id: int) -> bool:
    return str((state or {}).get("reference") or "") == reward_redemption_reference(
        redemption_id
    )


def recover_pending_reward_redemptions(
    *, policy_store, router, audit, router_error, actor="system:startup", ip=None
):
    """Reconcile every RESERVED reward debit against fresh RouterOS evidence.

    Outcomes:
      * matching durable RouterOS reference -> complete the debit;
      * proven no active/matching grant -> refund the debit;
      * RouterOS unavailable or unrelated active override -> leave RESERVED.

    Leaving an uncertain reservation debited is intentionally restrictive. It
    prevents an application interruption from creating free temporary access.
    """
    outcomes = []
    for pending in policy_store.list_pending_reward_redemptions(ip=ip):
        redemption_id = int(pending["id"])
        ip = str(pending["ip"])
        try:
            state = router.get_device_temporary_access(ip)
        except router_error as exc:
            audit(
                "REWARD_REDEMPTION_RECOVERY_DEFERRED",
                actor,
                f"redemption={redemption_id} ip={ip}; RouterOS state unavailable: {exc}",
            )
            outcomes.append({**pending, "recovery": "deferred", "reason": str(exc)})
            continue

        if temporary_state_proves_reward(state, redemption_id):
            completed = policy_store.complete_reward_redemption(
                redemption_id,
                restore_at=state.get("restore_at") or state.get("restore_time") or "",
                note="Recovered confirmed RouterOS reward access after application interruption",
            )
            audit(
                "REWARD_REDEMPTION_RECOVERED_APPLIED",
                actor,
                (
                    f"redemption={redemption_id} ip={ip} spent={pending.get('minutes')}m; "
                    f"active={bool(state.get('active'))} expired={bool(state.get('expired'))}"
                ),
            )
            outcomes.append({**completed, "recovery": "applied"})
            continue

        if state.get("active"):
            audit(
                "REWARD_REDEMPTION_RECOVERY_DEFERRED",
                actor,
                (
                    f"redemption={redemption_id} ip={ip}; active temporary access "
                    "exists without matching reward reference"
                ),
            )
            outcomes.append(
                {
                    **pending,
                    "recovery": "deferred",
                    "reason": "unbound active temporary access",
                }
            )
            continue

        refunded = policy_store.refund_reward_redemption(
            redemption_id,
            note="Recovered unconfirmed reward redemption; RouterOS grant was not present",
        )
        audit(
            "REWARD_REDEMPTION_RECOVERED_REFUNDED",
            actor,
            f"redemption={redemption_id} ip={ip} refunded={pending.get('minutes')}m",
        )
        outcomes.append({**refunded, "recovery": "refunded"})
    return outcomes
