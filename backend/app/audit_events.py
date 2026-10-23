"""
SR-16: the catalogue of audited events, and the only values an audit entry may hold.

Every event type the code writes is listed here with its category. audit() in app/security.py
refuses any other event type, any field outside its allow-list, and any value outside the fixed
sets below, so nothing an elector typed, no token and no ballot content can reach the log.

Categories:
- authentication: signing in and out of a session, and registering credentials.
- eligibility: an elector being allowed or refused a ballot, and their ballot being accepted.
  These name the elector's account, but never the ballot, the token or the receipt.
- privileged_access: staff signing in, staff being refused, staff accounts being created.
- configuration: the signed electoral roll and the signed ballot definitions.
- ballot_box: the sealed ballot chain. These never name an elector, a ballot or a token: only a
  batch number, a count and a reason code.
"""

AUTHENTICATION = "authentication"
ELIGIBILITY = "eligibility"
PRIVILEGED_ACCESS = "privileged_access"
CONFIGURATION = "configuration"
BALLOT_BOX = "ballot_box"
CATEGORIES = frozenset({AUTHENTICATION, ELIGIBILITY, PRIVILEGED_ACCESS, CONFIGURATION, BALLOT_BOX})

# SR-16: every event type, each in exactly one category. The names are the ones earlier SRs
# already wrote, so existing rows and the people reading them see no rename.
EVENT_CATEGORIES: dict[str, str] = {
    # SR-01 and SR-04: sign in, lockout, the IP rate limit, session extensions
    "auth_login_success": AUTHENTICATION,
    "auth_password_failed": AUTHENTICATION,
    "auth_totp_failed": AUTHENTICATION,
    "auth_account_locked": AUTHENTICATION,
    "auth_rate_limited": AUTHENTICATION,
    "SESSION_EXTENDED": AUTHENTICATION,
    "SESSION_EXTENSION_REFUSED": AUTHENTICATION,
    # Registration: credentials are set up for a roll entry
    "REGISTRATION_STARTED": AUTHENTICATION,
    "REGISTRATION_COMPLETED": AUTHENTICATION,
    "REGISTRATION_FAILED": AUTHENTICATION,
    # SR-02 and SR-03 (SR-05 for the reset route, SR-08 for an invalid ranking)
    "ELIGIBILITY_DENIED": ELIGIBILITY,
    "BALLOT_TOKEN_ISSUED": ELIGIBILITY,
    "BALLOT_TOKEN_REJECTED": ELIGIBILITY,
    "BALLOT_REJECTED_INVALID": ELIGIBILITY,
    "BALLOT_ACCEPTED": ELIGIBILITY,
    "BALLOT_REPLAY_BLOCKED": ELIGIBILITY,
    "ELECTOR_RESET": ELIGIBILITY,
    # SR-05 and SR-06
    "AUTH_PRIVILEGED_LOGIN_SUCCESS": PRIVILEGED_ACCESS,
    "AUTHZ_DENIED": PRIVILEGED_ACCESS,
    "STAFF_CREATED": PRIVILEGED_ACCESS,
    # SR-02 and SR-07
    "ROLL_VERIFIED": CONFIGURATION,
    "ROLL_VERIFICATION_FAILED": CONFIGURATION,
    "BALLOT_DEFINITION_ACTIVATED": CONFIGURATION,
    "BALLOT_DEFINITION_REJECTED": CONFIGURATION,
    "BALLOT_DEFINITION_INVALID": CONFIGURATION,
    # SR-13
    "BALLOT_BATCH_SEALED": BALLOT_BOX,
    "BALLOT_CHAIN_VERIFY_FAILED": BALLOT_BOX,
}

SUCCESS = "success"
FAILURE = "failure"
DENIED = "denied"
REJECTED = "rejected"
OUTCOMES = frozenset({SUCCESS, FAILURE, DENIED, REJECTED})

# SR-16: the role of whoever acted. "script" is an operator running a script on the server, and
# "unknown" is used when no account is known (a failed sign in with an unknown username).
SCRIPT = "script"
UNKNOWN = "unknown"
ROLES = frozenset({"elector", "polling_official", "auditor", SCRIPT, UNKNOWN})

# SR-16: every reason any event gives, collected from the earlier SRs. A reason is a fixed code,
# never free text, so it cannot carry a value from a request.
REASON_CODES = frozenset(
    {
        # SR-02: why an elector was denied, and the start-up roll check
        "no_record",
        "bad_signature",
        "not_enrolled",
        "no_division",
        "under_age",
        "public_key_missing",
        # SR-03: a ballot token problem
        "invalid",
        "wrong_state",
        # SR-04: a refused extension
        "limit",
        "expired",
        # SR-05: the permission an account lacked (app/rbac.py)
        "turnout:read",
        "elector:reset",
        "audit:read",
        "audit:verify",
        # SR-07: ballot definition checks and activation
        "bad_payload",
        "election_mismatch",
        "not_enough_delegates",
        "not_yet_valid",
        "bad_version",
        "bad_prev_hash",
        "no_active_definition",
        "no_division_entry",
        "unknown_election",
        "polls_open",
        "insufficient_lead",
        # SR-13: ballot chain verification (app/ballot_chain.py CHECK_GROUPS)
        "bad_entry_hash",
        "broken_link",
        "gap_or_reorder",
        "missing_ballot",
        "missing_checkpoint",
        "malformed_checkpoint",
        "bad_checkpoint_signature",
        "checkpoint_mismatch",
        "tail_mismatch",
        "unsealed_after_final",
        # Registration: the step that failed, or why it ended
        "details_not_verified",
        "wrong_code",
        "too_many_attempts",
        "already_registered",
    }
)
