# DEPLOY/D1/configs/opa-policies/govportal.rego
package govportal.authz
import future.keywords.if
import future.keywords.in
 
# ── DENY-BY-DEFAULT (I5) ───────────────────────────────
default allow := false
 
# ── RULE 1: Citizen đọc/nộp hồ sơ của mình ────────────
allow if {
    input.user.role == "CITIZEN"
    input.action in {"read", "submit"}
    input.resource.type == "application"
    input.resource.owner == input.user.id
}
 
# ── RULE 2: Officer xử lý hồ sơ đúng phòng ban ─────────
allow if {
    input.user.role == "OFFICER"
    input.action in {"read", "approve", "reject", "comment"}
    input.resource.type == "application"
    input.resource.dept == input.user.dept
    is_business_hours
}
 
# ── RULE 3: Admin quản lý tài khoản ────────────────────
allow if {
    input.user.role == "ADMIN"
    input.action in {"create_user","deactivate_user","assign_role"}
    input.resource.type == "user_management"
}
 
# ── RULE 4: Auditor chỉ đọc log ─────────────────────────
allow if {
    input.user.role == "AUDITOR"
    input.action == "read"
    input.resource.type == "audit_log"
}
 
# ── HELPER: giờ hành chính ──────────────────────────────
is_business_hours if {
    h := time.clock(time.now_ns())[0]
    h >= 7; h < 17
    day := time.weekday(time.now_ns())
    day in {"Monday","Tuesday","Wednesday","Thursday","Friday"}
}
 
# ── DENY REASON cho E-X2 Explainability (I5) ────────────
deny_reason := "CITIZEN can only access own resources" if {
    not allow
    input.user.role == "CITIZEN"
    input.resource.owner != input.user.id
} else := "Officer dept mismatch with resource dept" if {
    not allow
    input.user.role == "OFFICER"
    input.resource.dept != input.user.dept
} else := "Outside business hours" if {
    not allow
    input.user.role == "OFFICER"
    not is_business_hours
} else := "Action not permitted for this role" if {
    not allow
    input.user.role in {"CITIZEN","OFFICER","AUDITOR"}
} else := "No matching allow rule — deny by default"
