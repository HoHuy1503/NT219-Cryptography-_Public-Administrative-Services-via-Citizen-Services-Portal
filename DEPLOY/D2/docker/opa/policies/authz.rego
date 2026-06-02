package govportal.authz

import future.keywords.if
import future.keywords.in

default allow := false

public_paths := {
	"/health",
	"/.well-known/jwks.json",
	"/api/storage/login",
	"/api/storage/officers/login",
	"/api/storage/register",
	"/api/storage/register/officer",
	"/api/storage/register/thirdparty",
	"/api/storage/qr-register",
}

public_prefixes := [
	"/api/storage/register/",
]

allow if {
	input.path in public_paths
}

allow if {
	some prefix in public_prefixes
	startswith(input.path, prefix)
}

allow if {
	input.user_type == "storage_admin"
}

allow if {
	input.user_type == "pki_admin"
	not startswith(input.path, "/api/storage/admin/db")
}

allow if {
	input.user_type == "officer"
	officer_allowed(input.path, input.method)
}

allow if {
	input.user_type == "citizen"
	citizen_allowed(input.path, input.method)
}

allow if {
	input.user_type == "thirdparty"
	thirdparty_allowed(input.path, input.method)
}

officer_allowed(path, method) if {
	startswith(path, "/api/storage/officers")
}

officer_allowed(path, method) if {
	startswith(path, "/api/storage/document-sign-requests")
}

officer_allowed(path, method) if {
	startswith(path, "/api/storage/documents")
}

officer_allowed(path, method) if {
	startswith(path, "/api/documents")
}

officer_allowed(path, method) if {
	startswith(path, "/api/pki")
}

officer_allowed(path, method) if {
	startswith(path, "/api/storage/citizens")
}

officer_allowed(path, method) if {
	startswith(path, "/api/storage/officer-cert-requests")
}

officer_allowed(path, method) if {
	path == "/api/storage/status"
}

citizen_allowed(path, method) if {
	startswith(path, "/api/storage/documents")
}

citizen_allowed(path, method) if {
	startswith(path, "/api/storage/document-verify-requests")
}

citizen_allowed(path, method) if {
	startswith(path, "/api/storage/document-sign-requests")
}

citizen_allowed(path, method) if {
	path == "/api/storage/verify-document-qr"
}

citizen_allowed(path, method) if {
	startswith(path, "/api/qr")
}

citizen_allowed(path, method) if {
	path == "/api/storage/status"
}

thirdparty_allowed(path, method) if {
	startswith(path, "/api/storage/document-verify-requests")
}

thirdparty_allowed(path, method) if {
	path == "/api/storage/verify-document-qr"
}

thirdparty_allowed(path, method) if {
	startswith(path, "/api/thirdparty")
}

thirdparty_allowed(path, method) if {
	startswith(path, "/api/storage/documents")
}

thirdparty_allowed(path, method) if {
	path == "/api/storage/status"
}
