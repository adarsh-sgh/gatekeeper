# Example tenant policy. The service queries data.gatekeeper and reads
# `allow` (bool) and `reasons` (set of strings, joined into the audit reason).
package gatekeeper

default allow := false

# Admins can do anything.
allow if "admin" in input.subject.roles

# Owners can read and write their own resources.
allow if {
	input.action in {"read", "write"}
	input.resource.attrs.owner == input.subject.id
}

# Anyone can read public resources, except when the subject is suspended.
allow if {
	input.action == "read"
	input.resource.attrs.public == true
	not input.subject.attrs.suspended
}

reasons contains "role:admin" if "admin" in input.subject.roles
reasons contains "owner" if input.resource.attrs.owner == input.subject.id
reasons contains "public" if input.resource.attrs.public == true
reasons contains "suspended" if input.subject.attrs.suspended
