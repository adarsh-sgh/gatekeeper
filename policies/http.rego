# Policy for HTTP traffic authorised through Envoy ext_authz. The adapter
# maps GET/HEAD/OPTIONS to "read", everything else to "write", and the path
# to resource.id.
package gatekeeper

default allow := false

allow if "admin" in input.subject.roles

allow if {
	input.action == "read"
	startswith(input.resource.id, "/public/")
}

allow if {
	input.action == "read"
	"viewer" in input.subject.roles
}

reasons contains "role:admin" if "admin" in input.subject.roles
reasons contains "public" if startswith(input.resource.id, "/public/")
reasons contains "role:viewer" if {
	input.action == "read"
	"viewer" in input.subject.roles
}
