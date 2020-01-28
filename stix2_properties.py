import pprint

common = "id, created_by_ref, created, modified, labels, external_references"

specific = {
	"attack_pattern": "name, description, kill_chain_phases",
	"campaign": "name, description, aliases, first_seen, last_seen, objective",
	"course_of_action": "name, description, action",
	"identity": "name, description, identity_class, sectors, contact_information",
	"indicator": "name, description, pattern, valid_from, valid_until, kill_chain_phases",
	"intrusion_set": "name, description, aliases, first_seen, last_seen, goals, resource_level, primary_motivation, secondary_motivations",
	"malware": "name, description, kill_chain_phases",
	"observed_data": "first_observed, last_observed, number_observed, objects",
	"report": "name, description, published, object_refs",
	"threat_actor": "name, description, aliases, roles, goals, sophistication, resource_level, primary_motivation, secondary_motivations, personal_motivations",
	"tool": "name, description, kill_chain_phases, tool_version",
	"vulnerability": "name, description"}


result = dict()

_common = common.split(", ")
result["common"] = _common

for s in specific:
	result[s] = specific[s].split(", ")

pprint.pprint(result)

