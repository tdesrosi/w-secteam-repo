#
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

package templates.gcp.GCPIAMCustomRolePermissionsConstraintV1

import data.validator.gcp.lib as lib

deny[{
	"msg": message,
	"details": metadata,
}] {
	constraint := input.constraint
	lib.get_constraint_params(constraint, params)
	asset := input.asset

	asset.asset_type == "iam.googleapis.com/Role"

	asset_permissions := {x | x := asset.resource.data.includedPermissions[_]}
	params_permissions := {x | x := params.permissions[_]}

	asset_title := asset.resource.data.title

	params_title := lib.get_default(params, "title", "*")

	check_asset_title(asset_title, params_title)

	mode := lib.get_default(params, "mode", "allowlist")

	get_violations(mode, asset_permissions, params_permissions, matches_found)

	message := sprintf("Role %v grants permission %v", [asset.name, matches_found])

	metadata := {
		"resource": asset.name,
		"role_title": asset_title,
		"permission": asset_permissions,
	}
}

###########################
# Rule Utilities
###########################

# Get violations found, depending on the mode of the constraint
get_violations(mode, asset_permissions, params_permissions) = output {
	# Grab intersect from constraint permissions and tfplan permissions if denylist
	mode == "denylist"
	output = asset_permissions & params_permissions
}

get_violations(mode, asset_permissions, params_permissions) = output {
	# Grab permission(s) that fall outside of allowed permissions list
	# ie. the permissions in tfplan that are not in allowlist
	mode == "allowlist"
	output = asset_permissions - params_permissions
}

# Determine the overlap between matches under test and constraint
target_match_count(mode) = 0 {
	mode == "denylist"
}

target_match_count(mode) = 1 {
	mode == "allowlist"
}

check_asset_title(asset_title, params_title) {
	params_title == "*"
}

check_asset_title(asset_title, params_title) {
	params_title != "*"
	lower(asset_title) == lower(params_title)
}

# If the member in constraint is written as a single "*", turn it into super
# glob "**". Otherwise, we won't be able to match everything.
config_pattern(old_pattern) = "**" {
	old_pattern == "*"
}

config_pattern(old_pattern) = old_pattern {
	old_pattern != "*"
}
