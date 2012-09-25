<?php

/**
 * Create new ACLs
 *  - Global ACLs for each $acl_member_roles
 *  - Friend ACLs for each $acl_owner_roles - $acl_member_roles pair
 * 
 * @param array $acl_owner_roles Array of ACL owner Roles
 * @param array $acl_member_roles Array of ACL member Roles
 */
function roles_acl_setup_role_based_acls($acl_owner_roles = null, $acl_member_roles = null) {

	if (!$acl_owner_roles) {
		$acl_owner_roles = roles_get_all_selectable_roles();
		// default user role should have the possibility of accessing various global/friend collections
		$acl_owner_roles[] = roles_get_role_by_name(DEFAULT_ROLE);
	}

	if (!$acl_member_roles) {
		$acl_member_roles = roles_get_all_selectable_roles();
		/** @todo: would a collection of admins be useful? */
	}

	// Create global ACLs for each role
	foreach ($acl_member_roles as $acl_member_role) {
		roles_acl_regenerate_global_acl($acl_member_role->name);
	}

	// Create ACLs for all owner - member role pairs
	foreach ($acl_owner_roles as $acl_owner_role) {
		foreach ($acl_member_roles as $acl_member_role) {
			roles_acl_regenerate_friends_acls($acl_owner_role->name, $acl_member_role->name);
		}
	}

}

/**
 * Remove all ACLs associated with the $acl_member_role
 *
 * @param str $acl_member_role
 * @return bool
 */
function roles_acl_remove_role_based_acls($acl_member_role) {

	$collections = roles_acl_get_all_acls_by_member_role($acl_member_role);

	if ($collections) {
		foreach ($collections as $collection) {
			delete_access_collection($collection->id);
		}
	}
	
	return true;

}

/**
 * Get a Global ACL object
 * "acl:$role_name:global" naming convention applies
 *
 * @param str $acl_member_role Role name
 * @return obj Collection object
 */
function roles_acl_get_global_acl_by_member_role($acl_member_role) {

	$db_prefix = elgg_get_config('dbprefix');
	$collection_name = "acl:$acl_member_role:global";

	$query = "SELECT * FROM {$db_prefix}access_collections WHERE name = '{$collection_name}'";
	$get_collection = get_data_row($query);

	return $get_collection;

}

/**
 * Get all ACL objects for a given role
 * "acl:$role_name:global" naming convention applies
 * "acl:$role_name:friends" naming convention applies
 *
 * @param str $acl_member_role Role name
 * @return obj Collection object
 */
function roles_acl_get_all_acls_by_member_role($acl_member_role) {

	$db_prefix = elgg_get_config('dbprefix');
	$collection_names = "'acl:$acl_member_role:global','acl:$acl_member_role:friends'";

	$query = "SELECT * FROM {$db_prefix}access_collections WHERE name IN ($collection_names)";
	$get_collections = get_data($query);

	return $get_collections;

}

/**
 * Get an ACL owned by the User that contains only members with a given Role
 * "acl:$role_name:friends" naming convention applies
 *
 * @param int $owner_guid Guid of the User
 * @param str $acl_member_role Role name
 * @return obj Collection object
 */
function roles_acl_get_friends_acl_by_member_role($owner_guid, $acl_member_role) {

	$db_prefix = elgg_get_config('dbprefix');
	$collection_name = "acl:$acl_member_role:friends";

	$query = "SELECT * FROM {$db_prefix}access_collections WHERE name = '{$collection_name}' AND owner_guid = {$owner_guid}";
	$get_collection = get_data_row($query);

	return $get_collection;

}

/**
 * Create/Update a global ACL and populate with members with the specified role
 *
 * @param str $acl_member_role
 * @return int $collection_id
 */
function roles_acl_regenerate_global_acl($acl_member_role) {

	$collection = roles_acl_get_global_acl_by_member_role($acl_member_role);

	if (!$collection) {
		$collection_id = create_access_collection("acl:$acl_member_role:global", elgg_get_site_entity()->guid);
	} else {
		$collection_id = $collection->id;
	}

	$role = roles_get_role_by_name($acl_member_role);
	
	$members = $role->getUsers(array('limit' => 0));

	$member_guids = array();

	if ($members) {
		foreach ($members as $m) {
			$member_guids[] = $m->guid;
		}
	}

	update_access_collection($collection_id, $member_guids);

	return $collection_id;
}

/**
 * Create/Update ACLs for Users with $acl_owner_role that will contained befriended users with $acl_member_role
 *
 * @param str $acl_owner_role
 * @param str $acl_member_role
 *
 * @return array Array of created/updated collection_ids
 */
function roles_acl_regenerate_friends_acls($acl_owner_role, $acl_member_role) {

	$owner_role = roles_get_role_by_name($acl_owner_role);

	$acl_owners = $owner_role->getUsers(array('limit' => 0));
	
	$collection_ids = array();

	if ($acl_owners) {
		foreach ($acl_owners as $acl_owner) {
			$collection_ids[] = roles_acl_regenerate_friends_acl_for_user($acl_owner->guid, $acl_member_role);
		}
	}

	return $collection_ids;
}

/**
 * Update/Create an ACL for a given User containing friends with $acl_member_role
 *
 * @param str $acl_owner_guid Guid of the User
 * @param str $acl_member_role Role name
 * @return int $collection_id
 */
function roles_acl_regenerate_friends_acl_for_user($acl_owner_guid, $acl_member_role) {

	$collection = roles_acl_get_friends_acl_by_member_role($acl_owner_guid, $acl_member_role);

	if (!$collection) {
		$collection_id = create_access_collection("acl:$acl_member_role:friends", $acl_owner_guid);
	} else {
		$collection_id = $collection->id;
	}

	$role = roles_get_role_by_name($acl_member_role);

	if (!$role) {
		return false;
	}
	
	$members = $role->getUsers(array('limit' => 0));

	$member_guids = array();

	if ($members) {
		foreach ($members as $m) {
			if ($m->isFriendOf($acl_owner_guid)) {
				$member_guids[] = $m->guid;
			}
		}
	}

	update_access_collection($collection_id, $member_guids);

	return $collection_id;

}

/**
 * Remove a user from ACLs associated with an $acl_member_role
 *
 * @param int $user_guid Guid of the user
 * @param str $acl_member_role Role name
 * @return bool
 */
function roles_acl_remove_user_from_acls_by_member_role($user_guid, $acl_member_role) {

	$collections = roles_acl_get_all_acls_by_member_role($acl_member_role);

	if ($collections) {
		foreach ($collections as $collection) {
			remove_user_from_access_collection($user_guid, $collection->id);
		}
	}

	return true;

}

/**
 * Add a user to ACLs
 *  -- all global ACLs
 *  -- friends ACLs, if ACL owner is friends with the user
 *
 * @param int $user_guid Guid of the user
 * @param str $acl_member_role Role name
 * @return bool
 */
function roles_acl_add_user_to_acls_by_member_role($user_guid, $acl_member_role) {

	$collections = roles_acl_get_all_acls_by_member_role($acl_member_role);

	if ($collections) {
		foreach ($collections as $collection) {

			$type = explode(':', $collection->name);

			if (in_array('global', $type)) {
				add_user_to_access_collection($user_guid, $collection->id);
			} elseif (in_array('friends', $type)) {
				$collection_owner = get_entity($collection->owner_guid);
				if ($collection_owner->isFriendsWith($user_guid)) {
					add_user_to_access_collection($user_guid, $collection->id);
				}
			}
		}
	}

	return true;
	
}