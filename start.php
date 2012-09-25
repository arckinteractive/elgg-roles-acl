<?php

elgg_register_event_handler('init', 'system', 'roles_acl_init');

function roles_acl_init() {

	elgg_register_library('roles.acl', elgg_get_plugins_path() . 'roles_acl/lib/acl.php');
	elgg_load_library('roles.acl');

	run_function_once('roles_acl_setup_role_based_acls');

	elgg_register_admin_menu_item('administer', 'acl', 'roles');

	elgg_register_action('roles_acl/settings', elgg_get_plugins_path() . 'roles_acl/actions/roles_acl/settings.php', 'admin');

	// look at the role acl settings and return collections that match the criteria
	elgg_register_plugin_hook_handler('access:collections:write', 'user', 'roles_acl_write_access_array');


	/*
	 * Events that need to be considered
	 *
	 * GLOBAL ACLs
	 * 	- ACL member's role has changed (remove from collection A, add to collection B) -- 'has_role' relationship listener
	 *  - New Role object has been created
	 *  - Role object has been deleted
	 *
	 * FRIENDS ACLs
	 * 	- ACL owner's role has changed - nothing happens, reflected in the role ACL settings
	 *	- ACL member's role has changed - same hook as the global acl
	 *  - Friend added
	 *  - Friend removed
	 *  - New Role object has been created
	 *  - Role object has been deleted
	 *
	 */

	// Role object created/deleted
	elgg_register_event_handler('create', 'metadata', 'roles_acl_create_role_object');
	elgg_register_event_handler('delete', 'object', 'roles_acl_delete_role_object');

	// Listen to change in users' roles and update their ACL membership
	elgg_register_event_handler('all', 'has_role', 'roles_acl_role_change');

	// Listen to changes in friendship to update user's ACL membership
	elgg_register_event_handler('all', 'friend', 'roles_acl_friendship_status');
}

/**
 * New role object has been created
 *	- create a new global ACL
 *  - create new friend ACLs
 *
 * @param str $event 'create'
 * @param str $type 'object'
 * @param ElggEntity $entity
 * @return bool
 */
function roles_acl_create_role_object($event, $type, $obj) {

	if ($obj->name != 'name') {
		return true;
	}

	$entity = get_entity($obj->entity_guid);
	if (!elgg_instanceof($entity, 'object', 'role')) {
		return true;
	}

	$acl_member_roles = array($entity);

	roles_acl_setup_role_based_acls(null, $acl_member_roles);

	return true;
}

/**
 * Role object has been deleted
 *	- delete associated global ACL
 *  - delete friend ACLs
 *
 * @param str $event 'delete'
 * @param str $type 'object'
 * @param ElggEntity $entity
 * @return bool
 */
function roles_acl_delete_role_object($event, $type, $entity) {

	if (!elgg_instanceof($entity, 'object', 'role')) {
		return true;
	}

	$acl_member_roles = array($entity);

	roles_acl_remove_role_based_acls($acl_member_roles);

	return true;
}

/**
 * Listening to all changes in 'has_role' relationship
 * $guid_one is the guid of the user
 * $guid_two is the guid of the role
 * @param type $event
 *	'delete' : remove user from all ACLs with $acl_member_role = role being deleted
 *  'create' : add user to all ACLs with $acl_member_role = new role
 *  'update' : perform 'delete' on old role and 'create' on new role
 *
 * @param type $type
 * @param type $relationship
 * @return type
 */
function roles_acl_role_change($event, $type, $relationship) {

	if ($relationship->relationship !== 'has_role') {
		return true;
	}

	$user = get_entity($relationship->guid_one);
	$role = get_entity($relationship->guid_two);

	switch ($event) {
		case 'delete' :
			roles_acl_remove_user_from_acls_by_member_role($user->guid, $role->name);
			break;

		case 'create' :
			roles_acl_add_user_to_acls_by_member_role($user->guid, $role->name);
			break;

		case 'update' :
			$old_role = roles_get_role($user);
			roles_acl_remove_user_from_acls_by_member_role($user->guid, $old_role->name);
			roles_acl_add_user_to_acls_by_member_role($user->guid, $role->name);
			break;

		default :
			return true;
			break;
	}

	return true;
}

/**
 * Listen to frienship relationship between users and update when necessary
 *
 * @param type $event
 *   'delete' : remove $friend from $user's ACL's
 *   'create' : add $friend to $user's ACL's
 *   'update' : do nothing
 *
 * @param type $type
 * @param type $relationship
 * @return type
 */
function roles_acl_friendship_status($event, $type, $relationship) {

	if ($relationship->relationship !== 'friend') {
		return true;
	}

	$user = get_entity($relationship->guid_one);
	$friend = get_entity($relationship->guid_two);
	$user_role = roles_get_role($user);
	$friend_role = roles_get_role($friend);
	$collection = roles_acl_get_friends_acl_by_member_role($user->guid, $friend_role->name);

	if (!$collection) {
		roles_acl_regenerate_friends_acl_for_user($user->guid, $friend_role->name);
		$collection = roles_acl_get_friends_acl_by_member_role($user->guid, $friend_role->name);
	}

	switch ($event) {
		case 'delete' :
			remove_user_from_access_collection($friend->guid, $collection->id);
			break;

		case 'create' :
			add_user_to_access_collection($friend->guid, $collection->id);
			break;

		default :
			return true;
			break;
	}

	return true;
}

function roles_acl_write_access_array($hook, $type, $return, $params) {

	$user_guid = elgg_extract('user_id', $params);
	$user = get_entity($user_guid);
	$role = roles_get_role($user);

	if (!elgg_instanceof($user, 'user')) {
		return $return;
	}

	$settings = elgg_get_plugin_setting('roles_acl_settings', 'roles_acl');

	if (!$settings)
		return $return;

	$acls = unserialize($settings);

	$custom = array();

	if (isset($acls['global'][$role->name])) {
		foreach ($acls['global'][$role->name] as $acl_member_role) {
			$collection = roles_acl_get_global_acl_by_member_role($acl_member_role);
			if ($collection) {
				$custom["$collection->id"] = elgg_echo($collection->name);
			}
		}
	}

	// Unset friends ACLs created by roles_acl and only append those that are defined in settings
	/** @todo: find a better approach */
	foreach ($return as $id => $name) {
		$is_roles_acl = explode(':', $name);
		if (sizeof($is_roles_acl) == 3 && $is_roles_acl[0] == 'acl' && $is_roles_acl[2] == 'friends') {
			unset($return[$id]);
		}
	}

	if (isset($acls['friends'][$role->name])) {
		foreach ($acls['friends'][$role->name] as $acl_member_role) {
			$collection = roles_acl_get_friends_acl_by_member_role($user->guid, $acl_member_role);
			if ($collection) {
				$custom["$collection->id"] = elgg_echo($collection->name);
			}
		}
	}

	$custom = $return + $custom;

	return $custom;
}