<?php
/**
 * Fuel
 *
 * Fuel is a fast, lightweight, community driven PHP5 framework.
 *
 * @package    Fuel
 * @version    1.7
 * @author     Fuel Development Team
 * @license    MIT License
 * @copyright  2010 - 2015 Fuel Development Team
 * @link       http://fuelphp.com
 */

/**
 * NOTICE:
 *
 * If you need to make modifications to the default configuration, copy
 * this file to your app/config folder, and make them in there.
 *
 * This will allow you to upgrade fuel without losing your custom config.
 */

return array(

	/**
	 * DB connection, leave null to use default
	 */
	'db_connection' => null,

	/**
	 * DB write connection, leave null to use same value as db_connection
	 */
	'db_write_connection' => null,

	/**
	 * DB table name for the user table
	 */
	'table_name' => 'tb_users',
	'table_users' => 'tb_users',
	'table_usersinfo' => 'tb_usersinfo',

	/**
	 * Choose which columns are selected, must include: username, password, email, last_login,
	 * login_hash, group & profile_fields
	 */
	'table_columns' => array('*'),

	/**
	 * This will allow you to use the group & acl driver for non-logged in users
	 */
	'guest_login' => true,

	/**
	 * This will allow the same user to be logged in multiple times.
	 *
	 * Note that this is less secure, as session hijacking countermeasures have to
	 * be disabled for this to work!
	 */
	'multiple_logins' => false,

	/**
	 * Remember-me functionality
	 */
	'remember_me' => array(
		/**
		 * Whether or not remember me functionality is enabled
		 */
		'enabled' => false,

		/**
		 * Name of the cookie used to record this functionality
		 */
		'cookie_name' => 'rmcookie',

		/**
		 * Remember me expiration (default: 31 days)
		 */
		'expiration' => 86400 * 31,
	),

	/**
	 * Groups as id => array(name => <string>, roles => <array>)
	 */
	'groups' => array(
		/**
		 * Examples
		 * ---
		 *
		 * -50   => array('name' => 'Banned', 'roles' => 'custom'),
		 * -1   => array('name' => 'Banned', 'roles' => array('banned')),
		 * 0    => array('name' => 'Guests', 'roles' => array()),
		 * 1    => array('name' => 'Users', 'roles' => array('user')),
		 * 50   => array('name' => 'Moderators', 'roles' => array('user', 'moderator')),
		 * 100  => array('name' => 'Administrators', 'roles' => array('user', 'moderator', 'admin')),
		 */
        -1    => array('name' => 'Banned', 'roles' => array('banned')),
         0    => array('name' => 'Guest', 'roles' => array()),
         1    => array('name' => 'Users', 'roles' => array('user')),
         50   => array('name' => 'Moderators', 'roles' => array('user', 'moderator')),
        100   => array('name' => 'Administrators', 'roles' => array('super')),
        200   => array('name' => 'Custom', 'roles' => 'fromdb'),
	),

	/**
	 * Roles as name => array(location => rights)
	 */
	'roles' => array(
		/**
		 * Examples
		 * ---
		 *
		 * Regular example with role "user" given create & read rights on "comments":
		 *   'user'  => array('comments' => array('create', 'read')),
		 * And similar additional rights for moderators:
		 *   'moderator'  => array('comments' => array('update', 'delete')),
		 *
		 * Wildcard # role (auto assigned to all groups):
		 *   '#'  => array('website' => array('read'))
		 *
		 * Global disallow by assigning false to a role:
		 *   'banned' => false,
		 *
		 * Global allow by assigning true to a role (use with care!):
		 *   'super' => true,
		 */
//        /'#'  => array('website' => array('read')),
        'user'  => array('comments' => array('create', 'read')),
        'moderator'  => array('comments' => array('update', 'delete')),
        'super' => false,
        //'super' => array('comments' => array('delete')),
        'banned' => false,
	),

	/**
	 * Salt for the login hash
	 */
	'login_hash_salt' => 'put_some_salt_in_here',

	/**
	 * $_POST key for login username
	 */
	'username_post_key' => 'username',

	/**
	 * $_POST key for login password
	 */
	'password_post_key' => 'password',

    /**
     * This will allow you store logined info on session or hit db
     */
    'use_session' => true,

);
