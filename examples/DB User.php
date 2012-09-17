<?php 

namespace DB;

use \Primal\Authentication\Visitor;

class User extends \Primal\Authentication\UserRecord {
	protected $tablename = 'users';
	protected $primary = array('id');
			
	/**
	 * Set the login session using user credentials
	 *
	 * @static
	 * @param string $email User's email address
	 * @param string $password User's password
	 * @param boolean $remember Optional, if true it will also set a cookie login value for auto-signin on session loss
	 * @return integer See the ERR_LOGIN constants for return results.
	 * @access public
	 */
	const ERR_LOGIN_OK = 0;
	const ERR_LOGIN_BADUSER = 1;
	const ERR_LOGIN_BADPASS = 2;
	public static function LoginWithUsername ($username, $password, $remember=false) {
		$u = new static();
		$u->load($username, 'username');
		if (!$u->found) return static::ERR_LOGIN_BADUSER;
		if (!$u->testPassword($password)) return static::ERR_LOGIN_BADPASS;

		return Visitor::LoginWithUser($u, $remember);
	}
	
}
