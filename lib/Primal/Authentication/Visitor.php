<?php 

namespace Primal\Authentication;

class Visitor extends \Primal\Session\SessionAbstraction {

	/**
	 * Overwriting the session abstraction index key
	 *
	 * @var string
	 */
	protected $abstraction_key = 'Visitor';
	
	
	/**
	 * Prefix of the "remember me" cookie keys
	 *
	 * @var string
	 */
	protected $autologin_cookie_prefix = 'v';
	
	
	/**
	 * Visitor singleton
	 * If a user is logged in, we save the object for the duration of the request to avoid repeated lookups
	 *
	 * @var Visitor
	 */
	protected static $singleton = null;
	
	
	/**
	 * Primal Database Record object to be used for loading users
	 */
	protected static $user_record;
	

	/**
	 * Current User's Record
	 *
	 * @var string
	 */
	public $user;
	
	
	/**
	 * Current User's ID
	 *
	 * @var string
	 */
	public $id;

	
	public static function Current() {
		if (static::$singleton) {
			//if a visitor already exists, that means a user is logged in. just return it immediately
			return static::$singleton;
		} elseif (static::$singleton === false) {
			//we tested previously and know that no user is logged in
			return null;
		}
		
		if (!static::$user_record) {
			throw new VisitorException("Missing bound user record class");
		}
		
		$v = new static(); //initialize the session with auto-start
		if ($v['ID'] && $u = new static::$user_record($v['ID']) && $u->found) {
			$v->user = $u;
			$v->id = $u->getUserID();
			return static::$singleton = $v;
		}
		
		//user isn't currently logged in, check if a memory cookie exists
		
		if (isset($_COOKIE[$this->autologin_cookie_prefix.'-1']) && isset($_COOKIE[$this->autologin_cookie_prefix.'-2'])) {
			$cookie_id = hexdec($_COOKIE[$this->autologin_cookie_prefix.'x']);
			$cookie_pass = $_COOKIE[$this->autologin_cookie_prefix.'y'];

			$v->start(); //force session start
			
			$u = new static::$user_record($cookie_id);
			if ($u->found) {
				$hash = $u->getPasswordHash();
				if ($cookie_pass === sha1($u->getPasswordHash())) {
					return static::LoginWithUser($u, true);
				}
			}
		}
		
		return static::$singleton = false;
	}
	
	/**
	 * Set the login session using a user object
	 *
	 * @static
	 * @param DB\User $user
	 * @param boolean $remember Optional, if true it will also set a cookie login value for auto-signin on session loss
	 * @param integer $cookie_duration Optional, length of time to retain memory cookie, in days. Defaults to one year.
	 * @return Visitor
	 * @access public
	 */
	public static function LoginWithUser ($user, $remember=false, $cookie_duration = 365 ) {
		$v = new static(true); //force session creation
		$v->user = $user;
		$v['ID'] = $v->id = $user->getUserID();

		$user->postLogin();

		if ($remember) {
			setcookie($this->autologin_cookie_prefix.'x', dechex($user->getUserID()), time() + 86400 * $cookie_duration, '/');
			setcookie($this->autologin_cookie_prefix.'y', sha1($user->getPasswordHash()), time()+ 86400 * $cookie_duration, '/');
		}

		return static::$singleton = $v;
	}
	
	
	
	/**
	 * Removes the current user from the active session and kills the login cookie.
	 *
	 * @static
	 * @access public
	 */
	public static function Logout () {
		$v = new static();
		$v->reset();
		
		static::$singleton = false;
		
		setcookie($this->autologin_cookie_prefix.'x', '', 0, '/');
		setcookie($this->autologin_cookie_prefix.'y', '', 0, '/');
	}
	
	
	/**
	 * Validates the current user's login credentials and redirects to the login form if they do not have access to the requested page.
	 * This function is intended to be called at the top of any pages that require a user be logged in.
	 *
	 * @static
	 * @param string $type Optional user type (part of the table schema) to test against.  Use this to validate admin users on admin only pages.
	 * @access public
	 */
	static function Validate() {
		if (!static::Current()) {

			static::Bounce(static::ERR_BOUNCE_NOT_SIGNED_IN);
			
		} elseif (func_num_args()) {

			$type = static::Current()->user->getUserType();
			$allowed = func_get_args();
			if (!in_array($type, $allowed)) {
				static::Bounce(static::ERR_BOUNCE_PERMISSION);
			}
			
		}
	}
	
	
	const ERR_BOUNCE_NOT_SIGNED_IN = 1;
	const ERR_BOUNCE_PERMISSION = 2;
	
	/**
	 * Redirects the user to the login page.  Overwrite this in a subclass for further functionality.
	 *
	 * @param string $type 
	 * @return void
	 */
	static function Bounce($type) {
		header("Location: /login/");
		exit;
	}
	
	/**
	 * Assigns a specific Record subclass to be used for loading and checking user data
	 * Assigned class must implement UserRecordInterface and accept a user ID as the first constructor argument
	 *
	 * @param UserRecordInterface $o Instance of the object to be used
	 */
	public static function BindUserRecord(UserRecordInterface $o) {
		static::$user_record = $o;
	}
	
}

class VisitorException extends \Exception {}