<?php
namespace Primal\Authentication;

abstract class UserRecord extends \Primal\Database\MySQL\Record implements UserRecordInterface {

	protected $password_hash_column = 'password_hash';

	const ERR_PASSCHANGE_OK = 0;
	const ERR_PASSCHANGE_WRONGCURRENT = 1;
	const ERR_PASSCHANGE_WRONGCONFIRM = 2;
	const ERR_PASSCHANGE_TOOSHORT = 3;
	const PASSWORD_MIN_LENGTH = 4;

/**
	INSTANCE FUNCTIONS
*/

	/**
	 * Alias to fetching record values as object properties.  Allows for easier retrieval via Visitor::CurrentUser();
	 *
	 * @param string $field Property name being requested
	 * @return mixed
	 */
	function __get($field) {
		if (isset($this[$field])) return $this[$field];
	}	


	/**
	 * Proper function for setting the user's password.  Encrypts the password using internal functions and sets it in the database.
	 * If no ID is set on the record, the function assumes that this record has not yet been created and will only set it in memory.
	 *
	 * @param string $newpass The plaintext password we wish to set for this user.
	 * @param null|boolean $autosave Optional argument to force/deny automatic calling of $this->set() for the password value
	 * @return string The generated hash.
	 */
	public function setPassword($newpass, $autosave=null) {
		$sh = new SaltedHash();
		$hash = $sh->hash($newpass);
		
		if (($this['id'] && $autosave!==false) || $autosave===true) $this->set($this->password_hash_column,$hash);
		else $this[ $this->password_hash_column ] = $hash;
		return $hash;
	}

	/**
	 * Tests the passed password against the salted password stored in the user record
	 * 
	 * @param string $password
	 * @return boolean
	 */
	public function testPassword($password) {
		$sh = new SaltedHash($this[ $this->password_hash_column ]);
		return $sh->compare($password);
	}


	/**
	 * Convenience function for changing the users password.  Requires that the user provides their current password, as well as a confirmation of their new password.
	 *
	 * @param string $old User's current password
	 * @param string $new The new password to be set on this account
	 * @param string $confirm Optional confirmation value, triggers a separate error if new passwords do not match.
	 * @return integer See the ERR_PASSCHANGE constants at the beginning of this file for return results.
	 */
	public function changePassword($old, $new, $confirm=false) {
		if (!$this->testPassword($old)) return static::ERR_PASSCHANGE_WRONGCURRENT;
		if ($confirm !== false && $new != $confirm) return static::ERR_PASSCHANGE_WRONGCONFIRM;
		if (strlen(trim($new)) < static::PASSWORD_MIN_LENGTH) return static::ERR_PASSCHANGE_TOOSHORT;
	
		$this->setPassword($new);
		return static::ERR_PASSCHANGE_OK;
	}

/**
	UserRecordInterface Implementation
*/

	public function getUserID() {return $this['id'];}
	public function getPasswordHash() {return $this['password_hash'];}
	public function getUserType() {return isset($this['type']) ? $this['type'] : null;}
	public function postLogin() {
		//if the table for users has a last-login value, update it to right now
		if (isset($this['last_login'])) $this->set('last_login','now');
	}

}