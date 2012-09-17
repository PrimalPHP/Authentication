<?php 

/**
 * Primal SaltedHash
 *
 * Data model for hashing passwords with a blowfish salt.
 * 
 * @package Primal.Authentication
 */

namespace Primal\Authentication;

class SaltedHash {
	protected $salt;
	protected $active_hash;
	
	function __construct($hash=null, $cost='10') {
		$this->active_hash = $hash;
		if ($hash) $this->salt = substr($hash, 0, 29);
		else $this->salt = '$2a$'.$cost.'$'.substr(hash('sha256', uniqid(mt_rand(), true)), 0, 22);
	}
	
	function hash($password) {
		return crypt($password, $this->salt);
	}
	
	function compare($password) {
		if (!$this->active_hash) return false;
		return $this->hash($password) === $this->active_hash;
	}
	
}

/*
$sh = new SaltedHash();
$hash = $sh->hash('admin');

$sh = new SaltedHash($hash);
var_dump($hash, $sh->compare('admin'));
*/