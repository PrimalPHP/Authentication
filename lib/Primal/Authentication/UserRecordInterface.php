<?php 

namespace Primal\Authentication;

interface UserRecordInterface {
	
	public function getUserID();
	public function getPasswordHash();
	public function getUserType();
	public function postLogin();
	
}
