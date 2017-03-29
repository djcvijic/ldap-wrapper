<?php

namespace Cvl\LDAPWrapper;

class LDAPUser extends LDAPEntry {
	const EMPTY_RESULT = -1;

	protected $mail = self::EMPTY_RESULT;
	
	protected $isAdmin = self::EMPTY_RESULT;

	public function getMail() {
		if ($this->mail === self::EMPTY_RESULT) {
			$mailAttributes = $this->ldapWrapper->getAttributeForParticularDN($this->getDN(), 'mail');
			
			if (isset($mailAttributes) && isset($mailAttributes[0])) {
				$this->mail = $mailAttributes[0];
			} else {
				$this->mail = null;
			}
		}
		
		return $this->mail;
	}

	public function setMail($mail) {
		$this->mail = $mail;
	}

	public function isManagerOf($groupDN) {
		return $this->ldapWrapper->isGroupManager($groupDN, $this->getDN());
	}

	public function canModify($groupDN) {
		return $this->ldapWrapper->canModifyGroup($groupDN, $this->getDN());
	}

	public function isAdmin() {
		if ($this->isAdmin === self::EMPTY_RESULT) {
			$this->isAdmin = $this->ldapWrapper->isAdmin($this->getDN());
		}
		return $this->isAdmin;
	}

	public function toArray() {
		return array(
			'mail' => $this->getMail(), 
			'commonName' => $this->getCommonName(), 
			'tokens' => array_merge(array(
				$this->getMail()
			), explode(' ', $this->getCommonName()))
		);
	}
}