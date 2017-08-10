<?php

namespace Cvl\LDAPWrapper;

class LDAPUser extends LDAPEntry {
	const EMPTY_RESULT = -1;

	protected $displayName = self::EMPTY_RESULT;

	protected $mail = self::EMPTY_RESULT;
	
	protected $isAdmin = self::EMPTY_RESULT;

	protected $isDisabled = self::EMPTY_RESULT;

	protected $managerOf = array();

	protected $memberOf = array();

	public function getDisplayName() {
		if ($this->displayName == self::EMPTY_RESULT) {
			$displayNameAttributes = $this->ldapWrapper->getAttributeForParticularDN($this->getDN(), 'displayName');

			if (isset($displayNameAttributes) && isset($displayNameAttributes[0])) {
				$this->displayName = $displayNameAttributes[0];
			} else {
				$this->displayName = null;
			}
		}
		return $this->displayName;
	}

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
		if (!isset($this->managerOf[$groupDN])) {
			$this->managerOf[$groupDN] = $this->ldapWrapper->isGroupManager($groupDN, $this->getDN());
		}
		return $this->managerOf[$groupDN];
	}

	public function isMemberOf($groupDN) {
		if (!isset($this->memberOf[$groupDN])) {
			$this->memberOf[$groupDN] = $this->ldapWrapper->isGroupMember($groupDN, $this->getDN());
		}
		return $this->memberOf[$groupDN];
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

	public function isDisabled() {
		if ($this->isDisabled === self::EMPTY_RESULT) {
			$this->isDisabled = $this->ldapWrapper->isDisabled($this->getDN());
		}
		return $this->isDisabled;
	}
}