<?php

namespace Cvl\LDAPWrapper;

class LDAPGroup extends LDAPEntry {

	const EMPTY_RESULT = -1;
	
	protected $members = self::EMPTY_RESULT;

	protected $managers = self::EMPTY_RESULT;
	
	protected $description = self::EMPTY_RESULT;
	
	public function getDescription() {
		if ($this->description === self::EMPTY_RESULT) {
			$this->description = $this->ldapWrapper->getAttributeForParticularDN($this->getDN(), LDAPWrapper::LDAP_ATTRIBUTE_DESCRIPTION);
			if (!empty($this->description)) {
				$this->description = implode($this->description);
			} else {
				$this->description = '';
			}
		}
		return $this->description;
	}

	public function getMembers() {
		if ($this->members === self::EMPTY_RESULT) {
			$this->members = $this->ldapWrapper->getMembersOfGroup($this->getDN());
		}
		return $this->members;
	}

	public function getManagers() {
		if ($this->managers === self::EMPTY_RESULT) {
			$this->managers = $this->ldapWrapper->getManagersOfGroup($this->getDN());
		}
		return $this->managers;
	}
}