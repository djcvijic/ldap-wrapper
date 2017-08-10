<?php

namespace Cvl\LDAPWrapper;

class LDAPGroup extends LDAPEntry {

	const EMPTY_RESULT = -1;

	protected $allUserTypeMembers = self::EMPTY_RESULT;

	protected $directUserTypeMembers = self::EMPTY_RESULT;

	protected $directGroupTypeMembers = self::EMPTY_RESULT;

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

	/** @deprecated Use getAllUserTypeMembers */
	public function getMembers() {
		return $this->getAllUserTypeMembers();
	}

	public function getAllUserTypeMembers() {
		if ($this->allUserTypeMembers === self::EMPTY_RESULT) {
			$this->allUserTypeMembers = $this->ldapWrapper->getAllUserTypeMembersOfGroup($this->getDN());
		}
		return $this->allUserTypeMembers;
	}

	public function getDirectUserTypeMembers() {
		if ($this->directUserTypeMembers === self::EMPTY_RESULT) {
			$this->directUserTypeMembers = $this->ldapWrapper->getDirectUserTypeMembersOfGroup($this->getDN());
		}
		return $this->directUserTypeMembers;
	}

	public function getDirectGroupTypeMembers() {
		if ($this->directGroupTypeMembers === self::EMPTY_RESULT) {
			$this->directGroupTypeMembers = $this->ldapWrapper->getDirectGroupTypeMembersOfGroup($this->getDN());
		}
		return $this->directGroupTypeMembers;
	}

	public function getManagers() {
		if ($this->managers === self::EMPTY_RESULT) {
			$this->managers = $this->ldapWrapper->getManagersOfGroup($this->getDN());
		}
		return $this->managers;
	}
}