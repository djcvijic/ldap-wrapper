<?php

namespace Cvl\LDAPWrapper;

class LDAPEntry {

	protected $dn = null;

	protected $commonName = null;
	
	protected $ldapWrapper;

	public function __construct(LDAPWrapper $ldapWrapper, $dn) {
		$this->ldapWrapper = $ldapWrapper;
		$this->dn = $dn;
	}

	public function __toString() {
		return $this->dn;
	}

	public function getDN() {
		return $this->dn;
	}
	
	public function getCommonName(){
		
		if ($this->commonName === null){
			$this->commonName = $this->ldapWrapper->getAttributeForParticularDN($this->dn, 'cn')[0];
		}
		
		return $this->commonName;
	}
}