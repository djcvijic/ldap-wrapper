<?php

namespace Cvl\LDAPWrapper;

class LDAPWrapper {
	const LDAP_ATTRIBUTE_MEMBER_OF = 'memberOf';
	const LDAP_ATTRIBUTE_MEMBER = 'member';
	const LDAP_ATTRIBUTE_MANAGER_OF = 'groupManagerOf';
	const LDAP_ATTRIBUTE_MANAGER = 'groupManager';
	const LDAP_ATTRIBUTE_DESCRIPTION = 'description';
	const LDAP_ATTRIBUTE_ACCOUNT_NAME = 'sAMAccountName';
	const LDAP_MATCHING_RULE_BIT_AND = '1.2.840.113556.1.4.803';
	const USER_ACCOUNT_CONTROL_NORMAL_ACCOUNT = 0x200;
	const USER_ACCOUNT_CONTROL_ACCOUNTDISABLE = 0x2;
	const GROUP_TYPE = 0x80000002;

	protected $ldapHost;

	protected $ldapPort;

	protected $ldapDomain;

	protected $ldapUsername;

	protected $ldapPassword;

	protected $baseDN;

	protected $userBaseDNs;

	protected $groupBaseDNs;

	protected $adminGroup;

	protected $newGroupDir;

	protected $newUserDir;

	protected $defaultGroups;

	protected $defaultOfficeGroups;

	protected $ldapconn = null;

	protected $attributesCache = array();

	public function __construct($ldapConfig) {
		$this->ldapHost				= $ldapConfig['host'];
		$this->ldapPort				= $ldapConfig['port'];
		$this->ldapDomain			= $ldapConfig['domain'];
		$this->ldapUsername			= $ldapConfig['group_manager_dn'];
		$this->ldapPassword			= $ldapConfig['group_manager_password'];
		$this->baseDN				= $ldapConfig['base_dn'];
		$this->userBaseDNs			= $ldapConfig['user_directories'];
		$this->groupBaseDNs			= $ldapConfig['group_directories'];
		$this->adminGroup			= $ldapConfig['admin_group_dn'];
		$this->newGroupDir			= $ldapConfig['directory_for_new_groups'];
		$this->newUserDir			= $ldapConfig['directory_for_new_users'];
		$this->defaultGroups		= $ldapConfig['default_groups'];
		$this->defaultOfficeGroups	= $ldapConfig['default_office_groups'];

		if ($ldapConfig['do_login']) {
			$this->login();
		}
	}

	protected function __destruct() {
		$this->disconnect();
	}

	/**
	 * Establishes an LDAP connection.
	 * @param string $userDN
	 * @param string $password
	 * @throws LDAPException
	 */
	protected function login($userDN = null, $password = null) {
		if (!$userDN || !$password) {
			$userDN = $this->ldapUsername;
			$password = $this->ldapPassword;
		}
		if ($this->ldapconn) {
			$this->disconnect();
		}
		$this->ldapconn = ldap_connect($this->ldapHost, $this->ldapPort);
		
		if ($this->ldapconn) {
			ldap_set_option($this->ldapconn, LDAP_OPT_REFERRALS, 0);
			ldap_set_option($this->ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
			
			$ldapBind = ldap_bind($this->ldapconn, $userDN, $password);
			
			if (!$ldapBind) {
				throw new LDAPException("LDAP bind exception: " . ldap_error($this->ldapconn));
			}
		} else {
			throw new LDAPException("LDAP connect exception: " . ldap_error($this->ldapconn));
		}
	}

	/**
	 * Breakes a LDAP connection.
	 */
	protected function disconnect() {
		ldap_close($this->ldapconn);
		$this->ldapconn = null;
	}

	protected function sortEntriesByCommonName(&$entries) {
		usort($entries, function(LDAPEntry $entryA, LDAPEntry $entryB) {
			return strcasecmp($entryA->getCommonName(), $entryB->getCommonName());
		});
	}

	protected function sortUsersByCanModifyGroupThenCommonName(&$users, $groupDN) {
		usort($users, function (LDAPUser $userA, LDAPUser $userB) use ($groupDN) {
			$aCanModify = $this->canModifyGroup($groupDN, $userA->getDN());
			$bCanModify = $this->canModifyGroup($groupDN, $userB->getDN());
			if ($aCanModify != $bCanModify) {
				return ($aCanModify && !$bCanModify) ? -1 : 1;
			}
			return strcasecmp($userA->getCommonName(), $userB->getCommonName());
		});
	}

	public function isValidDN($str) {
		$pattern = '/[\x5c|\*|\(|\)|\x00]/';
		return (preg_match($pattern, $str) === 0);
	}

	public function isValidName($str) {
		$pattern = '/[\x5c|\*|\(|\)|\x00|\,|\/]/';
		return (preg_match($pattern, $str) === 0);
	}

	protected function getAttributeCacheKey($dn, $attributes) {
		$attributesKey = implode('#', $attributes);
		return "$dn#$attributesKey";
	}

	protected function invalidateAttributesCache() {
		$this->attributesCache = [];
	}

	/**
	 * @param string $dn - Distinguished name of entry.
	 * @param array $attributes - Array of strings-attributes which should be fetched for specified dn.
	 * @param bool $forceFetch - If set to true value is not fetched from LDAP and cache is updated
	 * @throws \Exception in a case of error
	 * @return array of strings containing searched attributes;
	 *         <br><b>NOTE:</b> only attributes that actually exist in entry will be fetched.
	 */
	protected function getAttributesForParticularDN($dn, $attributes, $forceFetch = false) {
		$cacheKey = $this->getAttributeCacheKey($dn, $attributes);
		if (!$forceFetch && isset($this->attributesCache[$cacheKey])) {
			return $this->attributesCache[$cacheKey];
		}

		$filter = "distinguishedName=$dn";
		
		$searchResults = ldap_search($this->ldapconn, $this->baseDN, $filter, $attributes);
		
		if (!$searchResults) {
			throw new LDAPException('LDAP search error: ' . ldap_error($this->ldapconn));
		}
		
		$resultEntries = ldap_get_entries($this->ldapconn, $searchResults);
		
		if (!$resultEntries) {
			throw new LDAPException('LDAP get entries error: ' . ldap_error($this->ldapconn));
		}
		
		if (!isset($resultEntries['count']) || $resultEntries['count'] !== 1) {
			return null;
		}

		$this->attributesCache[$cacheKey] = $resultEntries[0];
		return $resultEntries[0];
	}

	/**
	 * @param string $dn
	 * @param string $attribute
	 * @param bool $forceFetch - If set to true value is not fetched from LDAP and cache is updated
	 * @return array of strings representing values for specified attribute, null in case there is no such attribute.
	 */
	public function getAttributeForParticularDN($dn, $attribute, $forceFetch = false) {
		$results = $this->getAttributesForParticularDN($dn, array(
			$attribute
		), $forceFetch);
		
		$attributeLowerCase = strtolower($attribute);
		
		if (!isset($results[$attributeLowerCase])) {
			return null;
		} else {
			$returnValue = $results[$attributeLowerCase];
			unset($returnValue['count']);
			return $returnValue;
		}
	}

	/**
	 * Renames specified dn
	 * 
	 * @param string $dn
	 *        	DN which should be renamed
	 * @param string $newDN
	 *        	New value of dn
	 * @throws LDAPException in a case of error
	 */
	public function renameDN($dn, $newDN) {
		$position = strpos($newDN, ',');
		$parentDN = substr($newDN, $position + 1);
		$newRDN = substr($newDN, 0, $position);

		if (ldap_rename($this->ldapconn, $dn, $newRDN, $parentDN, true)) {
			$info = array();
			// account name should be changed, otherwise old dn of this group could not be used for new ones.
			$info[self::LDAP_ATTRIBUTE_ACCOUNT_NAME] = substr($newRDN, strpos($newRDN, '=') + 1);
			ldap_modify($this->ldapconn, $newDN, $info);
			$this->invalidateAttributesCache();
		} else {
			throw new LDAPException('Ldap rename error: ' . ldap_error($this->ldapconn));
		}
	}

	/**
	 * Changes description of specified dn.
	 * 
	 * @param string $dn        	
	 * @param string $newDescription        	
	 */
	public function changeDescription($dn, $newDescription) {
		$info = array();
		$info[self::LDAP_ATTRIBUTE_DESCRIPTION] = $newDescription;
		ldap_modify($this->ldapconn, $dn, $info);
		$this->invalidateAttributesCache();
	}

	/**
	 * Deletes specified dn.
	 * 
	 * @throws LDAPException in a case of error
	 */
	public function deleteDN($dn) {
		if (!ldap_delete($this->ldapconn, $dn)) {
			throw new LDAPException('Ldap delete error: ' . ldap_error($this->ldapconn));
		}
		$this->invalidateAttributesCache();
	}

	/**
	 * Creates a user in the $newUserDir and adds it to the required groups
	 * @param string $firstName
	 * @param string $lastName
	 * @param string $username
	 * @param string $email
	 * @param string $office
	 * @param string $password
	 * @param boolean $active
	 * @return string The distinguished name of the created user, or null if the operation fails
	 */
	public function createUser($firstName, $lastName, $username, $email, $office, $password, $active) {
		$fullName = $firstName . ' ' . $lastName;
		$info = array(
			'objectClass'						=> array(
													'top',
													'person',
													'organizationalPerson',
													'user',
												),
			'givenName'							=> $firstName,
			'sn'								=> $lastName,
			'cn'								=> $fullName,
			'displayName'						=> $fullName,
			self::LDAP_ATTRIBUTE_DESCRIPTION	=> $fullName,
			self::LDAP_ATTRIBUTE_ACCOUNT_NAME	=> $username,
			'userPrincipalName'					=> $username . '@' . $this->ldapDomain,
			'mail'								=> $email,
			'unicodePwd'						=> iconv('UTF-8', 'UTF-16LE', '"' . $password . '"'),
			'pwdLastSet'						=> '0',
			'physicalDeliveryOfficeName'		=> $office,
			'userAccountControl'				=> self::USER_ACCOUNT_CONTROL_NORMAL_ACCOUNT,
		);
		if (!$active) {
			$info['userAccountControl'] = $info['userAccountControl'] | self::USER_ACCOUNT_CONTROL_ACCOUNTDISABLE;
		}
		$dn = "CN=$fullName,$this->newUserDir";
		if (!@ldap_add($this->ldapconn, $dn, $info)) {
			error_log('Error creating user in LDAP: ' . ldap_error($this->ldapconn));
			return null;
		}
		$groupsToJoin = $this->defaultGroups;
		$groupsToJoin[] = $this->defaultOfficeGroups[$office];
		foreach ($groupsToJoin as $groupDN) {
			$this->addMemberToGroup($dn, $groupDN);
		}
		return $dn;
	}

	/**
	 * Edits the user with the given $userDN
	 * @param string $currentUsername
	 * @param string $firstName
	 * @param string $lastName
	 * @param string $username
	 * @param string $email
	 * @param string $office
	 * @param boolean $active
	 * @return string The new distinguished name, or null if the operation fails
	 */
	public function editUser($currentUsername, $firstName, $lastName, $username, $email, $office, $active) {
		try {
			$currentDN = $this->getUserDNByUsername($currentUsername);
		} catch (LDAPException $e) {
			error_log('Error searching for user in LDAP: ' . $e->getMessage());
			return null;
		}
		$fullName = $firstName . ' ' . $lastName;
		$newDN = "CN=$fullName,$this->newUserDir";
		if ($currentDN != $newDN) {
			if (!@ldap_rename($this->ldapconn, $currentDN, "CN=$fullName", $this->newUserDir, true)) {
				error_log('Error renaming user in LDAP: ' . ldap_error($this->ldapconn));
				return null;
			}
		}
		$info = array(
			'givenName'							=> $firstName,
			'sn'								=> $lastName,
			'displayName'						=> $fullName,
			self::LDAP_ATTRIBUTE_DESCRIPTION	=> $fullName,
			self::LDAP_ATTRIBUTE_ACCOUNT_NAME	=> $username,
			'userPrincipalName'					=> $username . '@' . $this->ldapDomain,
			'mail'								=> $email,
			'physicalDeliveryOfficeName'		=> $office,
			'userAccountControl'				=> self::USER_ACCOUNT_CONTROL_NORMAL_ACCOUNT,
		);
		if (!$active) {
			$info['userAccountControl'] = $info['userAccountControl'] | self::USER_ACCOUNT_CONTROL_ACCOUNTDISABLE;
		}
		if (!@ldap_modify($this->ldapconn, $newDN, $info)) {
			error_log('Error modifying user in LDAP: ' . ldap_error($this->ldapconn));
			return null;
		}
		$this->invalidateAttributesCache();
		return $newDN;
	}

	/**
	 *
	 * @param string $name
	 *        	Name of the group
	 * @return string|null Returns DN of newly created group on success or NULL on failure.
	 */
	public function createGroup($name, $description = null) {
		$info['cn'] = $name;
		$info['objectClass'][0] = 'top';
		$info['objectClass'][1] = 'group';
		$info['groupType'] = self::GROUP_TYPE;
		$info[self::LDAP_ATTRIBUTE_ACCOUNT_NAME] = $name;
		if (!empty($description)) {
			$info[self::LDAP_ATTRIBUTE_DESCRIPTION] = $description;
		}

		$dn = "CN=$name,$this->newGroupDir";

		if (ldap_add($this->ldapconn, $dn, $info)) {
			return $dn;
		} else {
			return null;
		}
	}

	/**
	 *
	 * @param string $commonName
	 *        	User common name
	 * @throws LDAPException in a case of error
	 * @return string DN of user with provided common name.
	 */
	public function getUserDNByCommonName($commonName) {
		$filter = "(&(objectCategory=person)(cn=$commonName))";

		$searchResults = ldap_search($this->ldapconn, $this->baseDN, $filter, array(
			'dn'
		));

		if (!$searchResults) {
			throw new LDAPException('User with provided common name does not exist');
		}

		$resultEntries = ldap_get_entries($this->ldapconn, $searchResults);

		if (!$resultEntries || !isset($resultEntries['count']) || $resultEntries['count'] === 0) {
			throw new LDAPException('User with provided common name does not exist');
		}

		if (!$resultEntries || !isset($resultEntries['count']) || $resultEntries['count'] > 1) {
			throw new LDAPException('There are multiple users with provided common name');
		}

		return $resultEntries[0]['dn'];
	}

	/**
	 *
	 * @param string $username
	 *        	User's username
	 * @throws LDAPException in a case of error
	 * @return string DN of user with provided username.
	 */
	public function getUserDNByUsername($username) {
		$filter = "(&(objectCategory=person)(" . self::LDAP_ATTRIBUTE_ACCOUNT_NAME . "=$username" . "))";

		$searchResults = ldap_search($this->ldapconn, $this->baseDN, $filter, array(
			'dn'
		));

		if (!$searchResults) {
			throw new LDAPException('User with provided username does not exist');
		}

		$resultEntries = ldap_get_entries($this->ldapconn, $searchResults);

		if (!$resultEntries || !isset($resultEntries['count']) || $resultEntries['count'] === 0) {
			throw new LDAPException('User with provided username does not exist');
		}

		if (!$resultEntries || !isset($resultEntries['count']) || $resultEntries['count'] > 1) {
			throw new LDAPException('There are multiple users with provided username');
		}

		return $resultEntries[0]['dn'];
	}

	/**
	 * @deprecated please use isEffectiveGroupMember method
	 * @param string $groupDN
	 * @param string $userDN
	 * @return boolean|bool whether specified user is member of specified group
	 */
	public function isGroupMember($groupDN, $userDN) {
		return $this->isEffectiveGroupMember($groupDN, $userDN);
	}

	/**
	 * Recursively check if user is member of given group or any nested one within it
	 *
	 * @param string $groupDN
	 * @param string $userDN
	 * @return boolean|bool whether specified user is member of specified group
	 */
	public function isEffectiveGroupMember($groupDN, $userDN) {
		$attribute = $this->getAttributeForParticularDN($groupDN, self::LDAP_ATTRIBUTE_MEMBER);

		if ($attribute === null) {
			return false;
		}

		if (in_array($userDN, $attribute)) return true;

		$nestedGroupArray = $this->filterDNs($attribute, $this->groupBaseDNs);
		foreach ($nestedGroupArray as $nestedGroupDN) {
			if ($this->isEffectiveGroupMember($nestedGroupDN, $userDN)) return true;
		}

		return false;
	}

	/**
	 * @param string $groupDN
	 * @param string $userDN
	 * @return boolean|bool whether specified user is member of specified group
	 */
	public function isDirectGroupMember($groupDN, $userDN) {
		$attribute = $this->getAttributeForParticularDN($groupDN, self::LDAP_ATTRIBUTE_MEMBER);

		if ($attribute === null) {
			return false;
		}

		return in_array($userDN, $attribute);
	}

	/**
	 *
	 * @param string $groupDN        	
	 * @param string $userDN        	
	 * @return boolean|bool whether specified user is manager of specified group
	 */
	public function isGroupManager($groupDN, $userDN) {
		$attribute = $this->getAttributeForParticularDN($groupDN, self::LDAP_ATTRIBUTE_MANAGER);

		if ($attribute === null) {
			return false;
		}

		return in_array($userDN, $attribute);
	}

	public function isAdmin($userDN) {
		return $this->isEffectiveGroupMember($this->adminGroup, $userDN);
	}

	/**
	 * @param $userDN
	 * @return bool whether specified user is disabled or not (works only with ActiveDirectory, otherwise returns false)
	 */
	public function isUserDisabled($userDN) {
		$attribute = $this->getAttributeForParticularDN($userDN, 'UserAccountControl');

		if ($attribute === null && !isset($attribute[0])) {
			return false;
		}

		$attribute = intval($attribute[0]);

		return ($attribute & self::USER_ACCOUNT_CONTROL_ACCOUNTDISABLE) !== 0;
	}

	/**
	 *
	 * @param string $groupDN        	
	 * @param string $userDN        	
	 * @return boolean|bool whether specified user can modify specified group
	 */
	public function canModifyGroup($groupDN, $userDN) {
		if ($this->isAdmin($userDN)) {
			return true;
		}
		
		return $this->isGroupManager($groupDN, $userDN);
	}

	/**
	 * Filters $dns by eliminating those dns that are not on the paths specified by $filter
	 *
	 * @param array $dns
	 *        	- array of DNs
	 * @param array $filter
	 *        	- array of DNs representing paths that should serve as filter
	 */
	protected function filterDNs($dns, $filter) {
		if (empty($dns)) {
			return;
		}
		
		foreach ($dns as $index => $dn) {
			$regularDN = false;
			foreach ($filter as $baseDN) {
				if (strpos($dn, $baseDN) !== false) {
					$regularDN = true;
					break;
				}
			}
			
			if (!$regularDN) {
				unset($dns[$index]);
			}
		}

		return $dns;
	}

	/**
	 *
	 * @param string $userDN
	 *        	Distinguished name of member
	 * @param bool $sort
	 *        	Whether resulting array should be sorted
	 * @return array of LDAPGroup objects representing groups which user is member of, null if user is not member of any group.
	 */
	public function getGroupsUserIsMemberOf($userDN, $sort = true) {
		$groupsArray = $this->getAttributeForParticularDN($userDN, self::LDAP_ATTRIBUTE_MEMBER_OF);
		return $this->groupDNsToGroupsFilteredAndSorted($groupsArray, $sort);
	}

	/**
	 *
	 * @param string $userDN
	 *        	Distinguished name of member
	 * @return array of LDAPGroup objects representing groups which user is manager of, null if user is not manager of any group.
	 */
	public function getGroupsUserIsManagerOf($userDN, $sort = true) {
		$groupsArray = $this->getAttributeForParticularDN($userDN, self::LDAP_ATTRIBUTE_MANAGER_OF);
		return $this->groupDNsToGroupsFilteredAndSorted($groupsArray, $sort);
	}

	/**
	 * @param bool $sort
	 * @return array|null
	 */
	public function getAllGroups($sort = true) {
		$groupDNs = $this->getAllGroupDNs();
		return $this->groupDNsToGroupsFilteredAndSorted($groupDNs, $sort);
	}

	/**
	 *
	 * @param string $userDN
	 *        	Distinguished name of user
	 * @return array of LDAPGroup objects representing groups which user can modify, null if user cannot modify any group
	 */
	public function getGroupsUserCanModify($userDN, $sort = true) {
		if ($this->isAdmin($userDN)) {
			return $this->getAllGroups($sort);
		} else {
			return $this->getGroupsUserIsManagerOf($userDN, $sort);
		}
	}

	/**
	 * @param $groupDns
	 * @param $sort
	 * @return array|null
	 */
	protected function groupDNsToGroupsFilteredAndSorted($groupDns, $sort) {
		$groupDns = $this->filterDNs($groupDns, $this->groupBaseDNs);
		if (empty($groupDns)) {
			return null;
		}
		$groups = array();
		foreach ($groupDns as $groupDN) {
			$groups[] = new LDAPGroup($this, $groupDN);
		}
		if ($sort) {
			$this->sortEntriesByCommonName($groups);
		}
		return $groups;
	}

	/**
	 * @deprecated Use getAllUserTypeMembersOfGroup
	 *
	 * @param string $groupDN
	 * @param bool $sort
	 * @return array of LDAPUser objects representing members of the specified group, NULL if there are no members in group.
	 */
	public function getMembersOfGroup($groupDN, $sort = true) {
		return $this->getAllUserTypeMembersOfGroup($groupDN, $sort);
	}

	/**
	 * Recursively get user type members from specified group and all nested groups within it
	 *
	 * @param string $groupDN
	 * @param bool $sort
	 * @return array of LDAPUser objects representing members of the specified group, NULL if there are no members in group.
	 */
	public function getAllUserTypeMembersOfGroup($groupDN, $sort = true) {
		$allUsersArray = array();

		$directUsersArray = $this->getDirectUserTypeMembersOfGroup($groupDN, false);

		if ($directUsersArray != null) {
			$allUsersArray = $directUsersArray;
		}

		$nestedGroupsArray = $this->getDirectGroupTypeMembersOfGroup($groupDN);

		if (!empty($nestedGroupsArray)) {
			$unprocessedSet = [];
			$finishedSet = [];

			foreach ($nestedGroupsArray as $nestedGroup) {
				$unprocessedSet[$nestedGroup->getDN()] = $nestedGroup;
			}

			while (!empty($unprocessedSet)) {
				/** @var LDAPGroup $currentGroup */
				$currentGroup = array_shift($unprocessedSet);
				$finishedSet[$currentGroup->getDN()] = $currentGroup;

				$directUsersArrayOfCurrentGroup = $currentGroup->getDirectUserTypeMembers();
				if (!empty($directUsersArrayOfCurrentGroup)) {
					$allUsersArray = array_merge($allUsersArray, $directUsersArrayOfCurrentGroup);
				}

				$directGroupsArrayOfCurrentGroup = $currentGroup->getDirectGroupTypeMembers();
				if (!empty($directGroupsArrayOfCurrentGroup)) {
					foreach ($directGroupsArrayOfCurrentGroup as $directGroupOfCurrentGroup) {
						/** @var LDAPGroup $directGroupOfCurrentGroup */
						if (empty($finishedSet[$directGroupOfCurrentGroup->getDN()])) {
							$unprocessedSet[$directGroupOfCurrentGroup->getDN()] = $directGroupOfCurrentGroup;
						}
					}
				}
			}
		}

		if (empty($allUsersArray)) {
			return null;
		}

		$allUsersArray = array_unique($allUsersArray);

		if ($sort) {
			$this->sortUsersByCanModifyGroupThenCommonName($allUsersArray, $groupDN);
		}

		return $allUsersArray;
	}

	/**
	 * @param string $groupDN
	 * @param bool $sort
	 * @return array of LDAPUser objects representing direct user members of the specified group,
	 *                  NULL if there are no direct user type members in group.
	 */
	public function getDirectUserTypeMembersOfGroup($groupDN, $sort = true) {
		$directMemberDnsArray = $this->getAttributeForParticularDN($groupDN, self::LDAP_ATTRIBUTE_MEMBER);
		$directUserTypeDnsArray = $this->filterDNs($directMemberDnsArray, $this->userBaseDNs);

		if ($directUserTypeDnsArray == null) {
			return null;
		}

		$userTypeMembersArray = array();

		foreach ($directUserTypeDnsArray as $userMemberDN) {
			$userTypeMembersArray[] = new LDAPUser($this, $userMemberDN);
		}

		if ($sort) {
			$this->sortUsersByCanModifyGroupThenCommonName($userTypeMembersArray, $groupDN);
		}

		return $userTypeMembersArray;
	}

	/**
	 * @param string $groupDN
	 * @return array of LDAPGroup objects representing direct group members of the specified group,
	 *                  NULL if there are no direct group type members in group.
	 */
	public function getDirectGroupTypeMembersOfGroup($groupDN) {
		$directMemberDnsArray = $this->getAttributeForParticularDN($groupDN, self::LDAP_ATTRIBUTE_MEMBER);
		$directGroupTypeDnsArray = $this->filterDNs($directMemberDnsArray, $this->groupBaseDNs);

		if ($directGroupTypeDnsArray == null) {
			return null;
		}

		$groupTypeMembersArray = array();

		foreach ($directGroupTypeDnsArray as $groupMemberDN) {
			$groupTypeMembersArray[] = new LDAPGroup($this, $groupMemberDN);
		}

		return $groupTypeMembersArray;
	}

	/**
	 *
	 * @param string $groupDN        	
	 * @return array of LDAPUser objects representing managers of the specified group, NULL if there are no managers in group.
	 */
	public function getManagersOfGroup($groupDN, $sort = true) {
		$managersArray = $this->getAttributeForParticularDN($groupDN, self::LDAP_ATTRIBUTE_MANAGER);
		$this->filterDNs($managersArray, $this->userBaseDNs);
		
		if ($managersArray == null) {
			return null;
		}

		$managers = array();
		foreach ($managersArray as $memberDN) {
			$managers[] = new LDAPUser($this, $memberDN);
		}
		
		if ($sort) {
			$this->sortEntriesByCommonName($managers);
		}
		
		return $managers;
	}

	public function getNumberOfManagersInGroup($groupDN) {
		return count($this->getManagersOfGroup($groupDN));
	}

	protected function getAllGroupDNs() {
		$filter = 'objectClass=group';
		
		$attributes = array(
			'dn'
		);
		
		$groups = null;
		
		foreach ($this->groupBaseDNs as $groupDN) {
			$searchResults = ldap_search($this->ldapconn, $groupDN, $filter, $attributes);
			
			if (!$searchResults) {
				return null;
			}
			
			$resultEntries = ldap_get_entries($this->ldapconn, $searchResults);
			
			if (!$resultEntries) {
				return null;
			}
			
			for($i = 0; $i < $resultEntries['count']; $i++) {
				// to show the attribute displayName (note the case!)
				$groups[] = $resultEntries[$i]['dn'];
			}
		}
		
		return $groups;
	}

	/**
	 *
	 * @param bool $includeDisabled - Includes disabled users. (can be used only with ActiveDirectory)
	 * @return array of LDAPUser objects representing all users that are on userBaseDNs path, null if there are no such users.
	 */
	public function getAllUsers($includeDisabled = true) {
		$isPerson = 'objectCategory=person';
		if ($includeDisabled) {
			$filter = $isPerson;
		} else {
			$isDisabled = 'UserAccountControl:' . self::LDAP_MATCHING_RULE_BIT_AND . ':=' . self::USER_ACCOUNT_CONTROL_ACCOUNTDISABLE;
			$filter = "(&($isPerson)(!($isDisabled)))";
		}
		
		$attributes = array(
			'dn'
		);
		
		$users = null;
		
		foreach ($this->userBaseDNs as $baseDN) {
			$searchResults = ldap_search($this->ldapconn, $baseDN, $filter, $attributes);
			
			if (!$searchResults) {
				return null;
			}
			
			$resultEntries = ldap_get_entries($this->ldapconn, $searchResults);
			
			if (!$resultEntries) {
				return null;
			}
			
			for($i = 0; $i < $resultEntries['count']; $i++) {
				// to show the attribute displayName (note the case!)
				$users[] = new LDAPUser($this, $resultEntries[$i]['dn']);
			}
		}
		
		return $users;
	}

	/**
	 * Adds member to group
	 *
	 * @param string $memberDN        	
	 * @param string $groupDN        	
	 */
	public function addMemberToGroup($memberDN, $groupDN) {
		/*
		 * When adding/editing attributes for a user, the 'memberof' attribute is a special case.
		 * The memberOf attribute is not an accessible attribute of the user schema.
		 * To add someone to a group, you have to add the user in the group, and not the group in the user.
		 * You can do this by accessing the group attribute 'member':
		 */
		if (!$this->isDirectGroupMember($groupDN, $memberDN)) {
			ldap_mod_add($this->ldapconn, $groupDN, array(
				self::LDAP_ATTRIBUTE_MEMBER => $memberDN
			));
		}
		$this->invalidateAttributesCache();
	}

	/**
	 * Adds manager to group
	 *
	 * @param string $memberDN        	
	 * @param string $groupDN        	
	 */
	public function addManagerToGroup($memberDN, $groupDN) {
		$this->addMemberToGroup($memberDN, $groupDN);

		if (!$this->isGroupManager($groupDN, $memberDN)) {
			ldap_mod_add($this->ldapconn, $groupDN, array(
				self::LDAP_ATTRIBUTE_MANAGER => $memberDN
			));
			ldap_mod_add($this->ldapconn, $memberDN, array(
				self::LDAP_ATTRIBUTE_MANAGER_OF => $groupDN
			));
		}

		$this->invalidateAttributesCache();
	}

	/**
	 * Removes user from group
	 *
	 * @param string $memberDN        	
	 * @param string $groupDN        	
	 */
	public function removeUserFromGroup($memberDN, $groupDN) {
		if ($this->isGroupManager($groupDN, $memberDN)) {
			ldap_mod_del($this->ldapconn, $groupDN, array(
				self::LDAP_ATTRIBUTE_MANAGER => $memberDN
			));
			ldap_mod_del($this->ldapconn, $memberDN, array(
				self::LDAP_ATTRIBUTE_MANAGER_OF => $groupDN
			));
		}
		if ($this->isDirectGroupMember($groupDN, $memberDN)) {
			ldap_mod_del($this->ldapconn, $groupDN, array(
				self::LDAP_ATTRIBUTE_MEMBER => $memberDN
			));
		}
		$this->invalidateAttributesCache();
	}

	/**
	 * Removes manager rights of user over group
	 * Requires: User has manager rights over group, otherwise function does not have effects
	 *
	 * @param string $memberDN        	
	 * @param string $groupDN        	
	 */
	public function removeManagerRights($memberDN, $groupDN) {
		if ($this->isGroupManager($groupDN, $memberDN)) {
			ldap_mod_del($this->ldapconn, $groupDN, array(
				self::LDAP_ATTRIBUTE_MANAGER => $memberDN
			));
			ldap_mod_del($this->ldapconn, $memberDN, array(
				self::LDAP_ATTRIBUTE_MANAGER_OF => $groupDN
			));
		}
		$this->invalidateAttributesCache();
	}

	/**
	 * Adds manager rights to user over group
	 * Requires: User is member of a specified group, otherwise unpredicted errors could occur
	 *
	 * @param string $memberDN        	
	 * @param string $groupDN        	
	 */
	public function addManagerRights($memberDN, $groupDN) {
		if (!$this->isGroupManager($groupDN, $memberDN)) {
			ldap_mod_add($this->ldapconn, $groupDN, array(
				self::LDAP_ATTRIBUTE_MANAGER => $memberDN
			));
			ldap_mod_add($this->ldapconn, $memberDN, array(
				self::LDAP_ATTRIBUTE_MANAGER_OF => $groupDN
			));
		}
		$this->invalidateAttributesCache();
	}
}