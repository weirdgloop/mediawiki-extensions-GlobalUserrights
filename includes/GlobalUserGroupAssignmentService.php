<?php
/**
 * @license GPL-2.0-or-later
 * @file
 * @author Nathaniel Herman <redwwjd@yahoo.com>
 * @copyright Copyright © 2008 Nathaniel Herman
 * @note Some of the code based on stuff by Lukasz 'TOR' Garczewski, as well as SpecialUserrights.php and CentralAuth
 */

use MediaWiki\Logging\ManualLogEntry;
use MediaWiki\Permissions\Authority;
use MediaWiki\Title\Title;
use MediaWiki\User\CentralId\CentralIdLookupFactory;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserGroupAssignmentService;
use MediaWiki\User\UserGroupManagerFactory;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserNameUtils;

/**
 * This class represents a service that provides high-level operations on user groups.
 * Contrary to UserGroupManager, this class is not interested in details of how user groups
 * are stored or defined, but rather in the business logic of assigning and removing groups.
 *
 * Therefore, it combines group management with logging and provides permission checks.
 * Additionally, the method interfaces are designed to be suitable for calls from user-facing code.
 *
 * @since 1.45
 * @ingroup User
 */
class GlobalUserGroupAssignmentService {

	public function __construct(
		private readonly CentralIdLookupFactory $centralIdLookupFactory,
		private readonly UserGroupManagerFactory $userGroupManagerFactory,
		private readonly UserNameUtils $userNameUtils,
		private readonly UserFactory $userFactory,
	) {

	}

	/**
	 * Checks whether the target user can have groups assigned at all.
	 */
	public function targetCanHaveUserGroups( UserIdentity $target ): bool {
		// Basic stuff - don't assign groups to anons and temp. accounts
		if ( !$target->isRegistered() ) {
			return false;
		}
		if ( $this->userNameUtils->isTemp( $target->getName() ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Check whether the given user can change the target user's rights.
	 *
	 * @param Authority $performer User who is attempting to change the target's rights
	 * @param UserIdentity $target User whose rights are being changed
	 */
	public function userCanChangeRights( Authority $performer, UserIdentity $target ): bool {
		if ( !$this->targetCanHaveUserGroups( $target ) ) {
			return false;
		}

		// changeableGroups already checks for self-assignments, so no need to do that here.
		$available = $this->getChangeableGroups( $performer, $target );
		if ( $available['add'] || $available['remove'] ) {
			return true;
		}
		return false;
	}

	/**
	 * Returns the groups that the performer can add or remove from the target user.
	 * @return array [
	 *   'add' => [ addablegroups ],
	 *   'remove' => [ removablegroups ],
	 *   'restricted' => [ groupname => [
	 *     'condition-met' => bool,
	 *     'ignore-condition' => bool,
	 *     'message' => string
	 *   ] ]
	 *  ]
	 * @phan-return array{add:list<string>,remove:list<string>,restricted:array<string,array>}
	 */
	public function getChangeableGroups( Authority $performer, UserIdentity $target ): array {
		$groups = [
			'add' => [],
			'remove' => [],
			'restricted' => [],
		];

		if ( $performer->isAllowed( 'userrights-global' ) ) {
			// all groups can be added globally
			$all = array_merge( $this->userGroupManagerFactory->getUserGroupManager()->listAllGroups() );
			$groups['add'] = $all;
			$groups['remove'] = $all;
		}

		return $groups;
	}

	/**
	 * Add a user to a group
	 *
	 * @param int $uid central Id
	 * @param string $group name of the group to add
	 * @param string|null $expiry expiration of the group membership
	 * @return bool
	 */
	private function addGroup( $uid, $group, $expiry = null ) {
		if ( $expiry ) {
			$expiry = wfTimestamp( TS_MW, $expiry );
		}

		$gugm = new GlobalUserGroupMembership( $uid, $group, $expiry );
		if ( !$gugm->insert( true ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Removes a user from a group
	 *
	 * @param int $uid central Id
	 * @param string $group name of the group
	 * @return bool
	 */
	private function removeGroup( $uid, $group ) {
		$gugm = new GlobalUserGroupMembership( $uid, $group );

		if ( !$gugm || !$gugm->delete() ) {
			return false;
		}

		return true;
	}

	/**
	 * Changes the user groups, ensuring that the performer has the necessary permissions
	 * and that the changes are logged.
	 *
	 * @param Authority $performer
	 * @param UserIdentity $target
	 * @param list<string> $addGroups The groups to add (or change expiry of)
	 * @param list<string> $removeGroups The groups to remove
	 * @param array<string, ?string> $newExpiries Map of group name to new expiry (string timestamp or null
	 *   for infinite). If a group is in $addGroups but not in this array, it won't expire.
	 * @param string $reason
	 * @param array $tags
	 * @return array{0:string[],1:string[]} The groups actually added and removed
	 */
	public function saveChangesToUserGroups(
		Authority $performer,
		UserIdentity $target,
		array $addGroups,
		array $removeGroups,
		array $newExpiries,
		string $reason = '',
		array $tags = []
	): array {
		$uid = $this->centralIdLookupFactory->getLookup()->centralIdFromLocalUser( $target );

		$oldGroupMemberships = GlobalUserrightsHooks::getGroupMemberships( $uid );
		$changeable = $this->getChangeableGroups( $performer, $target );
		UserGroupAssignmentService::enforceChangeGroupPermissions( $addGroups, $removeGroups, $newExpiries,
			$oldGroupMemberships, $changeable );

		// Remove groups, then add new ones/update expiries of existing ones
		foreach ( $removeGroups as $index => $group ) {
			if ( !$this->removeGroup( $uid, $group ) ) {
				unset( $removeGroups[$index] );
			}
		}
		foreach ( $addGroups as $index => $group ) {
			$expiry = $newExpiries[$group] ?? null;
			if ( !$this->addGroup( $uid, $group, $expiry, true ) ) {
				unset( $addGroups[$index] );
			}
		}
		$newGroupMemberships = GlobalUserrightsHooks::getGroupMemberships( $uid );

		// Ensure that caches are cleared
		$this->userFactory->invalidateCache( $target );

		// Only add a log entry if something actually changed
		if ( $newGroupMemberships != $oldGroupMemberships ) {
			$this->addLogEntry( $performer->getUser(), $target, $reason, $tags, $oldGroupMemberships,
				$newGroupMemberships );
		}

		return [ $addGroups, $removeGroups ];
	}

	/**
	 * Add a rights log entry for an action.
	 * @param UserIdentity $performer
	 * @param UserIdentity $target
	 * @param string $reason
	 * @param string[] $tags Change tags for the log entry
	 * @param array<string,UserGroupMembership> $oldUGMs Associative array of (group name => UserGroupMembership)
	 * @param array<string,UserGroupMembership> $newUGMs Associative array of (group name => UserGroupMembership)
	 */
	private function addLogEntry( UserIdentity $performer, UserIdentity $target, string $reason,
		array $tags, array $oldUGMs, array $newUGMs
	) {
		ksort( $oldUGMs );
		ksort( $newUGMs );
		$oldUGMs = array_map( static fn ( $ugm ) => self::serialiseUgmForLog( $ugm ), $oldUGMs );
		$oldGroups = array_keys( $oldUGMs );
		$oldUGMs = array_values( $oldUGMs );
		$newUGMs = array_map( static fn ( $ugm ) => self::serialiseUgmForLog( $ugm ), $newUGMs );
		$newGroups = array_keys( $newUGMs );
		$newUGMs = array_values( $newUGMs );

		$logEntry = new ManualLogEntry( 'gblrights', 'rights' );
		$logEntry->setPerformer( $performer );
		$logEntry->setTarget( Title::makeTitle( NS_USER, $target->getName() ) );
		$logEntry->setComment( $reason );
		$logEntry->setParameters( [
			'4::oldgroups' => $oldGroups,
			'5::newgroups' => $newGroups,
			'oldmetadata' => $oldUGMs,
			'newmetadata' => $newUGMs,
		] );
		$logId = $logEntry->insert();
		$logEntry->addTags( $tags );
		$logEntry->publish( $logId );
	}

	/**
	 * Serialise a UserGroupMembership object for storage in the log_params section
	 * of the logging table. Only keeps essential data, removing redundant fields.
	 */
	private static function serialiseUgmForLog( UserGroupMembership $ugm ): array {
		return [ 'expiry' => $ugm->getExpiry() ];
	}
}
