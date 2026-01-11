<?php

use MediaWiki\MediaWikiServices;

return [

	'GlobalUserrights.GlobalUserGroupAssignmentService' => static function (
		MediaWikiServices $services
	): GlobalUserGroupAssignmentService {
        return new GlobalUserGroupAssignmentService(
            $services->getCentralIdLookupFactory(),
            $services->getUserGroupManagerFactory(),
            $services->getUserNameUtils(),
            $services->getUserFactory(),
        );
	},
];