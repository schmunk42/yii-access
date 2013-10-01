<?php
/**
 */

class PhAccessBehavior extends CActiveRecordBehavior
{

    const ALL_DOMAINS    = '*';
    const APP_LANGUAGE   = '!';
    const SUPERUSER_ROLE = 'Superuser';

    /**
     * Name of the internal (parent-)child relation
     * set to `!` if a record should be automatically created
     * with the current application language
     * @var type
     */
    public $defaultDomain = self::ALL_DOMAINS;

    /**
     * Roles to use for checkAccess columns on create
     * @var type
     */
    public $defaultRoles = array(
        'defaultRoleRead'   => null,
        'defaultRoleCreate' => null,
        'defaultRoleUpdate' => null,
        'defaultRoleDelete' => null,
    );

    /**
     * @var
     */
    public $superuserRole = self::SUPERUSER_ROLE;

    /**
     * Named scope for records the user can read
     * @return mixed
     */
    public function appendable()
    {
        $this->Owner->getDbCriteria()->mergeWith($this->createAccessCriteria('access_append'));
        return $this->Owner;
    }

    /**
     * Named scope for records the user can read
     * @return mixed
     */
    public function readable()
    {
        $this->Owner->getDbCriteria()->mergeWith($this->createAccessCriteria('access_read'));
        return $this->Owner;
    }

    /**
     * Named scope for records the user can update
     * @return mixed
     */
    public function updateable()
    {
        $this->Owner->getDbCriteria()->mergeWith($this->createAccessCriteria('access_update'));
        return $this->Owner;
    }

    /**
     * Named scope for records the user can delete
     * @return mixed
     */
    public function deleteable()
    {
        $this->Owner->getDbCriteria()->mergeWith($this->createAccessCriteria('access_delete'));
        return $this->Owner;
    }

    /**
     * Whether an record can be appended to this record by the current user
     * @return boolean
     */
    public function isAppendable()
    {
        return Yii::app()->user->checkAccess($this->owner->access_create);
    }

    /**
     * Whether the record can be read by the current user
     * @return boolean
     */
    public function isReadable()
    {
        return Yii::app()->user->checkAccess($this->owner->access_read);
    }


    /**
     * Whether the record can be updated by the current user
     * @return boolean
     */
    public function isUpdateable()
    {
        return Yii::app()->user->checkAccess($this->owner->access_update);
    }

    /**
     * Whether the record can be deleted by the current user
     * @return boolean
     */
    public function isDeleteable()
    {
        return Yii::app()->user->checkAccess($this->owner->access_delete);
    }

    /**
     * Named scope for records in a specific language
     * @return mixed
     */
    public function localized($language = null, $strict = false)
    {
        if ($language === null) {
            $language = Yii::app()->language;
        }

        $condition = "(access_domain = :language";

        if ($strict === false) {
            $condition .= " OR access_domain= '" . self::ALL_DOMAINS . "')";
        } else {
            $condition .= ")";
        }

        $this->Owner->getDbCriteria()->mergeWith(
            array(
                 'condition' => $condition,
                 'params'    => array(':language' => $language)
            )
        );
        return $this->Owner;
    }

    /**
     * Checks if the user has delete permissions for the current record
     *
     * @param type $event
     *
     * @return type
     */
    public function beforeDelete($event)
    {
        parent::beforeDelete($event);
        if ($this->owner->access_delete && Yii::app()->user->checkAccess($this->owner->access_delete) === false) {
            throw new CHttpException(403, "You are not authorized to delete this record.");
            return false;
        } else {
            return true;
        }
    }

    /**
     * Sets cache entries
     *
     * @param type $event
     *
     * @return type
     */
    public function afterDelete($event)
    {
        Yii::app()->setGlobalState(
            'p3extensions.behaviors.PhAccessBehavior:lastDelete:' . $this->owner->tableSchema->name,
            microtime(true)
        );
        return true;
    }


    public function beforeValidate($event)
    {
        parent::beforeValidate($event);
        // running in console app - no automatic saving
        if (Yii::app() instanceof CConsoleApplication) {
            Yii::log('PhAccessBehavior assumes user.id:1 with no primary role.', CLogger::LEVEL_INFO);
            $userId      = 1;
            $primaryRole = null;
        } else {
            $userId       = Yii::app()->user->id;
            $defaultRoles = $this->resolveDefaultRoles();
        }

        if (isset($this->owner->access_domain)) {
            if ($this->defaultDomain === self::APP_LANGUAGE) {
                $this->defaultDomain = Yii::app()->language;
            }
            if (!$this->owner->access_domain) {
                $this->owner->access_domain = $this->defaultDomain;
            }
        }

        // TODO create new record or just update modifiedBy/At columns
        if ($this->owner->isNewRecord) {
            $model = $this->owner;
            if (!$model->access_owner) {
                $model->access_owner = $userId;
            }
        }

        return true;
    }

    /**
     * Checks if the user has update permissions for the current record
     *
     * @param type $event
     *
     * @return type
     */
    public function beforeSave($event)
    {
        parent::beforeSave($event);

        // exist in console app - no automatic saving
        if (Yii::app() instanceof CConsoleApplication) {
            Yii::log('PhAccessBehavior omitted in console application.', CLogger::LEVEL_INFO);
            return true;
        }

        // TODO - implement parent create check
        // on update check permission with record from database - not the modified one
        $checkAccess = $this->owner->access_update;
        if ($checkAccess = $this->owner->access_update) {
            if (Yii::app()->user->checkAccess($checkAccess) === false) {
                throw new CHttpException(403, "You are not authorized to update this record.");
                return false;
            }
        }

        return true;
    }


    /**
     *Creates a CDbCriteria with restrics read access
     * @return \CDbCriteria
     */
    private function createAccessCriteria($type)
    {
        $criteria = new CDbCriteria;

        // do not apply filter for superuser
        if (!Yii::app()->user->checkAccess($this->superuserRole)) {
            $tablePrefix = $this->owner->getTableAlias();
            $checkAccessRoles = "";
            if (!Yii::app()->user->isGuest) {
                foreach (Yii::app()->authManager->getRoles(Yii::app()->user->id) AS $role) {
                    $checkAccessRoles .= $tablePrefix . "." . $type . " = '" . $role->name . "' OR ";
                }
            } else {
                $checkAccessRoles .= $tablePrefix . "." . $type . " = 'Guest' OR ";
            }
            $criteria->condition = $checkAccessRoles . " " . $tablePrefix . "." . $type . " IS NULL";
        }

        return $criteria;
    }

    /**
     * Finds role with associated data eg. array('primaryRoleCreate'=>true)
     * Note: Last assignment wins.
     * @return null|string
     */
    private function resolveDefaultRoles()
    {
        $assignments = Yii::app()->authManager->getAuthAssignments(Yii::app()->user->id);
        $roles       = $this->defaultRoles;
        foreach ($assignments AS $assignmentName => $assignment) {
            foreach ($roles AS $roleName => $role) {
                if (isset($assignment->data[$roleName]) && true === $assignment->data[$roleName]) {
                    $roles[$roleName] = $assignmentName;
                }
            }
        }
        return $roles;
    }

}