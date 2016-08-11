(ns metabase.models.permissions-group-test
  (:require [expectations :refer :all]
            [metabase.db :as db]
            (metabase.models [database :refer [Database]]
                             [database-permissions :refer [DatabasePermissions]]
                             [permissions-group :as perm-group]
                             [table :refer [Table]]
                             [user :refer [User]])
            [metabase.test.util :as tu])
  (:import metabase.models.permissions_group.PermissionsGroupInstance))

;;; check that we can get the magic permissions groups through the helper functions
(expect PermissionsGroupInstance (perm-group/default))
(expect PermissionsGroupInstance (perm-group/admin))

(expect "Default" (:name (perm-group/default)))
(expect "Admin"   (:name (perm-group/admin)))


;;; make sure we're not allowed to delete the magic groups
(expect Exception (db/cascade-delete! 'PermissionsGroup :id (:id (perm-group/default))))
(expect Exception (db/cascade-delete! 'PermissionsGroup :id (:id (perm-group/admin))))


;;; make sure we're not allowed to edit the magic groups
(expect Exception (db/update! 'PermissionsGroup (:id (perm-group/default)) :name "Cool People"))
(expect Exception (db/update! 'PermissionsGroup (:id (perm-group/admin))   :name "Cool People"))


;;; newly created users should get added to the appropriate magic groups
(expect
  (tu/with-temp User [{user-id :id}]
    (db/exists? 'PermissionsGroupMembership
                :user_id  user-id
                :group_id (:id (perm-group/default)))))

(expect
  false
  (tu/with-temp User [{user-id :id}]
    (db/exists? 'PermissionsGroupMembership
                :user_id  user-id
                :group_id (:id (perm-group/admin)))))

(expect
  (tu/with-temp User [{user-id :id} {:is_superuser true}]
    (db/exists? 'PermissionsGroupMembership
                :user_id  user-id
                :group_id (:id (perm-group/default)))))

(expect
  (tu/with-temp User [{user-id :id} {:is_superuser true}]
    (db/exists? 'PermissionsGroupMembership
                :user_id  user-id
                :group_id (:id (perm-group/admin)))))


;;; newly created databases should get added to the appropriate magic groups
(expect
  #metabase.models.database_permissions.DatabasePermissionsInstance{:unrestricted_schema_access true
                                                                    :native_query_write_access  true}
  (tu/with-temp Database [{database-id :id}]
    (db/select-one [DatabasePermissions :unrestricted_schema_access :native_query_write_access]
      :group_id    (:id (perm-group/default))
      :database_id database-id)))

(expect
  #metabase.models.database_permissions.DatabasePermissionsInstance{:unrestricted_schema_access true
                                                                    :native_query_write_access  true}
  (tu/with-temp Database [{database-id :id}]
    (db/select-one [DatabasePermissions :unrestricted_schema_access :native_query_write_access]
      :group_id    (:id (perm-group/admin))
      :database_id database-id)))
