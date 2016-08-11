(ns metabase.api.permissions
  "/api/permissions endpoints."
  (:require [clojure.string :as s]
            [compojure.core :refer [GET POST PUT DELETE]]
            [metabase.api.common :refer :all]
            [metabase.db :as db]
            (metabase.models [database :as database]
                             [database-permissions :refer [DatabasePermissions]]
                             [hydrate :refer [hydrate]]
                             [permissions-group :refer [PermissionsGroup], :as group]
                             [permissions-group-membership :refer [PermissionsGroupMembership]]
                             [schema-permissions :refer [SchemaPermissions]]
                             [table :refer [Table]]
                             [table-permissions :refer [TablePermissions]])
            [metabase.util :as u]))

(defn- access-type [db-perms]
  (cond
    (and (:unrestricted_schema_access db-perms)
         (:native_query_write_access db-perms)) :unrestricted
    (:unrestricted_schema_access db-perms)      :all_schemas
    (nil? db-perms)                             :no_access
    :else                                       :some_schemas))


(defn- group-permissions-for-db [database-id group-id]
  (let [db-perms           (db/select-one DatabasePermissions
                             :database_id database-id
                             :group_id    group-id)
        schema-name->perms (u/key-by :schema
                             (when (and db-perms
                                        (not (:unrestricted_schema_access db-perms)))
                               (db/select SchemaPermissions :database_id database-id, :group_id group-id)))
        schema-names       (database/schema-names {:id database-id})]
    (assoc (or db-perms
               {:database_id                database-id
                :group_id                   group-id
                :unrestricted_schema_access false
                :native_query_write_access  false
                :id                         nil})
      :access_type (access-type db-perms)
      :schemas     (for [schema-name schema-names
                         :let        [schema-perms (schema-name->perms schema-name)]]
                     (assoc schema-perms
                       :name        schema-name
                       :access_type (cond
                                      (:unrestricted_schema_access db-perms) :all_tables
                                      schema-perms                           :some_tables
                                      :else                                  :no_access))))))

;; TODO - this is inefficient since it has to make DB calls for *every* DB.
;; Fix this later when I get time.
(defn- group-permissions-for-all-dbs
  "Return a sequence of *all* `Databases` including approriate `DatabasePermissions` for `PermissionsGroup` with GROUP-ID."
  [group-id]
  (for [database (db/select ['Database :id :name])]
    (assoc (group-permissions-for-db (:id database) group-id)
      :name (:name database))))


;;; ---------------------------------------- PermissionsGroup (/api/permissions/group) endpoints ----------------------------------------

;; TODO - should be GET /api/permissions/group
(defendpoint GET "/groups"
  "Fetch all `PermissionsGroups`."
  []
  (check-superuser)
  ;; TODO - this is complicated, should we just do normal queries and hydration here?
  (db/query {:select    [:pg.id :pg.name [:%count.pgm.id :members]]
             :from      [[:permissions_group :pg]]
             :left-join [[:permissions_group_membership :pgm]
                         [:= :pg.id :pgm.group_id]]
             :group-by  [:pg.id :pg.name]
             :order-by  [:%lower.pg.name]}))

(defendpoint POST "/group"
  "Create a new `PermissionsGroup`."
  [:as {{:keys [name]} :body}]
  {name [Required NonEmptyString]}
  (check-superuser)
  (db/insert! PermissionsGroup
    :name name))

;; TODO - should this be moved to `metbabase.models.permission-group`?

(defendpoint GET "/group/:id"
  "Fetch details for a specific `PermissionsGroup`."
  [id]
  (check-superuser)
  (assoc (PermissionsGroup id)
    :members   (group/members {:id id})
    :databases (group-permissions-for-all-dbs id)))

(defendpoint PUT "/group/:id"
  "Update the name of a `PermissionsGroup`."
  [id :as {{:keys [name]} :body}]
  {name [Required NonEmptyString]}
  (check-superuser)
  (check-404 (db/exists? PermissionsGroup :id id))
  (db/update! PermissionsGroup id
    :name name)
  ;; return the updated group
  (PermissionsGroup id))

(defendpoint DELETE "/group/:id"
  "Delete a specific `PermissionsGroup`."
  [id]
  (check-superuser)
  (db/cascade-delete! PermissionsGroup :id id))


;;; ---------------------------------------- PermissionsGroupMembership (api/permissions/membership?) endpoints ----------------------------------------

(defendpoint POST "/membership"
  "Add a `User` to a `PermissionsGroup`. Returns updated list of members belonging to the group."
  [:as {{:keys [group_id user_id]} :body}]
  {group_id [Required Integer]
   user_id  [Required Integer]}
  (check-superuser)
  (db/insert! PermissionsGroupMembership
    :group_id group_id
    :user_id  user_id)
  ;; TODO - it's a bit silly to return the entire list of members for the group, just return the newly created one and let the frontend add it ass appropriate
  (group/members {:id group_id}))

(defendpoint DELETE "/membership/:id"
  "Remove a User from a PermissionsGroup (delete their membership)."
  [id]
  (check-superuser)
  (check-404 (db/exists? PermissionsGroupMembership :id id))
  (db/cascade-delete! PermissionsGroupMembership
    :id id))


;;; ---------------------------------------- Database (/api/permissions/database) endpoints ----------------------------------------

(defendpoint GET "/database/:id"
  "Fetch details about Permissions for a specific `Database`."
  [id]
  (check-superuser)
  (let [group-id->db-permissions (u/key-by :group_id (db/select DatabasePermissions :database_id id))
        ;; TODO - handle schema permissions
        ;; schema-permissions       (db/select SchemaPermissions :database_id id)
        schema-names             (database/schema-names {:id id})
        groups                   (db/select 'PermissionsGroup
                                   {:order-by [:name]})]
    {:id      id
     :schemas (for [schema-name schema-names]
                {:name   schema-name
                 :groups (cons
                          {:name "FAKE", :access nil, :id 100}
                          (for [group groups
                                :let  [db-perms (group-id->db-permissions (:id group))]]
                            (assoc group
                              :access (when (:unrestricted_schema_access db-perms)
                                        "All tables"))))})}))


;;; ---------------------------------------- DatabasePermissions (/api/permissions/database/:id/group/:id) endpoints ----------------------------------------

(defendpoint GET "/database/:database-id/group/:group-id"
  "Get details about the permissions for a specific Group for a specific Database."
  [database-id group-id]
  (check-superuser)
  (group-permissions-for-db database-id group-id))

;; TODO - rename to *PUT* /permissions/database-permissions (?)
(defendpoint POST "/database/:database-id/group/:group-id"
  "Change permissions settings for a specific Group & specific Database."
  [database-id group-id :as {{:keys [access_type schemas]} :body}]
  {access_type [Required NonEmptyString]
   schemas     ArrayOfStrings}
  (check (contains? #{"unrestricted" "all_schemas" "some_schemas" "no_access"} access_type)
    400 "Invalid access type.")
  (if (= access_type "no_access")
    (db/delete! DatabasePermissions
      :database_id database-id
      :group_id    group-id)
    (let [database-permissions (or (db/select-one DatabasePermissions :database_id database-id, :group_id group-id)
                                   (db/insert! DatabasePermissions :database_id database-id, :group_id group-id))]
      ;; TODO - update SchemaPermissions as appropriate
      (case access_type
        "unrestricted" (db/update! DatabasePermissions (:id database-permissions)
                         :unrestricted_schema_access true
                         :native_query_write_access  true)
        "all_schemas"  (db/update! DatabasePermissions (:id database-permissions)
                         :unrestricted_schema_access true
                         :native_query_write_access  false)
        "some_schemas" (db/update! DatabasePermissions (:id database-permissions)
                         :unrestricted_schema_access false
                         :native_query_write_access  false))))
  (group-permissions-for-db database-id group-id))


;;; ---------------------------------------- SchemaPermissions (/api/permissions/database/:id/group/:id/schema/:schema) endpoints ----------------------------------------

;; TODO - this should probably be moved to `metabase.models.schema-permissions/` ?
(defn- add-schema-perms-extra-info [{database-id :database_id, group-id :group_id, schema :schema, :as schema-perms}]
  (let [tables          (db/select ['Table :name :id]
                          :db_id database-id
                          :schema schema
                          {:order-by [:%lower.name]})
        table-id->perms (u/key-by :table_id (db/select TablePermissions
                                              :group_id group-id
                                              :table_id [:in (map :id tables)]))]
    (println "table-id->perms:" table-id->perms) ; NOCOMMIT
    (assoc schema-perms
      :access_type (cond
                     (:unrestricted_table_access schema-perms) :unrestricted
                     (seq table-id->perms)                     :some_tables
                     :else                                     :no_access)
      ;; TODO - should we include :access_type for tables that *do* have permissions ?
      :tables      (for [table tables
                         :let  [perms (or (table-id->perms (:id table))
                                          {:id          nil
                                           :access_type :no_access})]]
                     (assoc perms
                       :table_id (:id table)
                       :name     (:name table))))))

;; TODO - move to models as well?
(defn- schema-permissions [database-id group-id schema]
  (add-schema-perms-extra-info (or (SchemaPermissions :database_id database-id, :group_id group-id, :schema schema)
                                   (throw (ex-info (format "Group %d doesn't have any permissions for '%s'." group-id schema)
                                            {:status-code 404})))))

(defendpoint GET "/database/:database-id/group/:group-id/schema/:schema"
  "Fetch `SchemaPermissions` for a `PermissionsGroup`."
  [database-id group-id schema]
  {schema NonEmptyString}
  (check-superuser)
  (when-not (db/exists? DatabasePermissions, :database_id database-id, :group_id group-id)
    (throw (ex-info (format "Can't fetch schema permissions for '%s': Group %d has no permissions for Database %d" schema group-id database-id)
             {:status-code 400})))
  (schema-permissions database-id group-id schema))


(defn- check-can-change-schema-permissions [database-id group-id schema]
  ;; make sure the schema exists
  (when-not (database/schema-exists? {:id database-id} schema)
    (throw (ex-info (format "Can't create schema permissions for '%s': schema doesn't exist." schema)
             {:status-code 404})))
  ;; you're not allowed to create schema permissions for a schema unless you have permissions for that DB
  (let [db-perms (db/exists? DatabasePermissions, :database_id database-id, :group_id group-id)]
    (when-not db-perms
      (throw (ex-info (format "Can't create schema permissions for '%s': Group %d doesn't have permissions for Database %d." schema group-id database-id)
               {:status-code 400})))
    ;; you also can't create schema permissions for the schema if you have unrestricted schema access
    (when (:unrestricted_schema_access db-perms)
      (throw (ex-info (format "Can't create schema permissions for '%s': Group %d has unrestricted schema access for Database %d." schema group-id database-id)
               {:status-code 400})))))


(defendpoint POST "/database/:database-id/group/:group-id/schema"
  "Enable schema permissions for a Group."
  [database-id group-id :as {{:keys [schema]} :body}]
  {schema [Required NonEmptyString]}
  (check-superuser)
  (check-can-change-schema-permissions database-id group-id schema)
  (when (db/exists? SchemaPermissions :database_id database-id, :group_id group-id, :schema schema)
    (throw (ex-info (format "Can't create schema permissions for '%s': permissions already exist" schema)
             {:status-code 404})))
  (db/insert! SchemaPermissions :schema schema, :database_id database-id, :group_id group-id))


;; TODO - this should probably just be `DELETE /schema-permissions/:id`
(defendpoint DELETE "/database/:database-id/group/:group-id/schema/:schema"
  "Remove schema permissions for a group."
  [database-id group-id schema]
  {schema NonEmptyString}
  (check-can-change-schema-permissions database-id group-id schema)
  (when-not (db/exists? SchemaPermissions :database_id database-id, :group_id group-id, :schema schema)
    (throw (ex-info (format "Can't remove schema permissions for '%s': no permissions found" schema)
             {:status-code 404})))
  (db/cascade-delete! SchemaPermissions, :database_id database-id, :group_id group-id, :schema schema))


(defendpoint PUT "/schema-permissions/:id"
  "Update the `unrestricted_table_access` setting for schema permissions for a group."
  [id :as {{:keys [unrestricted_table_access]} :body}]
  {unrestricted_table_access [Required Boolean]}
  (check-superuser)
  (check-404 (db/exists? SchemaPermissions :id id))
  (db/update! SchemaPermissions id
    :unrestricted_table_access unrestricted_table_access)
  (add-schema-perms-extra-info (SchemaPermissions id)))

;;; ---------------------------------------- TablePermissions (/api/permissions/table/:id/group/:id) endpoints ----------------------------------------

(defendpoint POST "/table-permissions"
  "Create `TablePermissions` for a Table."
  [:as {{:keys [group_id table_id]} :body}]
  {group_id [Required Integer]
   table_id [Required Integer]}
  (check-superuser)
  (let-404 [table (db/select-one [Table :db_id :schema :name], :id table_id)]
    (let [schema-perms (db/select-one [SchemaPermissions :unrestricted_table_access] :database_id (:db_id table), :group_id group_id, :schema (:schema table))]
      (check schema-perms
        400 (format "Can't create TablePermissions: group %d doesn't have permissions for schema '%s'" group_id (:schema table)))
      (check (not (:unrestricted_table_access schema-perms))
        400 (format "Can't create TablePermissions: group %d has unrestricted access for all tables in schema '%s'" group_id (:schema table)))))
  (check (not (db/exists? TablePermissions :table_id table_id, :group_id group_id))
    400 "Can't create TablePermissions: permissions already exist")
  (db/insert! TablePermissions
    :group_id group_id
    :table_id table_id))

(defendpoint DELETE "/table-permissions/:id"
  "Revoke `TablePermissions` for a Table."
  [id]
  (check-superuser)
  (check-404 (db/exists? TablePermissions :id id))
  (db/cascade-delete! TablePermissions :id id))


(define-routes)
