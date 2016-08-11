(ns metabase.query-processor.permissions
  "Logic related to whether a given user has permissions to run/edit a given query."
  (:require [clojure.tools.logging :as log]
            [honeysql.core :as hsql]
            (metabase [db :as db]
                      [util :as u])))

#_(defn- user-has-native-query-write-access?
  "Does User with USER-ID have appropriate permissions to *edit* or *delete* a *native* query against database with DATABASE-ID?
   (Users can always *run* existing native queries.)"
  [user-id database-id]
  (boolean (seq (db/query {:select    [:dp.native_query_write_access]
                           :from      [[:core_user :u]]
                           :left-join [[:permissions_group_membership :m]  [:= :u.id        :m.user_id]
                                       [:permissions_group            :g]  [:= :m.group_id  :g.id]
                                       [:database_permissions         :dp] [:= :dp.group_id :g.id]]
                           :where     [:and [:= :u.id                         user-id]
                                            [:= :dp.database_id               database-id]
                                            [:= :dp.native_query_write_access true]]
                           :limit     1}))))

(defn- user-can-run-query-referencing-table?
  "Does User with USER-ID have appropriate permissions to run an MBQL query referencing table with TABLE-ID?"
  [user-id table-id]
  {:pre [(integer? user-id) (integer? table-id)]}
  (boolean (seq (db/query {:select    [true]
                           :from      [[:permissions_group :g]]
                           :join      [[:permissions_group_membership :m]  [:= :g.id :m.group_id]
                                       [:database_permissions         :dp] [:= :g.id :dp.group_id]
                                       [:metabase_table               :t]  [:= :t.db_id :dp.database_id]]
                           :left-join [[:schema_permissions           :sp] [:and [:= :g.id :sp.group_id]
                                                                                 [:= :sp.database_id :t.db_id]
                                                                                 [:= :sp.schema :t.schema]]
                                       [:table_permissions            :tp] [:= :g.id :tp.group_id]]
                           :where     [:and [:= :m.user_id user-id]
                                            [:= :t.id table-id]
                                            [:or [:= :dp.unrestricted_schema_access true]
                                                 [:= :sp.unrestricted_table_access true]
                                                 [:= :tp.table_id :t.id]]]
                           :limit     1}))))


(defn- table-id [source-or-join-table]
  (or (:id source-or-join-table)
      (:table-id source-or-join-table)))

(defn- table-identifier ^String [source-or-join-table]
  (name (hsql/qualify (:schema source-or-join-table) (or (:name source-or-join-table)
                                                         (:table-name source-or-join-table)))))


(defn- throw-exception-if-user-cannot-run-query-referencing-table [user-id table]
  (log/debug (u/format-color 'yellow  "Permissions Check 🔐 : Can User %d access Table %d (%s)?" user-id (table-id table) (table-identifier table)))
  (when-not (user-can-run-query-referencing-table? user-id (table-id table))
    (log/error (u/format-color 'red "Permissions Check 🔐 : No 🚫"))
    (throw (Exception. (format "You do not have permissions to run queries referencing table '%s'." (table-identifier table)))))
  (log/debug (u/format-color 'green "Permissions Check 🔓 : Yes ✅")))

(defn check-query-permissions
  "Check that User with USER-ID has permissions to run QUERY, or throw an exception."
  [user-id {query-type :type, {:keys [source-table join-tables]} :query}]
  ;; TODO - handle checking for native queries that aren't part of existing cards
  (when-not (= (keyword query-type) :native)
    ;; check that we can run against the source-table. and each of the join-tables, if any
    (doseq [table (cons source-table join-tables)]
      (throw-exception-if-user-cannot-run-query-referencing-table user-id table))))
