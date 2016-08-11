import React, { Component } from "react";
import { connect } from "react-redux";

import { getDatabases, getDatabasePermissions, getGroups } from "../selectors";
import { fetchDatabases, fetchDatabasePermissions, fetchGroups } from "../permissions";

import DatabasePermissions from "../components/DatabasePermissions.jsx";


function mapStateToProps(state, props) {
    return {
        databases: getDatabases(state, props),
        databasePermissions: getDatabasePermissions(state, props),
        groups: getGroups(state, props)
    };
}

const mapDispatchToProps = {
    fetchDatabases,
    fetchDatabasePermissions,
    fetchGroups
};


@connect(mapStateToProps, mapDispatchToProps)
export default class DatabasePermissionsApp extends Component {
    async componentWillMount() {
        await this.props.fetchDatabases();
        await this.props.fetchDatabasePermissions(this.props.routeParams.databaseID, this.props.routeParams.groupID);
        await this.props.fetchGroups();
    }

    render () {
        return (
            <DatabasePermissions {...this.props} />
        );
    }
}
