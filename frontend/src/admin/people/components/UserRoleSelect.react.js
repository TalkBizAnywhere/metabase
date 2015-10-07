import React, { Component, PropTypes } from "react";
import cx from "classnames";

import ColumnarSelector from "metabase/components/ColumnarSelector.react";
import Icon from "metabase/components/Icon.react";
import MetabaseCore from "metabase/lib/core";
import PopoverWithTrigger from "metabase/components/PopoverWithTrigger.react";


export default class UserRoleSelect extends Component {

    toggle () {
        this.refs.popover.toggle();
    }

    render() {
        let { user, onChangeFn } = this.props;
        const roleDef = (user.is_superuser) ? MetabaseCore.user_roles[1] : MetabaseCore.user_roles[0];

        const triggerElement = (
            <div className={"flex align-center"}>
                <span className="mr1">{roleDef.name}</span>
                <Icon className="text-grey-2" name="chevrondown"  width="10" height="10"/>
            </div>
        );

        let sections = {};
        MetabaseCore.user_roles.forEach(function (option) {
            let sectionName = option.section || "";
            sections[sectionName] = sections[sectionName] || { title: sectionName || undefined, items: [] };
            sections[sectionName].items.push(option);
        });
        sections = Object.keys(sections).map((sectionName) => sections[sectionName]);

        const columns = [
            {
                selectedItem: roleDef,
                sections: sections,
                itemTitleFn: (item) => item.name,
                itemDescriptionFn: (item) => item.description,
                itemSelectFn: (item) => {
                    onChangeFn(user, item);
                    this.toggle();
                }
            }
        ];

        return (
            <PopoverWithTrigger ref="popover"
                                className="UserRolePopover block"
                                triggerElement={triggerElement}
                                triggerClasses={cx("AdminSelectBorderless", "py1", {"text-purple": user.is_superuser, "text-brand": !user.is_superuser})}>
                <ColumnarSelector columns={columns}/>
            </PopoverWithTrigger>
        );
    }
}

UserRoleSelect.defaultProps = {
    isInitiallyOpen: false
};

UserRoleSelect.propTypes = {
    user: React.PropTypes.object.isRequired,
    onChangeFn: React.PropTypes.func.isRequired
};