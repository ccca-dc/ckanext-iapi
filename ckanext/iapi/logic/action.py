# encoding: utf-8

import ckan.logic
import ckan.plugins as plugins
import ckan.plugins.toolkit as tk
from ckan.logic import side_effect_free

import os
import hashlib
import ckan.lib.uploader as uploader
import ckan.authz as authz
import ckan.lib.dictization.model_dictize as model_dictize
from paste.deploy.converters import asbool
from ckan.lib.base import _
import ckan.logic as logic
import sqlalchemy

ValidationError = ckan.logic.ValidationError
NotFound = ckan.logic.NotFound
NotAuthorized = ckan.logic.NotAuthorized
_check_access = ckan.logic.check_access
_get_or_bust = ckan.logic.get_or_bust
_get_action = ckan.logic.get_action

_select = sqlalchemy.sql.select
_and_ = sqlalchemy.and_


import re
from ckanext.resourceversions import helpers as hr
# FIXME: Check if resourceversions is loaded

@side_effect_free
def package_show (context, data_dict):

    # id kann key oder name sein; name braucht -vxx
    id = data_dict['id']
    r1 = re.compile("-v..$")
    if not r1.search(id):
            #Look for newest version: returns error if we tried with a key
            ipkg = hr.get_newest_version(id + '-v01')
            if ipkg:
                data_dict['id'] = ipkg['name']

    pkg = ckan.logic.action.get.package_show(context, data_dict)

    return pkg

def resource_change_package(context, data_dict):
    model = context['model']
    resource_id = data_dict.pop('resource_id', None)
    package_id_new = data_dict.pop('new_package_id', None)

    resource = model.Resource.get(resource_id)
    package_new = model.Package.get(package_id_new)

    # check if resource and package exist
    if resource is None:
        raise NotFound('resource_id')

    if package_new is None:
        raise NotFound('new_package_id')

    resource_dict = _get_action('resource_show')(context, {'id': resource_id})
    pkg_dict_new = _get_action('package_show')(context, {'id': package_id_new})

    # check if user has right to move resource to package
    _check_access('package_update', context, pkg_dict_new)
    _check_access('resource_update', context, resource_dict)

    package_id_old = resource.get_package_id()
    pkg_dict_old = _get_action('package_show')(context, {'id': package_id_old})

    if pkg_dict_new == pkg_dict_old:
        return "resource is already in this package"

    # delete resource from old package
    if pkg_dict_old.get('resources'):
        pkg_dict_old['resources'] = [r for r in pkg_dict_old['resources'] if
                                    not r['id'] == resource_id]

    _get_action('package_update')(context, pkg_dict_old)

    pkg_dict_new = _get_action('package_show')(context, {'id': package_id_new})

    resource_dict['url'] = resource.url

    # append resource to new package
    resource_dict['package_id'] = pkg_dict_new['id']
    pkg_dict_new['resources'].append(resource_dict)

    try:
        _get_action('package_update')(context, pkg_dict_new)
    except Exception, e:
        print(e)

    return "package '" + package_id_new + "' contains now " + str(len(pkg_dict_new['resources'])) + " resource(s)"

@side_effect_free
def resource_get_size(context, data_dict):
    model = context['model']
    user = context['user']

    resource_id = _get_or_bust(data_dict, 'id')

    _check_access('resource_update', context, data_dict)
    resource_dict = _get_action('resource_show')(context, {'id': resource_id})
    if _get_or_bust(resource_dict, 'url_type'):
        upload = uploader.get_resource_uploader(resource_dict)
        file_size = os.path.getsize(upload.get_path(resource_id))
        return file_size
    else:
        raise ValidationError({'order':'This is not an uploaded file'})

@side_effect_free
def resource_get_hash(context, data_dict):
    model = context['model']
    user = context['user']

    hasher = hashlib.md5()
    resource_id = _get_or_bust(data_dict, 'id')

    _check_access('resource_update', context, data_dict)
    resource_dict = _get_action('resource_show')(context, {'id': resource_id})
    # FIXME check if url_type is upload
    if _get_or_bust(resource_dict, 'url_type'):
        upload = uploader.get_resource_uploader(resource_dict)
        file_path = upload.get_path(resource_id)

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(128*hasher.block_size), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    else:
        raise ValidationError({'order':'This is not an uploaded file'})


def group_list_authz(context, data_dict):
    '''Return the list of groups that the user is authorized to edit.

    :param available_only: remove the existing groups in the package
      (optional, default: ``False``)
    :type available_only: boolean

    :param am_member: if ``True`` return only the groups the logged-in user is
      a member of, otherwise return all groups that the user is authorized to
      edit (for example, sysadmin users are authorized to edit all groups)
      (optional, default: ``False``)
    :type am-member: boolean

    :returns: list of dictized groups that the user is authorized to edit
    :rtype: list of dicts

    '''
    model = context['model']
    user = context['user']
    available_only = data_dict.get('available_only', False)
    am_member = data_dict.get('am_member', False)

    _check_access('group_list_authz', context, data_dict)

    sysadmin = authz.is_sysadmin(user)
    roles = authz.get_roles_with_permission('manage_group')
    if not roles:
        return []
    user_id = authz.get_user_id_for_username(user, allow_none=True)
    if not user_id:
        return []

    if not sysadmin or am_member:
        q = model.Session.query(model.Member) \
            .filter(model.Member.table_name == 'user') \
            .filter(model.Member.capacity.in_(roles)) \
            .filter(model.Member.table_id == user_id) \
            .filter(model.Member.state == 'active')
        group_ids = []
        for row in q.all():
            group_ids.append(row.group_id)

    q = model.Session.query(model.Group) \
        .filter(model.Group.is_organization == False) \
        .filter(model.Group.state == 'active')

    groups = []

    for row in q.all():
        # packages can be added to groups with addition_without_group_membership True in any case
        if row._extras.get('addition_without_group_membership', None) is not None and row._extras['addition_without_group_membership'].value == "True":
            groups.append(row)

    if not sysadmin or am_member:
        q = q.filter(model.Group.id.in_(group_ids))

    for row in q.all():
        if row not in groups:
            groups.append(row)

    if available_only:
        package = context.get('package')
        if package:
            groups = set(groups) - set(package.get_groups())

    group_list = model_dictize.group_list_dictize(groups, context)
    return group_list


def organization_list_for_other_user(context, data_dict):
    '''Return the organizations that the given user has a given permission for.

    By default this returns the list of organizations that the currently
    authorized user can edit, i.e. the list of organizations that the user is an
    admin of.

    Specifically it returns the list of organizations that the currently
    authorized user has a given permission (for example: "manage_group") against.

    When a user becomes a member of an organization in CKAN they're given a
    "capacity" (sometimes called a "role"), for example "member", "editor" or
    "admin".

    Each of these roles has certain permissions associated with it. For example
    the admin role has the "admin" permission (which means they have permission
    to do anything). The editor role has permissions like "create_dataset",
    "update_dataset" and "delete_dataset".  The member role has the "read"
    permission.

    This function returns the list of organizations that the authorized user
    has a given permission for. For example the list of organizations that the
    user is an admin of, or the list of organizations that the user can create
    datasets in. This takes account of when permissions cascade down an
    organization hierarchy.

    :param user_id: the id of the user
    :type user_id: string

    :returns: list of dicts with organizations that the user is part of and role of the user in this group
    :rtype: list of dicts

    '''
    model = context['model']
    user = context['user']

    if user == '':
        raise NotAuthorized(_('Not authorized'))

    user_id = _get_or_bust(data_dict, 'user_id')
    given_user = tk.get_action('user_show')(context, {'id': user_id})

    return_list = []

    if asbool(given_user['sysadmin']):
        orgs_q = model.Session.query(model.Group) \
            .filter(model.Group.is_organization == True) \
            .filter(model.Group.state == 'active')

        org_list = model_dictize.group_list_dictize(orgs_q.all(), context)

        for item in org_list:
            return_list.append({'organization': item, 'role': 'admin'})
    else:
        q = model.Session.query(model.Member, model.Group) \
            .filter(model.Member.table_name == 'user') \
            .filter(model.Member.table_id == user_id) \
            .filter(model.Member.state == 'active') \
            .filter(model.Group.is_organization == True) \
            .filter(model.Group.state == 'active') \
            .join(model.Group)

        # roles_that_cascade = \
        #     authz.check_config_permission('roles_that_cascade_to_sub_groups')
        for member, group in q.all():
            # if member.capacity in roles_that_cascade:
            #     group_ids |= set([
            #         grp_tuple[0] for grp_tuple
            #         in group.get_children_group_hierarchy(type='organization')
            #         ])
            # group_ids.add(group.id)
            org = tk.get_action('organization_show')(context, {'id': group.id, 'state': 'active', 'include_users': False, 'include_groups': False, 'include_extras': False, 'include_tags': False, 'include_followers': False})
            return_list.append({'organization': org, 'role': member.capacity})

    return return_list


@logic.validate(logic.schema.default_pagination_schema)
def package_list(context, data_dict):
    '''Return a list of the names of the site's datasets (packages).

    :param limit: if given, the list of datasets will be broken into pages of
        at most ``limit`` datasets per page and only one page will be returned
        at a time (optional)
    :type limit: int
    :param offset: when ``limit`` is given, the offset to start
        returning packages from
    :type offset: int

    :rtype: list of strings

    '''
    model = context["model"]
    api = context.get("api_version", 1)

    _check_access('package_list', context, data_dict)

    package_table = model.package_table
    col = (package_table.c.id
           if api == 2 else package_table.c.name)
    query = _select([col])
    query = query.where(_and_(
        package_table.c.state == 'active',
        package_table.c.private == False,
    ))
    query = query.order_by(col)

    limit = data_dict.get('limit')
    if limit:
        query = query.limit(limit)

    offset = data_dict.get('offset')
    if offset:
        query = query.offset(offset)

    pkg_name_list = [r[0] for r in query.execute()]

    # added this section for 'include_versions' parameter
    if '__extras' not in data_dict or data_dict['__extras'].get('include_versions', False) is False:
        # remove -v from all names
        pkg_name_list = ["-v".join(element.split("-v")[:-1]) for element in pkg_name_list]

        # make elements of list unique
        pkg_name_list = list(set(pkg_name_list))


    ## Returns the first field in each result record
    return pkg_name_list
