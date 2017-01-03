# encoding: utf-8

import ckan.logic
import ckan.plugins as plugins
from ckan.logic import side_effect_free
ValidationError = ckan.logic.ValidationError
NotFound = ckan.logic.NotFound
_check_access = ckan.logic.check_access
_get_or_bust = ckan.logic.get_or_bust
_get_action = ckan.logic.get_action


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

    # append resource to new package
    pkg_dict_new['resources'].append(resource_dict)

    _get_action('package_update')(context, pkg_dict_new)

    return "package '" + package_id_new + "' contains now " + str(len(pkg_dict_new['resources'])) + " resource(s)"