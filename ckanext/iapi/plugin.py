import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckanext.iapi.logic.action as action


class IapiPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IActions)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'iapi')

    def get_actions(self):
        actions = {'resource_change_package': action.resource_change_package,
                   'resource_get_size': action.resource_get_size,
                   'resource_get_hash': action.resource_get_hash,
                   'package_show': action.package_show,
                   'group_list_authz': action.group_list_authz}
        return actions
