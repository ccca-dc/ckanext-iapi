import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.logic as logic
import ckanext.iapi.logic.action as action
import ckan.model as model
import ckan.lib.base as base

c = base.c
ValidationError = logic.ValidationError


class IapiPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IResourceController, inherit=True)

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
                   'group_list_authz': action.group_list_authz,
                   'organization_list_for_other_user': action.organization_list_for_other_user,
                   'package_list': action.package_list}
        return actions

    def after_update(self, context, resource):
        self._enqueue_job(c.user, resource)

    def after_create(self, context, resource):
        self._enqueue_job(c.user, resource)

    def _enqueue_job(self, user, resource):
        try:
            enqueue_job = toolkit.enqueue_job
        except AttributeError:
            from ckanext.rq.jobs import enqueue as enqueue_job
        enqueue_job(hash_and_size_create_job, [user, resource])


def hash_and_size_create_job(user, resource):
    context = {'model': model, 'session': model.Session, 'user': user}

    # check if resource is subset as these cannot check hash and size this way
    package = toolkit.get_action('package_show')(context, {'id': resource['package_id']})
    parent_ids = [element['id'] for element in package['relations'] if element['relation'] == 'is_part_of']

    if len(parent_ids) == 0:
        orig_size = resource['size']
        orig_hash = resource['hash']

        try:
            resource['size'] = toolkit.get_action('resource_get_size')(context, {'id': resource['id']})
            resource['hash'] = toolkit.get_action('resource_get_hash')(context, {'id': resource['id']})
            resource['hash_algorithm'] = 'md5'
        except ValidationError:
            resource['size'] = ''
            resource['hash'] = ''
            resource['hash_algorithm'] = ''

        if orig_size != resource['size'] and orig_hash != resource['hash']:
            toolkit.get_action('resource_update')(context, resource)
