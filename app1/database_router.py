class CustomUserDatabaseRouter:
    """
    A database router to control operations on the CustomUser model
    to route to the default database.
    """

    def db_for_read(self, model, **hints):
        if model._meta.app_label == 'app1' and model.__name__ == 'CustomUser':
            return 'default'
        return None

    def db_for_write(self, model, **hints):
        if model._meta.app_label == 'app1' and model.__name__ == 'CustomUser':
            return 'default'
        return None

    def allow_relation(self, obj1, obj2, **hints):
        if obj1._meta.app_label == 'app1' and obj2._meta.app_label == 'app1':
            return True
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if app_label == 'app1' and model_name == 'CustomUser':
            return db == 'default'
        return None

