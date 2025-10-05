class ErrAccountNotFound(Exception):
    def __str__(self):
        return 'Account not found'
