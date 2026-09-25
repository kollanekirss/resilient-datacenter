"""A partner-policy change fails closed; it never rolls back a revocation."""


class TransitionError(ValueError):
    def __init__(self,closed):
        self.closed=closed
        super().__init__('Gateway change is pending review; '+('regional access is closed' if closed else 'closure could not be verified: isolate the gateway before retrying'))


def apply(store,runtime,candidate):
    # Durable intent is also checked at startup. An interrupted change must not
    # cause an automatic restart to reopen the previous partner set.
    store.begin(candidate)
    try:
        runtime.close()
        runtime.validate(candidate)
        store.commit(candidate)
        runtime.install(candidate)
        runtime.restart()
        runtime.open(candidate)
        store.finish()
    except BaseException as error:
        try:runtime.close();closed=True
        except BaseException:closed=False
        raise TransitionError(closed) from error
