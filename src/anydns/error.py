import warnings


class DNSError(Exception):
    """Base class for all DNS errors."""


class DeadlockWarning(UserWarning):
    """Warns user that queries are possibly still in limbo
    but that the all the file descriptors have exited
    unexpectedly. It's a rare case but still has a chance
    of happening. If this occurs, all running queries to
    ffi and cython dns resolvers are then closed following
    this warning's announcement."""


def issue_deadlock_warning(library: str):
    """Issued when callbacks do not function correctly or like they are supposed to."""
    warnings.warn(
        f"{library}'s qureries are possibly under a deadlock from misconfigured"
        " callbacks in the source code. DNSResolver will be canceling all running " \
        "queries to make up for this.",
        DeadlockWarning,
    )


class LibraryError(Exception):
    """Base class for all library related errors such as not having a 
    specifically needed library"""


