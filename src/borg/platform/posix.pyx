import errno
import grp
import os
import pwd
from functools import lru_cache


cdef extern from "wchar.h":
    cdef int wcswidth(const Py_UNICODE *str, size_t n)


@lru_cache(maxsize=None)
def uid2user(uid, default=None):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return default


@lru_cache(maxsize=None)
def user2uid(user, default=None):
    try:
        return user and pwd.getpwnam(user).pw_uid
    except KeyError:
        return default


@lru_cache(maxsize=None)
def gid2group(gid, default=None):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return default


@lru_cache(maxsize=None)
def group2gid(group, default=None):
    try:
        return group and grp.getgrnam(group).gr_gid
    except KeyError:
        return default


def get_user():
    return uid2user(os.getuid(), os.getuid())


def swidth(s):
    str_len = len(s)
    terminal_width = wcswidth(s, str_len)
    if terminal_width >= 0:
        return terminal_width
    else:
        return str_len


def process_alive(host, pid, thread):
    """
    Check if the (host, pid, thread_id) combination corresponds to a potentially alive process.

    If the process is local, then this will be accurate. If the process is not local, then this
    returns always True, since there is no real way to check.
    """
    from . import local_pid_alive
    from . import hostid

    assert isinstance(host, str)
    assert isinstance(hostid, str)
    assert isinstance(pid, int)
    assert isinstance(thread, int)

    if host != hostid:
        return True

    if thread != 0:
        # Currently thread is always 0, if we ever decide to set this to a non-zero value,
        # this code needs to be revisited, too, to do a sensible thing
        return True

    return local_pid_alive(pid)


def local_pid_alive(pid):
    """Return whether *pid* is alive."""
    try:
        # This doesn't work on Windows.
        # This does not kill anything, 0 means "see if we can send a signal to this process or not".
        # Possible errors: No such process (== stale lock) or permission denied (not a stale lock).
        # If the exception is not raised that means such a pid is valid and we can send a signal to it.
        os.kill(pid, 0)
        return True
    except OSError as err:
        if err.errno == errno.ESRCH:
            # ESRCH = no such process
            return False
        # Any other error (eg. permissions) means that the process ID refers to a live process.
        return True
