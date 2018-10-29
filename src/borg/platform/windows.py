import os

import pywintypes
from win32api import OpenProcess, CloseHandle, GetDiskFreeSpaceEx
from win32con import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
from winerror import ERROR_INVALID_PARAMETER

from .base import BaseFileAttrs


def get_user():
    pass


def check_python():
    return


class FileAttrs(BaseFileAttrs):
    pass


def sync_dir(path):
    for current, dirs, files in os.walk(path):
        for fname in files:
            fd = os.open(os.path.join(current, fname), os.O_RDWR | os.O_BINARY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)


def get_path_free_space(path):
    if type(path) is not str:
        raise TypeError('path must be a unicode string')

    try:
        return GetDiskFreeSpaceEx(path)[2]
    except pywintypes.error as ex:
        raise OSError(str(ex))


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
        handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    except pywintypes.error as ex:
        if ex.winerror == ERROR_INVALID_PARAMETER:
            return False
        raise

    CloseHandle(handle)
    return True
