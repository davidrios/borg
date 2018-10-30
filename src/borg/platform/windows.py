import os
from getpass import getuser

import pywintypes
from win32api import OpenProcess, CloseHandle, GetDiskFreeSpaceEx
from win32con import PROCESS_QUERY_INFORMATION, PROCESS_VM_READ
from win32file import CreateFile, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING
from win32file import FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS
from win32security import GetSecurityInfo, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, LookupAccountSid
from winerror import ERROR_INVALID_PARAMETER

from ..helpers import safe_ns, StableDict
from .base import BaseFileAttrs


def get_user():
    return getuser()


def check_python():
    return


class FileAttrs(BaseFileAttrs):
    def stat_simple_attrs(self, st, path):
        attrs = dict(
            mode=st.st_mode,
            uid=st.st_uid,
            gid=st.st_gid,
            mtime=safe_ns(st.st_mtime_ns),
        )
        # borg can work with archives only having mtime (older attic archives do not have
        # atime/ctime). it can be useful to omit atime/ctime, if they change without the
        # file content changing - e.g. to get better metadata deduplication.
        if not self.noatime:
            attrs['atime'] = safe_ns(st.st_atime_ns)
        if not self.noctime:
            attrs['ctime'] = safe_ns(st.st_ctime_ns)
        if not self.nobirthtime and hasattr(st, 'st_birthtime'):
            # sadly, there's no stat_result.st_birthtime_ns
            attrs['birthtime'] = safe_ns(int(st.st_birthtime * 10**9))

        if os.path.isdir(path):
            flags_attrs = FILE_FLAG_BACKUP_SEMANTICS
        else:
            flags_attrs = FILE_ATTRIBUTE_NORMAL

        fhandle = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, flags_attrs, None)

        try:
            sec_desc = GetSecurityInfo(fhandle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION)
            owner = sec_desc.GetSecurityDescriptorOwner()
            name, host, use = LookupAccountSid(None, owner)
            attrs['user'] = name

            group = sec_desc.GetSecurityDescriptorGroup()
            if group is not None:
                name, host, use = LookupAccountSid(None, group)

            attrs['group'] = name
        finally:
            CloseHandle(fhandle)

        return attrs

    def stat_ext_attrs(self, st, path):
        return {}


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
