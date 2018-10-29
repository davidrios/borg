# -*- coding: utf-8 -*-
import errno
import os

from libc.stddef cimport wchar_t

API_VERSION = '1.1_07'


cdef extern from "<windows.h>":
    ctypedef int BOOL
    ctypedef unsigned long DWORD
    ctypedef void *PVOID
    ctypedef PVOID HANDLE
    ctypedef wchar_t WCHAR
    ctypedef const WCHAR *LPCWSTR
    ctypedef double ULONGLONG

    ctypedef struct ULARGE_INTEGER:
        ULONGLONG QuadPart

    ctypedef ULARGE_INTEGER *PULARGE_INTEGER

    int PROCESS_QUERY_INFORMATION
    int PROCESS_VM_READ
    BOOL FALSE

    DWORD __stdcall GetLastError()

    BOOL __stdcall CloseHandle(
        HANDLE hObject
    )

    HANDLE OpenProcess(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwProcessId
    )

    BOOL GetDiskFreeSpaceExW(
        LPCWSTR         lpDirectoryName,
        PULARGE_INTEGER lpFreeBytesAvailableToCaller,
        PULARGE_INTEGER lpTotalNumberOfBytes,
        PULARGE_INTEGER lpTotalNumberOfFreeBytes
    )


cdef extern from "Python.h":
    wchar_t* PyUnicode_AsWideCharString(object, Py_ssize_t *)


def sync_dir(path):
    for current, dirs, files in os.walk(path):
        for fname in files:
            fd = os.open(os.path.join(current, fname), os.O_RDWR | os.O_BINARY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)


def get_path_free_space(path):
    if type(path) is not unicode:
        raise TypeError('path must be a unicode string')

    cdef Py_ssize_t length
    cdef wchar_t *wchars = PyUnicode_AsWideCharString(path, &length)
    cdef ULARGE_INTEGER total_free

    if not GetDiskFreeSpaceExW(wchars, NULL, NULL, &total_free):
        raise OSError('error code {}'.format(GetLastError()))

    return int(total_free.QuadPart)


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
    cdef HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)
    cdef int ret_val = NULL != h_process
    CloseHandle(h_process)
    return bool(ret_val)
