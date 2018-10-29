import errno
import os
import time

from ..logger import create_logger
logger = create_logger()

from ..helpers import Error, StableDict, safe_ns, set_ec, EXIT_WARNING
from .. import xattr
from .base import BaseFileAttrs
from .posix import uid2user, gid2group, user2uid, group2gid
from . import acl_get, acl_set, get_flags, set_flags

has_lchmod = hasattr(os, 'lchmod')


class PythonLibcTooOld(Error):
    """FATAL: this Python was compiled for a too old (g)libc and misses required functionality."""


def check_python():
    required_funcs = {os.stat, os.utime, os.chown}
    if not os.supports_follow_symlinks.issuperset(required_funcs):
        raise PythonLibcTooOld


class FileAttrs(BaseFileAttrs):
    def stdin_attrs(self):
        uid, gid = 0, 0
        t = int(time.time()) * 1000000000

        return dict(
            uid=uid, user=uid2user(uid),
            gid=gid, group=gid2group(gid),
            mtime=t, atime=t, ctime=t,
        )

    def stat_simple_attrs(self, st):
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
        if self.numeric_owner:
            attrs['user'] = attrs['group'] = None
        else:
            attrs['user'] = uid2user(st.st_uid)
            attrs['group'] = gid2group(st.st_gid)
        return attrs

    def stat_ext_attrs(self, st, path):
        attrs = {}
        bsdflags = 0
        with self.backup_io('extended stat'):
            xattrs = xattr.get_all(path, follow_symlinks=False)
            if not self.nobsdflags:
                bsdflags = get_flags(path, st)
            acl_get(path, attrs, st, self.numeric_owner)
        if xattrs:
            attrs['xattrs'] = StableDict(xattrs)
        if bsdflags:
            attrs['bsdflags'] = bsdflags
        return attrs

    def stat_attrs(self, st, path):
        attrs = self.stat_simple_attrs(st)
        attrs.update(self.stat_ext_attrs(st, path))
        return attrs

    def restore_attrs(self, path, item, symlink=False, fd=None):
        """
        Restore filesystem attributes on *path* (*fd*) from *item*.

        Does not access the repository.
        """
        self.backup_io.op = 'attrs'
        uid = gid = None
        if not self.numeric_owner:
            uid = user2uid(item.user)
            gid = group2gid(item.group)
        uid = item.uid if uid is None else uid
        gid = item.gid if gid is None else gid
        # This code is a bit of a mess due to os specific differences
        try:
            if fd:
                os.fchown(fd, uid, gid)
            else:
                os.chown(path, uid, gid, follow_symlinks=False)
        except OSError:
            pass
        if fd:
            os.fchmod(fd, item.mode)
        elif not symlink:
            os.chmod(path, item.mode)
        elif has_lchmod:  # Not available on Linux
            os.lchmod(path, item.mode)
        mtime = item.mtime
        if 'atime' in item:
            atime = item.atime
        else:
            # old archives only had mtime in item metadata
            atime = mtime
        if 'birthtime' in item:
            birthtime = item.birthtime
            try:
                # This should work on FreeBSD, NetBSD, and Darwin and be harmless on other platforms.
                # See utimes(2) on either of the BSDs for details.
                if fd:
                    os.utime(fd, None, ns=(atime, birthtime))
                else:
                    os.utime(path, None, ns=(atime, birthtime), follow_symlinks=False)
            except OSError:
                # some systems don't support calling utime on a symlink
                pass
        try:
            if fd:
                os.utime(fd, None, ns=(atime, mtime))
            else:
                os.utime(path, None, ns=(atime, mtime), follow_symlinks=False)
        except OSError:
            # some systems don't support calling utime on a symlink
            pass
        acl_set(path, item, self.numeric_owner)
        # chown removes Linux capabilities, so set the extended attributes at the end, after chown, since they include
        # the Linux capabilities in the "security.capability" attribute.
        xattrs = item.get('xattrs', {})
        for k, v in xattrs.items():
            try:
                xattr.setxattr(fd or path, k, v, follow_symlinks=False)
            except OSError as e:
                if e.errno == errno.E2BIG:
                    # xattr is too big
                    logger.warning('%s: Value or key of extended attribute %s is too big for this filesystem' %
                                   (path, k.decode()))
                    set_ec(EXIT_WARNING)
                elif e.errno == errno.ENOTSUP:
                    # xattrs not supported here
                    logger.warning('%s: Extended attributes are not supported on this filesystem' % path)
                    set_ec(EXIT_WARNING)
                elif e.errno == errno.EACCES:
                    # permission denied to set this specific xattr (this may happen related to security.* keys)
                    logger.warning('%s: Permission denied when setting extended attribute %s' % (path, k.decode()))
                    set_ec(EXIT_WARNING)
                elif e.errno == errno.ENOSPC:
                    # no space left on device while setting this specific xattr
                    # ext4 reports ENOSPC when trying to set an xattr with >4kiB while ext4 can only support 4kiB xattrs
                    # (in this case, this is NOT a "disk full" error, just a ext4 limitation).
                    logger.warning('%s: No space left on device while setting extended attribute %s (len = %d)' % (
                        path, k.decode(), len(v)))
                    set_ec(EXIT_WARNING)
                else:
                    raise
        # bsdflags include the immutable flag and need to be set last:
        if not self.nobsdflags and 'bsdflags' in item:
            try:
                set_flags(path, item.bsdflags, fd=fd)
            except OSError:
                pass
