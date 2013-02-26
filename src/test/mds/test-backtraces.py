
import subprocess as sub
from cStringIO import StringIO
import json
import os
import time
import sys

from rados import (Rados)
from cephfs import (LibCephFS)

cephinst='/home/slang/dev/ceph/build-wip-bt2/src'
prefix='testbt'

def get_name(b, i, j):
    c = '{pre}.{pid}.{i}.{j}'.format(pre=prefix, pid=os.getpid(), i=i, j=j)
    return c, b + '/' + c

def mkdir(ceph, d):
    ceph.mkdir(d, 0755)
    return ceph.stat(d)['st_ino']

def create(ceph, f):
    fd = ceph.open(f, os.O_CREAT|os.O_RDWR, 0644)
    ceph.close(fd)
    return ceph.stat(f)['st_ino']

def set_mds_config_param(ceph, param):
    r = sub.call("{c}/ceph mds tell a injectargs '{p}'".format(c=cephinst, p=param), shell=True)
    if (r != 0):
        raise

def flush(ceph):
    set_mds_config_param(ceph, '--mds_log_max_segments 2')

    for i in range(1, 2000):
        f = '{p}.{pid}.{i}'.format(p=prefix, pid=os.getpid(), i=i)
        fd = ceph.open(f, os.O_CREAT | os.O_RDWR, 0644)
        ceph.close(fd)
        ceph.unlink(f)

    ceph.shutdown()
    ceph = LibCephFS()
    ceph.mount()
    return ceph

def kill_mds(ceph, location, killnum):
    set_mds_config_param(ceph, '--mds_kill_{l}_at {k}'.format(l=location, k=killnum))

def wait_for_mds(ceph):
    # wait for restart
    while True:
        r = sub.check_output("{c}/ceph mds stat".format(c=cephinst), shell=True)
        if r.find('a=up:active'):
            break
        time.sleep(1)

def decode(value):

    tmpfile = '/tmp/{p}.{pid}'.format(p=prefix, pid=os.getpid())
    with open(tmpfile, 'w+') as f:
      f.write(value)

    p = sub.Popen(
        [
            '{c}/ceph-dencoder'.format(c=cephinst),
            'import',
            tmpfile,
            'type',
            'inode_backtrace_t',
            'decode',
            'dump_json',
        ],
        stdin=sub.PIPE,
        stdout=sub.PIPE,
      )
    (stdout, _) = p.communicate(input=value)
    p.stdin.close()
    if (p.returncode != 0):
        raise
    os.remove(tmpfile)
    return json.loads(stdout)


class VerifyFailure(Exception):
    pass

def verify(rados_ioctx, ino, values, pool):
    print 'getting parent attr for ino: %lx.00000000' % ino
    binbt = rados_ioctx.get_xattr('%lx.00000000' % ino, 'parent')
    bt = decode(binbt)

    if bt['ino'] != ino:
        raise VerifyFailure('inode mismatch: {bi} != {ino}\n\tbacktrace:\n\t\t{bt}\n\tfailed verify against:\n\t\t{i}, {v}'.format(
                    bi=bt['ancestors'][ind]['dname'], ino=ino, bt=bt, i=ino, v=values))
    ind = 0
    for (n, i) in values:
        if bt['ancestors'][ind]['dirino'] != i:
            raise VerifyFailure('ancestor dirino mismatch: {b} != {ind}\n\tbacktrace:\n\t\t{bt}\n\tfailed verify against:\n\t\t{i}, {v}'.format(
                    b=bt['ancestors'][ind]['dirino'], ind=i, bt=bt, i=ino, v=values))
        if bt['ancestors'][ind]['dname'] != n:
            raise VerifyFailure('ancestor dname mismatch: {b} != {n}\n\tbacktrace:\n\t\t{bt}\n\tfailed verify against:\n\t\t{i}, {v}'.format(
                    b=bt['ancestors'][ind]['dname'], n=n, bt=bt, i=ino, v=values))
        ind += 1

    if bt['pool'] != pool:
        raise VerifyFailure('pool mismatch: {btp} != {p}\n\tbacktrace:\n\t\t{bt}\n\tfailed verify against:\n\t\t{i}, {v}'.format(
                    btp=bt['pool'], p=pool, bt=bt, i=ino, v=values))

def make_abc(ceph, rooti, i):
    expected_bt = []
    c, d = get_name("/", i, 0)
    expected_bt = [(c, rooti)] + expected_bt
    di = mkdir(ceph, d)
    c, d = get_name(d, i, 1)
    expected_bt = [(c, di)] + expected_bt
    di = mkdir(ceph, d)
    c, f = get_name(d, i, 2)
    fi = create(ceph, f)
    expected_bt = [(c, di)] + expected_bt
    return fi, expected_bt

ceph = LibCephFS()
ceph.mount()

rados = Rados(conffile='/home/slang/dev/ceph/build-wip-bt2/src/ceph.conf')
rados.connect()
ioctx = rados.open_ioctx('data')

rooti = ceph.stat('/')['st_ino']

test = None
if len(sys.argv) > 1:
    test = int(sys.argv[1])

# create /a/b/c
# flush
# verify

i = 0
if not test or test == i:
  print 'Running test %d: basic verify' % i
  ino, expected_bt = make_abc(ceph, rooti, i)
  ceph = flush(ceph)
  verify(ioctx, ino, expected_bt, 0)

i += 1

# kill-mds-at-openc-1
# create /a/b/c
# restart-mds
# flush
# verify

if not test or test == i:
  print 'Running test %d: kill openc' % i
  kill_mds(ceph, 'openc', 1)
  ino, expected_bt = make_abc(ceph, rooti, i)
  ceph = flush(ceph)
  verify(ioctx, ino, expected_bt, 0)

i += 1

# kill-mds-at-openc-1
# create /a/b/c
# restart-mds with kill-mds-at-replay-1
# restart-mds
# flush
# verify
#if not test or test == i:
#  kill_mds(ceph, 'openc', 1)
#  ino, expected_bt = make_abc(ceph, rooti, i)
#  kill_mds(ceph, 'replay', 1)
#  ceph = flush(ceph)
#  verify(ioctx, ino, expected_bt, 0)

#i += 1


# create /a/b/c
# flush
# restart-mds kill-mds-at-replay-1
# restart-mds
# verify

ioctx.close()
rados.shutdown()
ceph.shutdown()


