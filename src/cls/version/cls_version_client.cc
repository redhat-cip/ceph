#include <errno.h>

#include "include/types.h"
#include "cls/version/cls_version_ops.h"
#include "include/rados/librados.hpp"

using namespace librados;


void cls_version_set(librados::ObjectWriteOperation& op, obj_version& objv)
{
  bufferlist in;
  cls_version_set_op call;
  call.objv = objv;
  ::encode(call, in);
  op.exec("version", "set", in);
}

void cls_version_inc(librados::ObjectWriteOperation& op)
{
  bufferlist in;
  cls_version_inc_op call;
  ::encode(call, in);
  op.exec("version", "inc", in);
}

void cls_version_inc(librados::ObjectWriteOperation& op, obj_version& objv, VersionCond cond)
{
  bufferlist in;
  cls_version_inc_op call;
  call.objv = objv;
  
  obj_version_cond c;
  c.cond = cond;
  c.ver = objv;

  call.conds.push_back(c);

  ::encode(call, in);
  op.exec("version", "inc_cond", in);
}

void cls_version_check(librados::ObjectOperation& op, obj_version& objv, VersionCond cond)
{
  bufferlist in;
  cls_version_inc_op call;
  call.objv = objv;

  obj_version_cond c;
  c.cond = cond;
  c.ver = objv;

  call.conds.push_back(c);

  ::encode(call, in);
  op.exec("version", "check_conds", in);
}

int cls_version_read(librados::IoCtx& io_ctx, string& oid, obj_version *ver)
{
  bufferlist in, out;
  int r = io_ctx.exec(oid, "version", "read", in, out);
  if (r < 0)
    return r;

  cls_version_read_ret ret;
  try {
    bufferlist::iterator iter = out.begin();
    ::decode(ret, iter);
  } catch (buffer::error& err) {
    return -EIO;
  }

  *ver = ret.objv;

  return r;
}