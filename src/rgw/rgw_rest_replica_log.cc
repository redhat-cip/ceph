// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */
#include "common/ceph_json.h"
#include "common/strtol.h"
#include "rgw_rest.h"
#include "rgw_op.h"
#include "rgw_rest_s3.h"
#include "rgw_rest_replica_log.h"
#include "rgw_client_io.h"
#include "common/errno.h"

#define dout_subsys ceph_subsys_rgw

void RGWOp_MDLog_SetBounds::execute() {
  string id = s->args.get("id"),
         marker = s->args.get("marker"),
         time = s->args.get("time"),
         daemon_id = s->args.get("daemon_id");

  if (id.empty() ||
      marker.empty() ||
      time.empty() ||
      daemon_id.empty()) {
    dout(5) << "Error - invalid parameter list" << dendl;
    http_ret = -EINVAL;
    return;
  }
  
  http_ret = 0;
}

void RGWOp_MDLog_GetBounds::execute() {
  string id = s->args.get("id");

  if (id.empty()) {
    dout(5) << " Error - invalid parameter list" << dendl;
    http_ret = -EINVAL;
    return;
  }

  http_ret = 0;
}

void RGWOp_MDLog_GetBounds::send_response() {
  set_req_state_err(s, http_ret);
  dump_errno(s);
  end_header(s);

  if (http_ret < 0)
    return;
}

void RGWOp_MDLog_DeleteBounds::execute() {
  string id = s->args.get("id"),
         daemon_id = s->args.get("daemon_id");

  if (id.empty() ||
      daemon_id.empty()) {
    dout(5) << "Error - invalid parameter list" << dendl;
    http_ret = -EINVAL;
    return;
  }
  
  http_ret = 0;
}

void RGWOp_DATALog_SetBounds::execute() {
  string id = s->args.get("id"),
         marker = s->args.get("marker"),
         time = s->args.get("time"),
         daemon_id = s->args.get("daemon_id");

  if (id.empty() ||
      marker.empty() ||
      time.empty() ||
      daemon_id.empty()) {
    dout(5) << "Error - invalid parameter list" << dendl;
    http_ret = -EINVAL;
    return;
  }
  
  http_ret = 0;
}

void RGWOp_DATALog_GetBounds::execute() {
  string id = s->args.get("id");

  if (id.empty()) {
    dout(5) << " Error - invalid parameter list" << dendl;
    http_ret = -EINVAL;
    return;
  }

  http_ret = 0;
}

void RGWOp_DATALog_GetBounds::send_response() {
  set_req_state_err(s, http_ret);
  dump_errno(s);
  end_header(s);

  if (http_ret < 0)
    return;
}

void RGWOp_DATALog_DeleteBounds::execute() {
  string id = s->args.get("id"),
         daemon_id = s->args.get("daemon_id");

  if (id.empty() ||
      daemon_id.empty()) {
    dout(5) << "Error - invalid parameter list" << dendl;
    http_ret = -EINVAL;
    return;
  }
  
  http_ret = 0;
}

void RGWOp_BILog_SetBounds::execute() {
  string bucket = s->args.get("bucket"),
         marker = s->args.get("marker"),
         time = s->args.get("time"),
         daemon_id = s->args.get("daemon_id");

  if (bucket.empty() ||
      marker.empty() ||
      time.empty() ||
      daemon_id.empty()) {
    dout(5) << "Error - invalid parameter list" << dendl;
    http_ret = -EINVAL;
    return;
  }
  
  http_ret = 0;
}

void RGWOp_BILog_GetBounds::execute() {
  string bucket = s->args.get("bucket");

  if (bucket.empty()) {
    dout(5) << " Error - invalid parameter list" << dendl;
    http_ret = -EINVAL;
    return;
  }

  http_ret = 0;
}

void RGWOp_BILog_GetBounds::send_response() {
  set_req_state_err(s, http_ret);
  dump_errno(s);
  end_header(s);

  if (http_ret < 0)
    return;
}

void RGWOp_BILog_DeleteBounds::execute() {
  string bucket = s->args.get("bucket"),
         daemon_id = s->args.get("daemon_id");

  if (bucket.empty() ||
      daemon_id.empty()) {
    dout(5) << "Error - invalid parameter list" << dendl;
    http_ret = -EINVAL;
    return;
  }
  
  http_ret = 0;
}

RGWOp *RGWHandler_ReplicaLog::op_get() {
  bool exists;
  string type = s->args.get("type", &exists);

  if (!exists) {
    return NULL;
  }

  if (type.compare("metadata") == 0) {
    return new RGWOp_MDLog_GetBounds;
  } else if (type.compare("bucket-index") == 0) {
    return new RGWOp_BILog_GetBounds;
  } else if (type.compare("data") == 0) {
    return new RGWOp_DATALog_GetBounds;
  }
  return NULL;
}

RGWOp *RGWHandler_ReplicaLog::op_delete() {
  bool exists;
  string type = s->args.get("type", &exists);

  if (!exists) {
    return NULL;
  }

  if (type.compare("metadata") == 0)
    return new RGWOp_MDLog_DeleteBounds;
  else if (type.compare("bucket-index") == 0) 
    return new RGWOp_BILog_DeleteBounds;
  else if (type.compare("data") == 0)
    return new RGWOp_DATALog_DeleteBounds;
  return NULL;
}

RGWOp *RGWHandler_ReplicaLog::op_post() {
  bool exists;
  string type = s->args.get("type", &exists);

  if (!exists) {
    return NULL;
  }

  if (type.compare("metadata") == 0) {
    return new RGWOp_MDLog_SetBounds;
  } else if (type.compare("bucket-index") == 0) {
    return new RGWOp_BILog_SetBounds;
  } else if (type.compare("data") == 0) {
    return new RGWOp_DATALog_SetBounds;
  }
  return NULL;
}

