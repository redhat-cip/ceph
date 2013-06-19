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
#ifndef CEPH_RGW_REST_REPLICA_LOG_H
#define CEPH_RGW_REST_REPLICA_LOG_H

class RGWOp_MDLog_GetBounds : public RGWRESTOp {
  int http_ret;
public:
  RGWOp_MDLog_GetBounds() : http_ret(0) {}
  ~RGWOp_MDLog_GetBounds() {}

  int check_caps(RGWUserCaps& caps) {
    return caps.check_cap("mdlog", RGW_CAP_READ);
  }
  int verify_permission() {
    return check_caps(s->user.caps);
  }
  void execute();
  virtual void send_response();
  virtual const char *name() {
    return "get_mdlog_bounds";
  }
};

class RGWOp_MDLog_SetBounds : public RGWRESTOp {
public:
  RGWOp_MDLog_SetBounds() {}
  ~RGWOp_MDLog_SetBounds() {}

  int check_caps(RGWUserCaps& caps) {
    return caps.check_cap("mdlog", RGW_CAP_WRITE);
  }
  void execute();
  virtual const char *name() {
    return "set_mdlog_bounds";
  }
};

class RGWOp_MDLog_DeleteBounds : public RGWRESTOp {
public:
  RGWOp_MDLog_DeleteBounds() {}
  ~RGWOp_MDLog_DeleteBounds() {}

  int check_caps(RGWUserCaps& caps) {
    return caps.check_cap("mdlog", RGW_CAP_WRITE);
  }
  void execute();
  virtual const char *name() {
    return "delete_mdlog_bounds";
  }
};

class RGWOp_DATALog_GetBounds : public RGWRESTOp {
  int http_ret;
public:
  RGWOp_DATALog_GetBounds() : http_ret(0) {}
  ~RGWOp_DATALog_GetBounds() {}

  int check_caps(RGWUserCaps& caps) {
    return caps.check_cap("datalog", RGW_CAP_READ);
  }
  int verify_permission() {
    return check_caps(s->user.caps);
  }
  void execute();
  virtual void send_response();
  virtual const char *name() {
    return "get_datalog_bounds";
  }
};

class RGWOp_DATALog_SetBounds : public RGWRESTOp {
public:
  RGWOp_DATALog_SetBounds() {}
  ~RGWOp_DATALog_SetBounds() {}

  int check_caps(RGWUserCaps& caps) {
    return caps.check_cap("datalog", RGW_CAP_WRITE);
  }
  void execute();
  virtual const char *name() {
    return "set_datalog_bounds";
  }
};

class RGWOp_DATALog_DeleteBounds : public RGWRESTOp {
public:
  RGWOp_DATALog_DeleteBounds() {}
  ~RGWOp_DATALog_DeleteBounds() {}

  int check_caps(RGWUserCaps& caps) {
    return caps.check_cap("datalog", RGW_CAP_WRITE);
  }
  void execute();
  virtual const char *name() {
    return "delete_datalog_bounds";
  }
};

class RGWOp_BILog_GetBounds : public RGWRESTOp {
  int http_ret;
public:
  RGWOp_BILog_GetBounds() : http_ret(0) {}
  ~RGWOp_BILog_GetBounds() {}

  int check_caps(RGWUserCaps& caps) {
    return caps.check_cap("bilog", RGW_CAP_READ);
  }
  int verify_permission() {
    return check_caps(s->user.caps);
  }
  void execute();
  virtual void send_response();
  virtual const char *name() {
    return "get_bilog_bounds";
  }
};

class RGWOp_BILog_SetBounds : public RGWRESTOp {
public:
  RGWOp_BILog_SetBounds() {}
  ~RGWOp_BILog_SetBounds() {}

  int check_caps(RGWUserCaps& caps) {
    return caps.check_cap("bilog", RGW_CAP_WRITE);
  }
  void execute();
  virtual const char *name() {
    return "set_bilog_bounds";
  }
};

class RGWOp_BILog_DeleteBounds : public RGWRESTOp {
public:
  RGWOp_BILog_DeleteBounds() {}
  ~RGWOp_BILog_DeleteBounds() {}

  int check_caps(RGWUserCaps& caps) {
    return caps.check_cap("bilog", RGW_CAP_WRITE);
  }
  void execute();
  virtual const char *name() {
    return "delete_bilog_bounds";
  }
};

class RGWHandler_ReplicaLog : public RGWHandler_Auth_S3 {
protected:
  RGWOp *op_get();
  RGWOp *op_delete();
  RGWOp *op_post();

  int read_permissions(RGWOp*) {
    return 0;
  }
public:
  RGWHandler_ReplicaLog() : RGWHandler_Auth_S3() {}
  virtual ~RGWHandler_ReplicaLog() {}
};

class RGWRESTMgr_ReplicaLog : public RGWRESTMgr {
public:
  RGWRESTMgr_ReplicaLog() {}
  virtual ~RGWRESTMgr_ReplicaLog() {}

  virtual RGWHandler *get_handler(struct req_state *s){
    return new RGWHandler_ReplicaLog;
  }
};

#endif /*!CEPH_RGW_REST_REPLICA_LOG_H*/
