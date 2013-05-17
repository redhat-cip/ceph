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
#include "rgw_rest.h"
#include "rgw_op.h"
#include "rgw_rest_s3.h"
#include "rgw_rest_log.h"
#include "rgw_client_io.h"
#include "common/errno.h"

#define dout_subsys ceph_subsys_rgw

static int parse_date_str(string& in, utime_t& out) {
  uint64_t epoch = 0;

  if (!in.empty()) {
    if (parse_date(in, &epoch) < 0) {
      dout(5) << "Error parsing date " << in << dendl;
      return -EINVAL;
    }
  }
  out = utime_t(epoch, 0);
  return 0;
}

void RGWOp_MDLog_List::execute() {
  string   st = s->args.get("start-time"),
           et = s->args.get("end-time");
  utime_t  ut_st, 
           ut_et;
  void    *handle;
  list<cls_log_entry> entries;

  if (parse_date_str(st, ut_st) < 0) {
    http_ret = -EINVAL;
    return;
  }

  if (parse_date_str(et, ut_et) < 0) {
    http_ret = -EINVAL;
    return;
  }

  RGWMetadataLog *meta_log = store->meta_mgr->get_log();

  meta_log->init_list_entries(store, ut_st, ut_et, &handle);

  bool truncated;

  s->formatter->open_array_section("entries");
  do {
    http_ret = meta_log->list_entries(handle, 1000, entries, &truncated);
    if (http_ret < 0) {
      return;
    }

    for (list<cls_log_entry>::iterator iter = entries.begin(); 
         iter != entries.end(); ++iter) {
      cls_log_entry& entry = *iter;
      store->meta_mgr->dump_log_entry(entry, s->formatter);
    }
  } while (truncated);

  s->formatter->close_section();

  http_ret = 0;
}

void RGWOp_MDLog_Delete::execute() {
  string   st = s->args.get("start-time"),
           et = s->args.get("end-time");
  utime_t  ut_st, 
           ut_et;

  http_ret = 0;
  if (st.empty() || et.empty()) {
    http_ret = -EINVAL;
    return;
  }

  if (parse_date_str(st, ut_st) < 0) {
    http_ret = -EINVAL;
    return;
  }

  if (parse_date_str(et, ut_et) < 0) {
    http_ret = -EINVAL;
    return;
  }
  RGWMetadataLog *meta_log = store->meta_mgr->get_log();

  http_ret = meta_log->trim(store, ut_st, ut_et);
}

void RGWOp_BILog_List::execute() {
  string bucket_name = s->args.get("bucket"),
         marker = s->args.get("marker"),
         max_entries_str = s->args.get("max-entries");
  RGWBucketInfo bucket_info;
  int max_entries = -1;

  if (bucket_name.empty()) {
    dout(5) << "ERROR: bucket not specified" << dendl;
    http_ret = -EINVAL;
    return;
  }

  http_ret = store->get_bucket_info(NULL, bucket_name, bucket_info);
  if (http_ret < 0) {
    dout(5) << "could not get bucket info for bucket=" << bucket_name << dendl;
    return;
  }

  s->formatter->open_array_section("entries");
  bool truncated;
  int count = 0;
  istringstream ss(max_entries_str);
  
  ss >> max_entries;
  if (max_entries < 0)
    max_entries = 1000;

  do {
    list<rgw_bi_log_entry> entries;
    http_ret = store->list_bi_log_entries(bucket_info.bucket, 
                                          marker, max_entries - count, 
                                          entries, &truncated);
    if (http_ret < 0) {
      dout(5) << "ERROR: list_bi_log_entries()" << dendl;
      return;
    }

    count += entries.size();

    for (list<rgw_bi_log_entry>::iterator iter = entries.begin(); iter != entries.end(); ++iter) {
      rgw_bi_log_entry& entry = *iter;
      encode_json("entry", entry, s->formatter);

      marker = entry.id;
    }
  } while (truncated && count < max_entries);

  s->formatter->close_section();
  http_ret = 0;
}

void RGWOp_BILog_Delete::execute() {
  string bucket_name = s->args.get("bucket"),
         start_marker = s->args.get("start-marker"),
         end_marker = s->args.get("end-marker");
  RGWBucketInfo bucket_info;

  http_ret = 0;
  if (bucket_name.empty() || 
      start_marker.empty() ||
      end_marker.empty()) {
    dout(5) << "ERROR: bucket, start-marker, end-marker are mandatory" << dendl;
    http_ret = -EINVAL;
    return;
  }
  http_ret = store->get_bucket_info(NULL, bucket_name, bucket_info);
  if (http_ret < 0) {
    dout(5) << "could not get bucket info for bucket=" << bucket_name << dendl;
    return;
  }
  http_ret = store->trim_bi_log_entries(bucket_info.bucket, start_marker, end_marker);
  if (http_ret < 0) {
    dout(5) << "ERROR: trim_bi_log_entries() " << dendl;
  }
  return;
}

RGWOp *RGWHandler_Log::op_get() {
  bool exists;
  string type = s->args.get("type", &exists);

  if (!exists) {
    return NULL;
  }

  if (type.compare("metadata") == 0)
    return new RGWOp_MDLog_List;
  else if (type.compare("bucket-index") == 0) 
    return new RGWOp_BILog_List;
  return NULL;
}

RGWOp *RGWHandler_Log::op_delete() {
  bool exists;
  string type = s->args.get("type", &exists);

  if (!exists) {
    return NULL;
  }

  if (type.compare("metadata") == 0)
    return new RGWOp_MDLog_Delete;
  else if (type.compare("bucket-index") == 0) 
    return new RGWOp_BILog_Delete;
  return NULL;
}
