#include <errno.h>

#include <string>
#include <map>

#include "common/errno.h"
#include "rgw_rados.h"
#include "rgw_acl.h"

#include "include/types.h"
#include "rgw_user.h"
#include "rgw_string.h"

// until everything is moved from rgw_common
#include "rgw_common.h"

#define dout_subsys ceph_subsys_rgw

using namespace std;


/**
 * Get the anonymous (ie, unauthenticated) user info.
 */
void rgw_get_anon_user(RGWUserInfo& info)
{
  info.user_id = RGW_USER_ANON_ID;
  info.display_name.clear();
  info.access_keys.clear();
}

bool rgw_user_is_authenticated(RGWUserInfo& info)
{
  return (info.user_id != RGW_USER_ANON_ID);
}

/**
 * Save the given user information to storage.
 * Returns: 0 on success, -ERR# on failure.
 */
int rgw_store_user_info(RGWRados *store, RGWUserInfo& info, RGWUserInfo *old_info, bool exclusive)
{
  bufferlist bl;
  info.encode(bl);
  string md5;
  int ret;
  map<string,bufferlist> attrs;

  map<string, RGWAccessKey>::iterator iter;
  for (iter = info.swift_keys.begin(); iter != info.swift_keys.end(); ++iter) {
    if (old_info && old_info->swift_keys.count(iter->first) != 0)
      continue;
    RGWAccessKey& k = iter->second;
    /* check if swift mapping exists */
    RGWUserInfo inf;
    int r = rgw_get_user_info_by_swift(store, k.id, inf);
    if (r >= 0 && inf.user_id.compare(info.user_id) != 0) {
      ldout(store->ctx(), 0) << "WARNING: can't store user info, swift id already mapped to another user" << dendl;
      return -EEXIST;
    }
  }

  if (info.access_keys.size()) {
    /* check if access keys already exist */
    RGWUserInfo inf;
    map<string, RGWAccessKey>::iterator iter = info.access_keys.begin();
    for (; iter != info.access_keys.end(); ++iter) {
      RGWAccessKey& k = iter->second;
      if (old_info && old_info->access_keys.count(iter->first) != 0)
        continue;
      int r = rgw_get_user_info_by_access_key(store, k.id, inf);
      if (r >= 0 && inf.user_id.compare(info.user_id) != 0) {
        ldout(store->ctx(), 0) << "WARNING: can't store user info, access key already mapped to another user" << dendl;
        return -EEXIST;
      }
    }
  }

  RGWUID ui;
  ui.user_id = info.user_id;

  bufferlist link_bl;
  ::encode(ui, link_bl);

  bufferlist data_bl;
  ::encode(ui, data_bl);
  ::encode(info, data_bl);

  ret = rgw_put_system_obj(store, store->params.user_uid_pool, info.user_id, data_bl.c_str(), data_bl.length(), exclusive);
  if (ret < 0)
    return ret;

  if (info.user_email.size()) {
    if (!old_info ||
        old_info->user_email.compare(info.user_email) != 0) { /* only if new index changed */
      ret = rgw_put_system_obj(store, store->params.user_email_pool, info.user_email, link_bl.c_str(), link_bl.length(), exclusive);
      if (ret < 0)
        return ret;
    }
  }

  if (info.access_keys.size()) {
    map<string, RGWAccessKey>::iterator iter = info.access_keys.begin();
    for (; iter != info.access_keys.end(); ++iter) {
      RGWAccessKey& k = iter->second;
      if (old_info && old_info->access_keys.count(iter->first) != 0)
	continue;

      ret = rgw_put_system_obj(store, store->params.user_keys_pool, k.id, link_bl.c_str(), link_bl.length(), exclusive);
      if (ret < 0)
        return ret;
    }
  }

  map<string, RGWAccessKey>::iterator siter;
  for (siter = info.swift_keys.begin(); siter != info.swift_keys.end(); ++siter) {
    RGWAccessKey& k = siter->second;
    if (old_info && old_info->swift_keys.count(siter->first) != 0)
      continue;

    ret = rgw_put_system_obj(store, store->params.user_swift_pool, k.id, link_bl.c_str(), link_bl.length(), exclusive);
    if (ret < 0)
      return ret;
  }

  return ret;
}

int rgw_get_user_info_from_index(RGWRados *store, string& key, rgw_bucket& bucket, RGWUserInfo& info)
{
  bufferlist bl;
  RGWUID uid;

  int ret = rgw_get_obj(store, NULL, bucket, key, bl);
  if (ret < 0)
    return ret;

  bufferlist::iterator iter = bl.begin();
  try {
    ::decode(uid, iter);
    return rgw_get_user_info_by_uid(store, uid.user_id, info);
  } catch (buffer::error& err) {
    ldout(store->ctx(), 0) << "ERROR: failed to decode user info, caught buffer::error" << dendl;
    return -EIO;
  }

  return 0;
}

/**
 * Given an email, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
int rgw_get_user_info_by_uid(RGWRados *store, string& uid, RGWUserInfo& info)
{
  bufferlist bl;
  RGWUID user_id;

  int ret = rgw_get_obj(store, NULL, store->params.user_uid_pool, uid, bl);
  if (ret < 0)
    return ret;

  bufferlist::iterator iter = bl.begin();
  try {
    ::decode(user_id, iter);
    if (user_id.user_id.compare(uid) != 0) {
      lderr(store->ctx())  << "ERROR: rgw_get_user_info_by_uid(): user id mismatch: " << user_id.user_id << " != " << uid << dendl;
      return -EIO;
    }
    if (!iter.end()) {
      ::decode(info, iter);
    }
  } catch (buffer::error& err) {
    ldout(store->ctx(), 0) << "ERROR: failed to decode user info, caught buffer::error" << dendl;
    return -EIO;
  }

  return 0;
}

/**
 * Given an email, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
int rgw_get_user_info_by_email(RGWRados *store, string& email, RGWUserInfo& info)
{
  return rgw_get_user_info_from_index(store, email, store->params.user_email_pool, info);
}

/**
 * Given an swift username, finds the user_info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
extern int rgw_get_user_info_by_swift(RGWRados *store, string& swift_name, RGWUserInfo& info)
{
  return rgw_get_user_info_from_index(store, swift_name, store->params.user_swift_pool, info);
}

/**
 * Given an access key, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
extern int rgw_get_user_info_by_access_key(RGWRados *store, string& access_key, RGWUserInfo& info)
{
  return rgw_get_user_info_from_index(store, access_key, store->params.user_keys_pool, info);
}

static void get_buckets_obj(string& user_id, string& buckets_obj_id)
{
  buckets_obj_id = user_id;
  buckets_obj_id += RGW_BUCKETS_OBJ_PREFIX;
}

static int rgw_read_buckets_from_attr(RGWRados *store, string& user_id, RGWUserBuckets& buckets)
{
  bufferlist bl;
  rgw_obj obj(store->params.user_uid_pool, user_id);
  int ret = store->get_attr(NULL, obj, RGW_ATTR_BUCKETS, bl);
  if (ret)
    return ret;

  bufferlist::iterator iter = bl.begin();
  try {
    buckets.decode(iter);
  } catch (buffer::error& err) {
    ldout(store->ctx(), 0) << "ERROR: failed to decode buckets info, caught buffer::error" << dendl;
    return -EIO;
  }
  return 0;
}

/**
 * Get all the buckets owned by a user and fill up an RGWUserBuckets with them.
 * Returns: 0 on success, -ERR# on failure.
 */
int rgw_read_user_buckets(RGWRados *store, string user_id, RGWUserBuckets& buckets, bool need_stats)
{
  int ret;
  buckets.clear();
  if (store->supports_omap()) {
    string buckets_obj_id;
    get_buckets_obj(user_id, buckets_obj_id);
    bufferlist bl;
    rgw_obj obj(store->params.user_uid_pool, buckets_obj_id);
    bufferlist header;
    map<string,bufferlist> m;

    ret = store->omap_get_all(obj, header, m);
    if (ret == -ENOENT)
      ret = 0;

    if (ret < 0)
      return ret;

    for (map<string,bufferlist>::iterator q = m.begin(); q != m.end(); q++) {
      bufferlist::iterator iter = q->second.begin();
      RGWBucketEnt bucket;
      ::decode(bucket, iter);
      buckets.add(bucket);
    }
  } else {
    ret = rgw_read_buckets_from_attr(store, user_id, buckets);
    switch (ret) {
    case 0:
      break;
    case -ENODATA:
      ret = 0;
      return 0;
    default:
      return ret;
    }
  }

  list<string> buckets_list;

  if (need_stats) {
    map<string, RGWBucketEnt>& m = buckets.get_buckets();
    int r = store->update_containers_stats(m);
    if (r < 0)
      ldout(store->ctx(), 0) << "ERROR: could not get stats for buckets" << dendl;

  }
  return 0;
}

/**
 * Store the set of buckets associated with a user on a n xattr
 * not used with all backends
 * This completely overwrites any previously-stored list, so be careful!
 * Returns 0 on success, -ERR# otherwise.
 */
int rgw_write_buckets_attr(RGWRados *store, string user_id, RGWUserBuckets& buckets)
{
  bufferlist bl;
  buckets.encode(bl);

  rgw_obj obj(store->params.user_uid_pool, user_id);

  int ret = store->set_attr(NULL, obj, RGW_ATTR_BUCKETS, bl);

  return ret;
}

int rgw_add_bucket(RGWRados *store, string user_id, rgw_bucket& bucket)
{
  int ret;
  string& bucket_name = bucket.name;

  if (store->supports_omap()) {
    bufferlist bl;

    RGWBucketEnt new_bucket;
    new_bucket.bucket = bucket;
    new_bucket.size = 0;
    time(&new_bucket.mtime);
    ::encode(new_bucket, bl);

    string buckets_obj_id;
    get_buckets_obj(user_id, buckets_obj_id);

    rgw_obj obj(store->params.user_uid_pool, buckets_obj_id);
    ret = store->omap_set(obj, bucket_name, bl);
    if (ret < 0) {
      ldout(store->ctx(), 0) << "ERROR: error adding bucket to directory: "
          << cpp_strerror(-ret)<< dendl;
    }
  } else {
    RGWUserBuckets buckets;

    ret = rgw_read_user_buckets(store, user_id, buckets, false);
    RGWBucketEnt new_bucket;

    switch (ret) {
    case 0:
    case -ENOENT:
    case -ENODATA:
      new_bucket.bucket = bucket;
      new_bucket.size = 0;
      time(&new_bucket.mtime);
      buckets.add(new_bucket);
      ret = rgw_write_buckets_attr(store, user_id, buckets);
      break;
    default:
      ldout(store->ctx(), 10) << "rgw_write_buckets_attr returned " << ret << dendl;
      break;
    }
  }

  return ret;
}

int rgw_remove_user_bucket_info(RGWRados *store, string user_id, rgw_bucket& bucket)
{
  int ret;

  if (store->supports_omap()) {
    bufferlist bl;

    string buckets_obj_id;
    get_buckets_obj(user_id, buckets_obj_id);

    rgw_obj obj(store->params.user_uid_pool, buckets_obj_id);
    ret = store->omap_del(obj, bucket.name);
    if (ret < 0) {
      ldout(store->ctx(), 0) << "ERROR: error removing bucket from directory: "
          << cpp_strerror(-ret)<< dendl;
    }
  } else {
    RGWUserBuckets buckets;

    ret = rgw_read_user_buckets(store, user_id, buckets, false);

    if (ret == 0 || ret == -ENOENT) {
      buckets.remove(bucket.name);
      ret = rgw_write_buckets_attr(store, user_id, buckets);
    }
  }

  return ret;
}

int rgw_remove_key_index(RGWRados *store, RGWAccessKey& access_key)
{
  rgw_obj obj(store->params.user_keys_pool, access_key.id);
  int ret = store->delete_obj(NULL, obj);
  return ret;
}

int rgw_remove_uid_index(RGWRados *store, string& uid)
{
  rgw_obj obj(store->params.user_uid_pool, uid);
  int ret = store->delete_obj(NULL, obj);
  return ret;
}

int rgw_remove_email_index(RGWRados *store, string& email)
{
  rgw_obj obj(store->params.user_email_pool, email);
  int ret = store->delete_obj(NULL, obj);
  return ret;
}

int rgw_remove_swift_name_index(RGWRados *store, string& swift_name)
{
  rgw_obj obj(store->params.user_swift_pool, swift_name);
  int ret = store->delete_obj(NULL, obj);
  return ret;
}

/**
 * delete a user's presence from the RGW system.
 * First remove their bucket ACLs, then delete them
 * from the user and user email pools. This leaves the pools
 * themselves alone, as well as any ACLs embedded in object xattrs.
 */
int rgw_delete_user(RGWRados *store, RGWUserInfo& info) {
  RGWUserBuckets user_buckets;
  int ret = rgw_read_user_buckets(store, info.user_id, user_buckets, false);
  if (ret < 0)
    return ret;

  map<string, RGWBucketEnt>& buckets = user_buckets.get_buckets();
  vector<rgw_bucket> buckets_vec;
  for (map<string, RGWBucketEnt>::iterator i = buckets.begin();
      i != buckets.end();
      ++i) {
    RGWBucketEnt& bucket = i->second;
    buckets_vec.push_back(bucket.bucket);
  }
  map<string, RGWAccessKey>::iterator kiter = info.access_keys.begin();
  for (; kiter != info.access_keys.end(); ++kiter) {
    ldout(store->ctx(), 10) << "removing key index: " << kiter->first << dendl;
    ret = rgw_remove_key_index(store, kiter->second);
    if (ret < 0 && ret != -ENOENT) {
      ldout(store->ctx(), 0) << "ERROR: could not remove " << kiter->first << " (access key object), should be fixed (err=" << ret << ")" << dendl;
      return ret;
    }
  }

  map<string, RGWAccessKey>::iterator siter = info.swift_keys.begin();
  for (; siter != info.swift_keys.end(); ++siter) {
    RGWAccessKey& k = siter->second;
    ldout(store->ctx(), 10) << "removing swift subuser index: " << k.id << dendl;
    /* check if swift mapping exists */
    ret = rgw_remove_swift_name_index(store, k.id);
    if (ret < 0 && ret != -ENOENT) {
      ldout(store->ctx(), 0) << "ERROR: could not remove " << k.id << " (swift name object), should be fixed (err=" << ret << ")" << dendl;
      return ret;
    }
  }

  rgw_obj email_obj(store->params.user_email_pool, info.user_email);
  ldout(store->ctx(), 10) << "removing email index: " << info.user_email << dendl;
  ret = store->delete_obj(NULL, email_obj);
  if (ret < 0 && ret != -ENOENT) {
    ldout(store->ctx(), 0) << "ERROR: could not remove " << info.user_id << ":" << email_obj << ", should be fixed (err=" << ret << ")" << dendl;
    return ret;
  }

  string buckets_obj_id;
  get_buckets_obj(info.user_id, buckets_obj_id);
  rgw_obj uid_bucks(store->params.user_uid_pool, buckets_obj_id);
  ldout(store->ctx(), 10) << "removing user buckets index" << dendl;
  ret = store->delete_obj(NULL, uid_bucks);
  if (ret < 0 && ret != -ENOENT) {
    ldout(store->ctx(), 0) << "ERROR: could not remove " << info.user_id << ":" << uid_bucks << ", should be fixed (err=" << ret << ")" << dendl;
    return ret;
  }
  
  rgw_obj uid_obj(store->params.user_uid_pool, info.user_id);
  ldout(store->ctx(), 10) << "removing user index: " << info.user_id << dendl;
  ret = store->delete_obj(NULL, uid_obj);
  if (ret < 0 && ret != -ENOENT) {
    ldout(store->ctx(), 0) << "ERROR: could not remove " << info.user_id << ":" << uid_obj << ", should be fixed (err=" << ret << ")" << dendl;
    return ret;
  }

  return 0;
}

/* new functionality */

static bool char_is_unreserved_url(char c)
{
  if (isalnum(c))
    return true;

  switch (c) {
  case '-':
  case '.':
  case '_':
  case '~':
    return true;
  default:
    return false;
  }
}

// define as static when changes complete
bool validate_access_key(string& key)
{
  const char *p = key.c_str();
  while (*p) {
    if (!char_is_unreserved_url(*p))
      return false;
    p++;
  }
  return true;
}

// define as static when changes complete
int remove_object(RGWRados *store, rgw_bucket& bucket, std::string& object)
{
  int ret = -EINVAL;
  RGWRadosCtx rctx(store);

  rgw_obj obj(bucket,object);

  ret = store->delete_obj((void *)&rctx, obj);

  return ret;
}

// define as static when changes complete
int remove_bucket(RGWRados *store, rgw_bucket& bucket, bool delete_children)
{
  int ret;
  map<RGWObjCategory, RGWBucketStats> stats;
  std::vector<RGWObjEnt> objs;
  std::string prefix, delim, marker, ns;
  map<string, bool> common_prefixes;
  rgw_obj obj;
  RGWBucketInfo info;
  bufferlist bl;

  ret = store->get_bucket_stats(bucket, stats);
  if (ret < 0)
    return ret;

  obj.bucket = bucket;
  int max = 1000;

  ret = rgw_get_obj(store, NULL, store->params.domain_root,\
           bucket.name, bl, NULL);

  bufferlist::iterator iter = bl.begin();
  try {
    ::decode(info, iter);
  } catch (buffer::error& err) {
    //cerr << "ERROR: could not decode buffer info, caught buffer::error" << std::endl;
    return -EIO;
  }

  if (delete_children) {
    ret = store->list_objects(bucket, max, prefix, delim, marker,\
            objs, common_prefixes,\
            false, ns, (bool *)false, NULL);

    if (ret < 0)
      return ret;

    while (objs.size() > 0) {
      std::vector<RGWObjEnt>::iterator it = objs.begin();
      for (it = objs.begin(); it != objs.end(); it++) {
        ret = remove_object(store, bucket, (*it).name);
        if (ret < 0)
          return ret;
      }
      objs.clear();

      ret = store->list_objects(bucket, max, prefix, delim, marker, objs, common_prefixes,
                                false, ns, (bool *)false, NULL);
      if (ret < 0)
        return ret;
    }
  }

  ret = store->delete_bucket(bucket);
  if (ret < 0) {
    //cerr << "ERROR: could not remove bucket " << bucket.name << std::endl;

    return ret;
  }

  ret = rgw_remove_user_bucket_info(store, info.owner, bucket);
  if (ret < 0) {
    //cerr << "ERROR: unable to remove user bucket information" << std::endl;
  }

  return ret;
}

static bool remove_old_indexes(RGWRados *store,\
         RGWUserInfo& old_info, RGWUserInfo& new_info, std::string& err_msg)
{
  int ret;
  bool success = true;

  if (!old_info.user_id.empty() && old_info.user_id.compare(new_info.user_id) != 0) {
    ret = rgw_remove_uid_index(store, old_info.user_id);
    if (ret < 0 && ret != -ENOENT) {
      err_msg =  "ERROR: could not remove index for uid " + old_info.user_id;
      success = false;
    }
  }

  if (!old_info.user_email.empty() &&
      old_info.user_email.compare(new_info.user_email) != 0) {
    ret = rgw_remove_email_index(store, old_info.user_email);
  if (ret < 0 && ret != -ENOENT) {
      err_msg = "ERROR: could not remove index for email " + old_info.user_email;
      success = false;
    }
  }

  map<string, RGWAccessKey>::iterator old_iter;
  for (old_iter = old_info.swift_keys.begin(); old_iter != old_info.swift_keys.end(); ++old_iter) {
    RGWAccessKey& swift_key = old_iter->second;
    map<string, RGWAccessKey>::iterator new_iter = new_info.swift_keys.find(swift_key.id);
    if (new_iter == new_info.swift_keys.end()) {
      ret = rgw_remove_swift_name_index(store, swift_key.id);
      if (ret < 0 && ret != -ENOENT) {
        err_msg =  "ERROR: could not remove index for swift_name " + swift_key.id;
        success = false;
      }
    }
  }

  return success;
}

static bool get_key_type(std::string requested_type,\
         int& dest, string& err_msg)
{
  if (strcasecmp(requested_type.c_str(), "swift") == 0) {
    dest = KEY_TYPE_SWIFT;
  } else if (strcasecmp(requested_type.c_str(), "s3") == 0) {
    dest = KEY_TYPE_S3;
  } else {
    err_msg = "bad key type";
    return false;
  }

  return true;
}

RGWAccessKeyPool::RGWAccessKeyPool(RGWUser *usr)
{
  if (!usr || usr->has_failed()) {
    keys_allowed = false;
    return;
  }

  store = usr->get_store();
  user = usr;
}

RGWAccessKeyPool::~RGWAccessKeyPool()
{

}

bool RGWAccessKeyPool::init(RGWUserAdminRequest& req)
{
  std::string uid = req.get_user_id();
  if (uid.compare(RGW_USER_ANON_ID) == 0) {
    keys_allowed = false;
    return false;
  }

  swift_keys = req.get_swift_keys();
  access_keys = req.get_access_keys();

  keys_allowed = true;

  return true;
}

static bool compare_key_owner(RGWUserAdminRequest& req, RGWUserInfo& info)
{
  std::string uid = req.get_user_id();
  std::string info_uid = info.user_id;

  if (info_uid.empty())
    return false;

  return (info_uid.compare(uid) == 0);
}

bool RGWAccessKeyPool::check_key_owner(RGWUserAdminRequest& req)
{
  bool duplicate = false;
  std::string access_key = req.get_access_key();

  RGWUserInfo dup_info;

  duplicate = (rgw_get_user_info_by_access_key(store, access_key, dup_info) >= 0);
  if (duplicate)
    return compare_key_owner(req, dup_info);

  duplicate = (rgw_get_user_info_by_swift(store, access_key, dup_info) >= 0);
  if (duplicate)
    return compare_key_owner(req, dup_info);

  std::string swift_kid = req.build_default_swift_kid();
  if (swift_kid.empty())
    return true;

  duplicate = (rgw_get_user_info_by_swift(store, access_key, dup_info) >= 0);
  if (duplicate)
    return compare_key_owner(req, dup_info);

  return true;
}

bool RGWAccessKeyPool::check_existing_key(RGWUserAdminRequest& req)
{
  bool existing_key = false;

  int key_type = req.get_key_type();
  std::string kid = req.get_access_key();
  std::string swift_kid = req.build_default_swift_kid();

  RGWUserInfo dup_info;

  if (kid.empty())
    return false;

  switch (key_type) {
    case KEY_TYPE_SWIFT:
      existing_key = swift_keys->count(kid);
      if (existing_key)
        break;

      if (swift_kid.empty())
        return false;

      existing_key = swift_keys->count(swift_kid);
      if (existing_key)
        req.set_access_key(swift_kid);

      break;
    case KEY_TYPE_S3:
      existing_key = access_keys->count(kid);
      break;
    default:
      existing_key = access_keys->count(kid);
      if (existing_key) {
        req.set_key_type(KEY_TYPE_S3);
        break;
      }

      existing_key = swift_keys->count(kid);
      if (existing_key) {
        req.set_key_type(KEY_TYPE_SWIFT);
        break;
      }

      if (swift_kid.empty())
        return false;

      existing_key = swift_keys->count(swift_kid);
      if (existing_key) {
        req.set_access_key(swift_kid);
        req.set_key_type(KEY_TYPE_SWIFT);
      }
  }

  if (existing_key)
    req.set_existing_key();

  return existing_key;
}

bool RGWAccessKeyPool::check_request(RGWUserAdminRequest& req,\
     std::string& err_msg)
{
  std::string subprocess_msg;
  RGWUserInfo dup_info;

  if (!req.is_initialized()) {
     if (!user->init(req)) {
       err_msg = "unable to initialize request";
       return false;
     }
  }

  if (!keys_allowed) {
    err_msg = "keys not allowed for this user";
    return false;
  }

  std::string access_key = req.get_access_key();
  std::string secret_key = req.get_secret_key();

  /* see if the access key or secret key was specified */
  if (!req.will_gen_access() && access_key.empty()) {
    err_msg = "empty access key";
    return false;
  }

  if (!req.will_gen_secret() && secret_key.empty()) {
    err_msg = "empty secret key";
    return false;
  }

  // one day it will be safe to force subusers to have swift keys
  //if (req.subuser_specified)
  //  req.key_type = KEY_TYPE_SWIFT;

  check_existing_key(req);

  // if a key type wasn't specified set it to s3
  if (req.get_key_type() < 0)
    req.set_key_type(KEY_TYPE_S3);

  return true;
}

// Generate a new random key
bool RGWAccessKeyPool::generate_key(RGWUserAdminRequest& req, std::string& err_msg)
{
  std::string duplicate_check_id;
  std::string id;
  std::string key;
  std::string subuser;

  std::pair<std::string, RGWAccessKey> key_pair;
  RGWAccessKey new_key;
  RGWUserInfo duplicate_check;

  int ret;
  int key_type = req.get_key_type();
  bool gen_access = req.will_gen_access();
  bool gen_secret = req.will_gen_secret();

  if (!keys_allowed) {
    err_msg = "access keys not allowed for this user";
    return false;
  }

  if (!gen_access) {
    id = req.get_access_key();

    if (!check_key_owner(req)) {
      err_msg = "access key: " + id + "owned by other user";
      return false;
    }
  }

  if (!gen_secret)
    key = req.get_secret_key();

  if (req.has_subuser())
    new_key.subuser = req.get_subuser();

  // Generate the secret key
  if (gen_secret) {
    char secret_key_buf[SECRET_KEY_LEN + 1];

    ret = gen_rand_base64(g_ceph_context, secret_key_buf, sizeof(secret_key_buf));
    if (ret < 0) {
      err_msg = "unable to generate secret key";
      return false;
    }

    key = secret_key_buf;
  }

  // Generate the access key
  if (key_type == KEY_TYPE_S3 && gen_access) {
    char public_id_buf[PUBLIC_ID_LEN + 1];

    do {
      int id_buf_size = sizeof(public_id_buf);
      ret = gen_rand_alphanumeric_upper(g_ceph_context,\
               public_id_buf, id_buf_size);

      if (ret < 0) {
        err_msg = "unable to generate access key";
        return false;
      }

      id = public_id_buf;
      if (!validate_access_key(id))
        continue;

    } while (!rgw_get_user_info_by_access_key(store, id, duplicate_check));
  }

  if (key_type == KEY_TYPE_SWIFT && gen_access) {
    id = req.build_default_swift_kid();

    // check that the access key doesn't exist
    if (rgw_get_user_info_by_swift(store, id, duplicate_check) >= 0) {
      err_msg = "swift key already owned by: " + subuser;
      return false;
    }
  }

  // finally create the new key
  new_key.id = id;
  new_key.key = key;

  key_pair.first = id;
  key_pair.second = new_key;

  if (key_type == KEY_TYPE_S3)
    access_keys->insert(key_pair);
  else if (key_type == KEY_TYPE_SWIFT)
    swift_keys->insert(key_pair);

  return true;
}

// modify an existing key
bool RGWAccessKeyPool::modify_key(RGWUserAdminRequest& req, std::string& err_msg)
{
  std::string id = req.get_access_key();
  std::string key = req.get_secret_key();
  int key_type = req.get_key_type();

  RGWAccessKey modify_key;

  pair<string, RGWAccessKey> key_pair;
  map<std::string, RGWAccessKey>::iterator kiter;

  if (id.empty()) {
    err_msg = "no access key specified";
    return false;
  }

  if (!req.has_existing_key()) {
    err_msg = "key does not exist";
    return false;
  }

  key_pair.first = id;

  if (key_type == KEY_TYPE_SWIFT) {
    kiter = swift_keys->find(id);
    modify_key = kiter->second;
  }

  if (key_type == KEY_TYPE_S3) {
    kiter = access_keys->find(id);
    modify_key = kiter->second;
  }

  if (req.will_gen_secret()) {
    char secret_key_buf[SECRET_KEY_LEN + 1];

    int ret;
    int key_buf_size = sizeof(secret_key_buf);
    ret  = gen_rand_base64(g_ceph_context, secret_key_buf, key_buf_size);
    if (ret < 0) {
      err_msg = "unable to generate secret key";
      return false;
    }

    key = secret_key_buf;
  }

  if (key.empty()) {
      err_msg = "empty secret key";
      return false;
  }

  // update the access key with the new secret key
  modify_key.key = key;
  key_pair.second = modify_key;


  if (key_type == KEY_TYPE_S3)
    access_keys->insert(key_pair);

  else if (key_type == KEY_TYPE_SWIFT)
    swift_keys->insert(key_pair);

  return true;
}

bool RGWAccessKeyPool::execute_add(RGWUserAdminRequest& req,\
         std::string& err_msg, bool defer_user_update)
{
  bool created;
  bool updated = true;

  std::string subprocess_msg;

  int op = GENERATE_KEY;

  // set the op
  if (req.has_existing_key())
    op = MODIFY_KEY;

  switch (op) {
  case GENERATE_KEY:
    created = generate_key(req, subprocess_msg);
    break;
  case MODIFY_KEY:
    created = modify_key(req, subprocess_msg);
    break;
  }

  if (!created)
    return false;

  // store the updated info
  if (!defer_user_update)
    updated = user->update(req, err_msg);

  if (!updated)
    return false;

  return true;
}

bool RGWAccessKeyPool::add(RGWUserAdminRequest& req, std::string& err_msg)
{
  return add(req, err_msg, false);
}

bool RGWAccessKeyPool::add(RGWUserAdminRequest& req, std::string& err_msg, bool defer_user_update)
{
  bool created;
  bool checked;
  std::string subprocess_msg;

  checked = check_request(req, subprocess_msg);
  if (!checked) {
    err_msg = "unable to parse request, " + subprocess_msg;
    return false;
  }

  created = execute_add(req, subprocess_msg, defer_user_update);
  if (!created) {
    err_msg = "unable to add access key, " + subprocess_msg;
    return false;
  }

  return true;
}

bool RGWAccessKeyPool::execute_remove(RGWUserAdminRequest& req, std::string& err_msg, bool defer_user_update)
{
  bool updated =  true;

  int key_type = req.get_key_type();
  std::string id = req.get_access_key();
  map<std::string, RGWAccessKey>::iterator kiter;
  map<std::string, RGWAccessKey> *keys_map;

  if (!req.has_existing_key()) {
    err_msg = "unable to find access key";
    return false;
  }

  // one day it will be safe to assume that subusers always have swift keys
  //if (req.subuser_specified)
  //  req.key_type = KEY_TYPE_SWIFT

  if (key_type == KEY_TYPE_S3) {
    keys_map = access_keys;
    kiter = keys_map->find(id);
  }

  else if (key_type == KEY_TYPE_SWIFT) {
    keys_map = swift_keys;
    kiter = keys_map->find(id);
  }

  int ret = rgw_remove_key_index(store, kiter->second);
  if (ret < 0) {
    err_msg = "unable to remove key index";
    return false;
  }

  keys_map->erase(kiter);

  if (!defer_user_update)
    updated =  user->update(req, err_msg);

  if (!updated)
    return false;

  return true;
}

bool RGWAccessKeyPool::remove(RGWUserAdminRequest& req, std::string& err_msg)
{
  return remove(req, err_msg, false);
}

bool RGWAccessKeyPool::remove(RGWUserAdminRequest& req, std::string& err_msg, bool defer_user_update)
{
  bool checked;
  bool removed;

  std::string subprocess_msg;

  checked = check_request(req, subprocess_msg);
  if (!checked) {
    err_msg = "unable to parse request, " + subprocess_msg;
    return false;
  }

  removed = execute_remove(req, subprocess_msg, defer_user_update);
  if (!removed) {
    err_msg = "unable to remove subuser, " + subprocess_msg;
    return false;
  }

  return true;
}

RGWSubUserPool::RGWSubUserPool(RGWUser *usr)
{
   if (!usr || usr->failure)
    subusers_allowed = false;

  store = usr->get_store();
  user = usr;
}

RGWSubUserPool::~RGWSubUserPool()
{

}

bool RGWSubUserPool::init(RGWUserAdminRequest& req)
{
  if (!subusers_allowed)
    return false;

  std::string uid = req.get_user_id();
  if (uid.compare(RGW_USER_ANON_ID) == 0) {
    subusers_allowed = false;
    return false;
  }

  subuser_map = req.get_subusers();
  if (subuser_map == NULL) {
    subusers_allowed = false;
    return false;
  }

  subusers_allowed = true;

  return true;
}

bool RGWSubUserPool::exists(std::string subuser)
{
  if (subuser.empty())
    return false;

  if (!subuser_map)
    return false;

  if (subuser_map->count(subuser))
    return true;

  return false;
}

bool RGWSubUserPool::check_request(RGWUserAdminRequest& req,\
        std::string& err_msg)
{
  bool initialized;
  bool existing = false;
  string subprocess_msg;
  std::string subuser = req.get_subuser();

  if (!req.is_initialized()) {
    initialized = user->init(req);
    if (!initialized) {
      err_msg = "unable to initialize user";
      return false;
    }
  }

  if (!subusers_allowed) {
    err_msg = "subusers not allowed for this user";
    return false;
  }

  if (subuser.empty() && !req.will_gen_subuser()) {
    err_msg = "empty subuser name";
    return false;
  }

  // check if the subuser exists
  if (!subuser.empty())
    existing = exists(subuser);

  if (existing)
    req.set_existing_subuser();

  return true;
}

bool RGWSubUserPool::execute_add(RGWUserAdminRequest& req,\
        std::string& err_msg, bool defer_user_update)
{
  bool updated = true;
  std::string subprocess_msg;

  RGWSubUser subuser;

  // no duplicates
  if (req.has_existing_subuser()) {
    err_msg = "subuser exists";
    return false;
  }

  // assumes key should be created
  if (req.has_key_op()) {
    bool keys_added = user->keys->add(req, subprocess_msg, true);
    if (!keys_added) {
      err_msg = "unable to create subuser key, " + subprocess_msg;
      return false;
    }
  }

  // create the subuser
  subuser.name = req.get_subuser();

  if (req.has_subuser_perm())
    subuser.perm_mask = req.get_subuser_perm();

  // insert the subuser into user info
  std::pair<std::string, RGWSubUser> subuser_pair;
  subuser_pair  = make_pair(req.subuser, subuser);
  subuser_map->insert(subuser_pair);

  // attempt to save the subuser
  if (!defer_user_update)
    updated = user->update(req, err_msg);

  if (!updated)
    return false;

  return true;
}

bool RGWSubUserPool::add(RGWUserAdminRequest& req, std::string& err_msg)
{
  return add(req, err_msg, false);
}

bool RGWSubUserPool::add(RGWUserAdminRequest& req, std::string& err_msg, bool defer_user_update)
{
  std::string subprocess_msg;
  bool checked;
  bool created;

  checked = check_request(req, subprocess_msg);
  if (!checked) {
    err_msg = "unable to parse request, " + subprocess_msg;
    return false;
  }

  created = execute_add(req, subprocess_msg, defer_user_update);
  if (!created) {
    err_msg = "unable to create subuser, " + subprocess_msg;
    return false;
  }

  return true;
}

bool RGWSubUserPool::execute_remove(RGWUserAdminRequest& req,\
        std::string& err_msg, bool defer_user_update)
{
  bool updated = true;
  std::string subprocess_msg;

  map<std::string, RGWSubUser>::iterator siter;

  if (!req.has_existing_subuser())
    err_msg = "subuser not found: " + req.subuser;

  if (req.will_purge_keys()) {
    bool removed = user->keys->remove(req, subprocess_msg, true);
    if (!removed) {
      err_msg = "unable to remove subuser keys, " + subprocess_msg;
      return false;
    }
  }

  //remove the subuser from the user info
  subuser_map->erase(siter);

  // attempt to save the subuser
  if (!defer_user_update)
    updated = user->update(req, err_msg);

  if (!updated)
    return false;

  return true;
}

bool RGWSubUserPool::remove(RGWUserAdminRequest& req, std::string& err_msg)
{
  return remove(req, err_msg, false);
}

bool RGWSubUserPool::remove(RGWUserAdminRequest& req, std::string& err_msg, bool defer_user_update)
{
  std::string subprocess_msg;
  bool checked;
  bool removed;

  checked = check_request(req, subprocess_msg);
  if (!checked) {
    err_msg = "unable to parse request, " + subprocess_msg;
    return false;
  }

  removed = execute_remove(req, subprocess_msg, defer_user_update);
  if (!removed) {
    err_msg = "unable to remove subuser, " + subprocess_msg;
    return false;
  }

  return true;
}

bool RGWSubUserPool::execute_modify(RGWUserAdminRequest& req, std::string& err_msg, bool defer_user_update)
{
  bool updated = true;
  std::string subprocess_msg;
  std::map<std::string, RGWSubUser>::iterator siter;
  std::pair<std::string, RGWSubUser> subuser_pair;

  std::string subuser_str = req.get_subuser();
  RGWSubUser subuser;

  if (!req.has_existing_subuser()) {
    err_msg = "subuser does not exist";
    return false;
  }

  subuser_pair.first = subuser_str;

  siter = subuser_map->find(subuser_str);
  subuser = siter->second;

  bool success = user->keys->add(req, subprocess_msg, true);
  if (!success) {
    err_msg = "unable to create subuser keys, " + subprocess_msg;
    return false;
  }

  if (req.has_subuser_perm())
    subuser.perm_mask = req.get_subuser_perm();

  subuser_pair.second = subuser;
  subuser_map->insert(subuser_pair);

  // attempt to save the subuser
  if (!defer_user_update)
    updated = user->update(req, err_msg);

  if (!updated)
    return false;

  return true;
}

bool RGWSubUserPool::modify(RGWUserAdminRequest& req, std::string& err_msg)
{
  return RGWSubUserPool::modify(req, err_msg, false);
}

bool RGWSubUserPool::modify(RGWUserAdminRequest& req, std::string& err_msg, bool defer_user_update)
{
  std::string subprocess_msg;
  bool checked;
  bool modified;

  RGWSubUser subuser;

  checked = check_request(req, subprocess_msg);
  if (!checked) {
    err_msg = "unable to parse request, " + subprocess_msg;
    return false;
  }

  modified = execute_modify(req, subprocess_msg, defer_user_update);
  if (!modified) {
    err_msg = "unable to modify subuser, " + subprocess_msg;
    return false;
  }

  return true;
}

RGWUserCapPool::RGWUserCapPool(RGWUser *usr)
{
  if (!user || usr->has_failed()) {
    caps_allowed = false;
  }

  user = usr;
}

RGWUserCapPool::~RGWUserCapPool()
{

}

bool RGWUserCapPool::init(RGWUserAdminRequest& req)
{
  std::string uid = req.get_user_id();
  if (uid == RGW_USER_ANON_ID) {
    caps_allowed = false;
    return false;
  }

  caps = req.get_caps_obj();
  if (!caps) {
    caps_allowed = false;
    return false;
  }

  caps_allowed = true;

  return true;
}

bool RGWUserCapPool::add(RGWUserAdminRequest& req, std::string& err_msg)
{
  return add(req, err_msg, false);
}

bool RGWUserCapPool::add(RGWUserAdminRequest& req, std::string& err_msg, bool defer_save)
{
  bool initialized;
  bool updated = true;
  std::string subprocess_msg;
  std::string caps_str = req.get_caps();

  if (!req.is_initialized()) {
    initialized = user->init(req);
    if (!initialized) {
      err_msg = "unable to initialize user";
      return false;
    }
  }

  if (!caps_allowed) {
    err_msg = "caps not allowed for this user";
    return false;
  }

  if (caps_str.empty()) {
    err_msg = "empty user caps";
    return false;
  }

  int r = caps->add_from_string(caps_str);
  if (r < 0) {
    err_msg = "unable to add caps: " + caps_str;
    return false;
  }

  if (!defer_save)
    updated = user->update(req, err_msg);

  if (!updated)
    return false;

  return true;
}

bool RGWUserCapPool::remove(RGWUserAdminRequest& req, std::string& err_msg)
{
  return remove(req, err_msg, false);
}

bool RGWUserCapPool::remove(RGWUserAdminRequest& req, std::string& err_msg, bool defer_save)
{
  bool initialized;
  bool updated = true;
  std::string subprocess_msg;

  std::string caps_str = req.get_caps();

  if (!req.is_initialized()) {
    initialized = user->init(req);
    if (!initialized) {
      err_msg = "unable to initialize user";
      return false;
    }
  }

  if (!caps_allowed) {
    err_msg = "caps not allowed for this user";
    return false;
  }

  if (caps_str.empty()) {
    err_msg = "empty user caps";
    return false;
  }

  int r = caps->remove_from_string(caps_str);
  if (r < 0) {
    err_msg = "unable to remove caps: " + caps_str;
    return false;
  }

  if (!defer_save)
    updated = user->update(req, err_msg);

  if (!updated)
    return false;

  return true;
}

RGWUser::RGWUser()
{
  // use anonymous user info as a placeholder
  rgw_get_anon_user(old_info);
  user_id = RGW_USER_ANON_ID;

  clear_failure();
  clear_populated();

  keys = NULL;
  caps = NULL;
  subusers = NULL;
}

RGWUser::RGWUser(RGWRados *storage, RGWUserAdminRequest& req)
{
  keys = NULL;
  caps = NULL;
  subusers = NULL;

  if (!init_storage(storage)) {
    set_failure();
    return;
  }

  if (!init(req))
    set_failure();
}


RGWUser::RGWUser(RGWRados *storage)
{
  if (!init_storage(storage))
    set_failure();
}

RGWUser::~RGWUser()
{
  clear_members();
}

void RGWUser::clear_members()
{
  if (keys != NULL)
    delete keys;

  if (caps != NULL)
    delete caps;

  if (subusers != NULL)
    delete subusers;
}

bool RGWUser::init_storage(RGWRados *storage)
{
  if (!storage) {
    set_failure();
    return false;
  }

  store = storage;

  clear_failure();
  clear_populated();

  /* API wrappers */
  keys = new RGWAccessKeyPool(this);
  caps = new RGWUserCapPool(this);
  subusers = new RGWSubUserPool(this);

  // use anonymous user info as a placeholder
  rgw_get_anon_user(old_info);
  user_id = RGW_USER_ANON_ID;

  return true;
}

bool RGWUser::init(RGWUserAdminRequest& req)
{
  bool found = false;
  std::string swift_user = req.build_default_swift_kid();
  std::string uid = req.get_user_id();
  std::string user_email = req.get_user_email();
  std::string access_key = req.get_access_key();

  RGWUserInfo user_info;

  clear_populated();
  clear_failure();

  if (!uid.empty() && (uid.compare(RGW_USER_ANON_ID) != 0))
    found = (rgw_get_user_info_by_uid(store, uid, user_info) >= 0);

  if (!user_email.empty() && !found)
    found = (rgw_get_user_info_by_email(store, user_email, user_info) >= 0);

  if (!swift_user.empty() && !found)
    found = (rgw_get_user_info_by_swift(store, swift_user, user_info) >= 0);

  if (!access_key.empty() && !found)
    found = (rgw_get_user_info_by_access_key(store, access_key, user_info) >= 0);

  if (found) {
    req.set_existing_user();
    req.set_user_info(user_info);

    old_info = user_info;
  }

  user_id = user_info.user_id;
  req.set_initialized();

  // this may have been called by a helper object
  bool initialized = init_members(req);
  if (!initialized)
    return false;

  return true;
}

bool RGWUser::init_members(RGWUserAdminRequest& req)
{
  bool initialized = false;

  if (!keys || !subusers || !caps)
    return false;

  initialized = keys->init(req);
  if (!initialized)
    return false;

  initialized = subusers->init(req);
  if (!initialized)
    return false;

  initialized = caps->init(req);
  if (!initialized)
    return false;

  return true;
}

bool RGWUser::update(RGWUserAdminRequest& req, std::string& err_msg)
{
  int ret;
  std::string subprocess_msg;
  RGWUserInfo user_info = req.get_user_info();

  if (!store) {
    err_msg = "couldn't initialize storage";
    return false;
  }

  // remove any existing user info from the RGW system
  if (is_populated()) {
    ret = remove_old_indexes(store, old_info, user_info, subprocess_msg);
    if (ret < 0) {
      err_msg = "unable to remove old user info, " + subprocess_msg;
      return false;
    }
  }

  ret = rgw_store_user_info(store, user_info, &old_info, false);
  if (ret < 0) {
    err_msg = "unable to store user info";
    return false;
  }

  old_info = user_info;
  set_populated();

  return true;
}

bool RGWUser::check_request(RGWUserAdminRequest& req, std::string& err_msg)
{
  std::string subprocess_msg;
  bool same_id;
  bool populated;
  bool existing_email = false;
  std::string req_id = req.get_user_id();
  std::string req_email = req.get_user_email();

  RGWUserInfo user_info;

  same_id = (user_id.compare(req_id) == 0);
  populated = is_populated();

  if (req_id.compare(RGW_USER_ANON_ID) == 0) {
    err_msg = "unable to perform operations on the anoymous user";
    return false;
  }

  if (populated && !same_id) {
    err_msg = "user id mismatch, requested id: " + req_id\
            + " does not match: " + user_id;

    return false;
  }

  // check for an existing user email
  if (!req_email.empty())
    existing_email = (rgw_get_user_info_by_email(store, req_email, user_info) >= 0);

  if (existing_email)
    req.set_existing_email();

  return true;
}

bool RGWUser::execute_add(RGWUserAdminRequest& req, std::string& err_msg)
{
  std::string subprocess_msg;
  bool updated = true;
  bool defer_user_update = true;

  RGWUserInfo user_info;

  std::string uid = req.get_user_id();
  std::string user_email = req.get_user_email();
  std::string display_name = req.get_display_name();

  // fail if the user exists already
  if (req.has_existing_user()) {
    err_msg = "user: " + req.user_id + " exists";
    return false;
  }

  // fail if the user_info has already been populated
  if (req.is_populated()) {
    err_msg = "cannot overwrite already populated user";
    return false;
  }

  // fail if the display name was not included
  if (display_name.empty()) {
    err_msg = "no display name specified";
    return false;
  }

  // fail if the user email is a duplicate
  if (req.has_existing_email()) {
    err_msg = "duplicate email provided";
    return false;
  }

  // set the user info
  user_id = uid;
  user_info.user_id = user_id;
  user_info.display_name = display_name;

  if (!user_email.empty())
    user_info.user_email = user_email;

  user_info.max_buckets = req.get_max_buckets();
  user_info.suspended = req.get_suspension_status();

  // update the request
  req.set_user_info(user_info);

  // update the helper objects
  if (!init_members(req)) {
    err_msg = "unable to initialize user";
    return false;
  }

  // see if we need to add an access key
  if (req.has_key_op()) {
    bool success = keys->add(req, subprocess_msg, defer_user_update);
    if (!success) {
      err_msg = "unable to create access key, " + subprocess_msg;
      return false;
    }
  }

  // see if we need to add some caps
  if (req.has_caps_op()) {
    bool success = caps->add(req, subprocess_msg, defer_user_update);
    if (!success) {
      err_msg = "unable to add user capabilities, " + subprocess_msg;
      return false;
    }
  }

  updated = update(req, err_msg);
  if (!updated)
    return false;

  return true;
}

bool RGWUser::add(RGWUserAdminRequest& req, std::string& err_msg)
{
  std::string subprocess_msg;

  bool checked = check_request(req, subprocess_msg);
  if (!checked) {
    err_msg = "unable to parse parameters, " + subprocess_msg;
    return false;
  }

  bool created = execute_add(req, subprocess_msg);
  if (!created) {
    err_msg = "unable to create user, " + subprocess_msg;
    return false;
  }

  return true;
}

bool RGWUser::execute_remove(RGWUserAdminRequest& req, std::string& err_msg)
{
  int ret;
  std::string uid = req.get_user_id();

  RGWUserInfo user_info = req.get_user_info();

  bool existing_user = req.has_existing_user();
  if (!existing_user) {
    err_msg = "user does not exist";
    return false;
  }

  // purge the data first
  if (req.will_purge_data()) {
    RGWUserBuckets buckets;
    ret = rgw_read_user_buckets(store, uid, buckets, false);
    if (ret < 0) {
      err_msg = "unable to read user data";
      return false;
    }

    map<std::string, RGWBucketEnt>& m = buckets.get_buckets();

    if (m.size() > 0) {
      std::map<std::string, RGWBucketEnt>::iterator it;
      for (it = m.begin(); it != m.end(); it++) {
        ret = remove_bucket(store, ((*it).second).bucket, true);

         if (ret < 0) {
           err_msg = "unable to delete user data";
           return false;
         }
      }
    }
  }

  ret = rgw_delete_user(store, user_info);
  if (ret < 0) {
    err_msg = "unable to remove user from RADOS";
    return false;
  }

  return true;
}

bool RGWUser::remove(RGWUserAdminRequest& req, std::string& err_msg)
{
  std::string subprocess_msg;

  bool checked = check_request(req, subprocess_msg);
  if (!checked) {
    err_msg = "unable to parse parameters, " + subprocess_msg;
    return false;
  }

  bool removed = execute_remove(req, subprocess_msg);
  if (!removed) {
    err_msg = "unable to remove user, " + subprocess_msg;
    return false;
  }

  return true;
}

bool RGWUser::execute_modify(RGWUserAdminRequest& req, string& err_msg)
{
  bool same_email = true;
  bool populated = req.is_populated();
  bool defer_user_update = true;
  bool updated = true;
  int ret = 0;

  std::string subprocess_msg;
  std::string req_email = req.get_user_email();
  std::string display_name = req.get_display_name();
  std::string old_email = old_info.user_email;


  RGWUserInfo user_info = old_info;
  RGWUserInfo duplicate_check;

  // ensure that the user info has been populated or is populate-able
  if (!req.existing_user && !populated) {
    err_msg = "user not found";
    return false;
  }

  // ensure that we can modify the user's attributes
  if (user_id == RGW_USER_ANON_ID) {
    err_msg = "unable to modify anonymous user's info";
    return false;
  }

  // if the user hasn't already been populated...attempt to
  if (!populated) {
    bool found = init(req);

    if (!found) {
      err_msg = "unable to retrieve user info";
      return false;
    }
  }

  if (!old_email.empty())
    same_email = (old_email.compare(req_email) == 0);

  // make sure we are not adding a duplicate email
  if (!req_email.empty() && !same_email) {
    ret = rgw_get_user_info_by_email(store, req_email, duplicate_check);
    if (ret >= 0) {
      err_msg = "cannot add duplicate email";
      return false;
    }
  }

  // update the remaining user info
  if (!display_name.empty())
    user_info.display_name = display_name;

  // will be set to RGW_DEFAULT_MAX_BUCKETS by default
  user_info.max_buckets = req.get_max_buckets();

  if (req.has_suspension_op()) {

    string id;
    __u8 suspended = req.get_suspension_status();

    RGWUserBuckets buckets;
    if (rgw_read_user_buckets(store, user_id, buckets, false) < 0) {
      err_msg = "could not get buckets for uid:  " + user_id;
      return false;
    }
    map<string, RGWBucketEnt>& m = buckets.get_buckets();
    map<string, RGWBucketEnt>::iterator iter;

    vector<rgw_bucket> bucket_names;
    for (iter = m.begin(); iter != m.end(); ++iter) {
      RGWBucketEnt obj = iter->second;
      bucket_names.push_back(obj.bucket);
    }
    ret = store->set_buckets_enabled(bucket_names, !suspended);
    if (ret < 0) {
     err_msg = "failed to change pool";
      return false;
    }
  }

  // if we're supposed to modify keys, do so
  if (req.has_key_op()) {

    bool success = keys->add(req, subprocess_msg, defer_user_update);
    if (!success) {
      err_msg = "unable to create or modify keys, " + subprocess_msg;
      return false;
    }
  }

  updated = update(req, err_msg);
  if (!updated)
    return false;

  return true;
}

bool RGWUser::modify(RGWUserAdminRequest& req, std::string& err_msg)
{
  std::string subprocess_msg;

  bool checked = check_request(req, subprocess_msg);
  if (!checked) {
    err_msg = "unable to parse parameters, " + subprocess_msg;
    return false;
  }

  bool modified = execute_modify(req, subprocess_msg);
  if (!modified) {
    err_msg = "unable to modify user, " + subprocess_msg;
    return false;
  }

  return true;
}

bool RGWUser::info(RGWUserAdminRequest& req, RGWUserInfo& fetched_info, std::string& err_msg)
{
  bool found = init(req);
  if (!found) {
    err_msg = "unable to fetch user info";
    return false;
  }

  // return the user info
  fetched_info = req.get_user_info();

  return true;
}

bool RGWUser::info(RGWUserInfo& fetched_info, std::string& err_msg)
{
  if (!info_stored) {
    err_msg = "no user info saved";
    return false;
  }

  if (failure) {
   err_msg = "previous error detected...aborting";
   return false;
  }

  // return the user info
  fetched_info = old_info;

  return true;
}
