#ifndef CEPH_RGW_USER_H
#define CEPH_RGW_USER_H

#include <string>

#include "include/types.h"
#include "rgw_common.h"
#include "rgw_tools.h"

#include "rgw_rados.h"

#include "rgw_string.h"

using namespace std;

#define RGW_USER_ANON_ID "anonymous"

#define SECRET_KEY_LEN 40
#define PUBLIC_ID_LEN 20

/**
 * A string wrapper that includes encode/decode functions
 * for easily accessing a UID in all forms
 */
struct RGWUID
{
  string user_id;
  void encode(bufferlist& bl) const {
    ::encode(user_id, bl);
  }
  void decode(bufferlist::iterator& bl) {
    ::decode(user_id, bl);
  }
};
WRITE_CLASS_ENCODER(RGWUID)

/**
 * Get the anonymous (ie, unauthenticated) user info.
 */
extern void rgw_get_anon_user(RGWUserInfo& info);

/**
 * verify that user is an actual user, and not the anonymous user
 */
extern bool rgw_user_is_authenticated(RGWUserInfo& info);
/**
 * Save the given user information to storage.
 * Returns: 0 on success, -ERR# on failure.
 */
extern int rgw_store_user_info(RGWRados *store, RGWUserInfo& info, RGWUserInfo *old_info, bool exclusive);
/**
 * Given an email, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
extern int rgw_get_user_info_by_uid(RGWRados *store, string& user_id, RGWUserInfo& info);
/**
 * Given an swift username, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
extern int rgw_get_user_info_by_email(RGWRados *store, string& email, RGWUserInfo& info);
/**
 * Given an swift username, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
extern int rgw_get_user_info_by_swift(RGWRados *store, string& swift_name, RGWUserInfo& info);
/**
 * Given an access key, finds the user info associated with it.
 * returns: 0 on success, -ERR# on failure (including nonexistence)
 */
extern int rgw_get_user_info_by_access_key(RGWRados *store, string& access_key, RGWUserInfo& info);
/**
 * Given an RGWUserInfo, deletes the user and its bucket ACLs.
 */
extern int rgw_delete_user(RGWRados *store, RGWUserInfo& user);
/**
 * Store a list of the user's buckets, with associated functinos.
 */
class RGWUserBuckets
{
  map<string, RGWBucketEnt> buckets;

public:
  RGWUserBuckets() {}
  void encode(bufferlist& bl) const {
    ::encode(buckets, bl);
  }
  void decode(bufferlist::iterator& bl) {
    ::decode(buckets, bl);
  }
  /**
   * Check if the user owns a bucket by the given name.
   */
  bool owns(string& name) {
    map<string, RGWBucketEnt>::iterator iter;
    iter = buckets.find(name);
    return (iter != buckets.end());
  }

  /**
   * Add a (created) bucket to the user's bucket list.
   */
  void add(RGWBucketEnt& bucket) {
    buckets[bucket.bucket.name] = bucket;
  }

  /**
   * Remove a bucket from the user's list by name.
   */
  void remove(string& name) {
    map<string, RGWBucketEnt>::iterator iter;
    iter = buckets.find(name);
    if (iter != buckets.end()) {
      buckets.erase(iter);
    }
  }

  /**
   * Get the user's buckets as a map.
   */
  map<string, RGWBucketEnt>& get_buckets() { return buckets; }

  /**
   * Cleanup data structure
   */
  void clear() { buckets.clear(); }

  size_t count() { return buckets.size(); }
};
WRITE_CLASS_ENCODER(RGWUserBuckets)

/**
 * Get all the buckets owned by a user and fill up an RGWUserBuckets with them.
 * Returns: 0 on success, -ERR# on failure.
 */
extern int rgw_read_user_buckets(RGWRados *store, string user_id, RGWUserBuckets& buckets, bool need_stats);

/**
 * Store the set of buckets associated with a user.
 * This completely overwrites any previously-stored list, so be careful!
 * Returns 0 on success, -ERR# otherwise.
 */
extern int rgw_write_buckets_attr(RGWRados *store, string user_id, RGWUserBuckets& buckets);

extern int rgw_add_bucket(RGWRados *store, string user_id, rgw_bucket& bucket);
extern int rgw_remove_user_bucket_info(RGWRados *store, string user_id, rgw_bucket& bucket);

/*
 * remove the different indexes
 */
extern int rgw_remove_key_index(RGWRados *store, RGWAccessKey& access_key);
extern int rgw_remove_uid_index(RGWRados *store, string& uid);
extern int rgw_remove_email_index(RGWRados *store, string& email);
extern int rgw_remove_swift_name_index(RGWRados *store, string& swift_name);


/* remove these when changes complete */
extern bool validate_access_key(string& key);
extern int remove_object(RGWRados *store, rgw_bucket& bucket, std::string& object);
extern int remove_bucket(RGWRados *store, rgw_bucket& bucket, bool delete_children);


/* end remove these */
/*
 * An RGWUser class along with supporting classes created
 * to support the creation of an RESTful administrative API
 */

enum ObjectKeyType {
  KEY_TYPE_SWIFT,
  KEY_TYPE_S3,
};

enum RGWKeyPoolOp {
  CREATE_KEY,
  GENERATE_KEY,
  MODIFY_KEY
};

enum RGWUserId {
  RGW_USER_ID,
  RGW_SWIFT_USERNAME,
  RGW_USER_EMAIL,
  RGW_ACCESS_KEY,
};

struct RGWUserAdminRequest {
  // user attributes
  RGWUserInfo info;
  std::string user_id;
  std::string user_email;
  std::string display_name;
  uint32_t max_buckets;
  __u8 suspended;
  std::string caps;

  // subuser attributes
  std::string subuser;
  uint32_t perm_mask;

  // key_attributes
  std::string id; // access key
  std::string key; // secret key
  int32_t key_type;

  // operation attributes
  bool existing_user;
  bool existing_key;
  bool existing_subuser;
  bool existing_email;
  bool subuser_specified;
  bool gen_secret;
  bool gen_access;
  bool gen_subuser;
  bool id_specified;
  bool key_specified;
  bool type_specified;
  bool purge_data;
  bool purge_keys;
  bool display_name_specified;
  bool user_email_specified;
  bool max_buckets_specified;
  bool perm_specified;
  bool caps_specified;
  bool suspension_op;
  bool key_op;

  // req parameters
  bool populated;
  bool initialized;
  bool key_params_checked;
  bool subuser_params_checked;
  bool user_params_checked;

  void set_access_key(std::string& access_key) {
    if (access_key.empty())
      return;

    id = access_key;
    id_specified = true;
    gen_access = false;
    key_op = true;
  }
  void set_secret_key(std::string& secret_key) {
    if (secret_key.empty())
      return;

    key = secret_key;
    key_specified = true;
    gen_secret = false;
    key_op = true;
  }
  void set_user_id(std::string& id) {
    if (id.empty())
      return;

    user_id = id;
  }
  void set_user_email(std::string& email) {
    if (email.empty())
      return;

    user_email = email;
    user_email_specified = true;
  }
  void set_display_name(std::string& name) {
    if (name.empty())
      return;

    display_name = name;
    display_name_specified = true;
  }
  void set_subuser(std::string& _subuser) {
    subuser = _subuser;
    subuser_specified = true;
  }
  void set_caps(std::string& _caps) {
    caps = _caps;
    caps_specified = true;
  }
  void set_perm(uint32_t perm) {
    perm_mask = perm;
    perm_specified = true;
  }
  void set_key_type(int32_t type) {
    key_type = type;
    type_specified = true;
  }
  void set_suspension(__u8 is_suspended) {
    suspended = is_suspended;
    suspension_op = true;
  }
  void set_user_info(RGWUserInfo& user_info) {
    user_id = user_info.user_id;
    info = user_info;
  }
  void set_max_buckets(uint32_t mb) {
    max_buckets = mb;
  }
  void set_gen_access() {
    gen_access = true;
    key_op = true;
  }
  void set_gen_secret() {
    gen_secret = true;
    key_op = true;
  }

  bool is_populated() { return populated; };
  bool is_initialized() { return initialized; };
  bool is_existing_user() { return existing_user; };
  bool is_existing_key() { return existing_key; };
  bool has_existing_user() { return existing_user; };
  bool has_existing_key() { return existing_key; };
  bool has_existing_subuser() { return existing_subuser; };
  bool has_existing_email() { return existing_email; };
  bool has_subuser() { return subuser_specified; };
  bool has_key_op() { return key_op; };
  bool has_caps_op() { return caps_specified; };
  bool has_suspension_op() { return suspension_op; };
  bool has_subuser_perm() { return perm_specified; };
  bool will_gen_access() { return gen_access; };
  bool will_gen_secret() { return gen_secret; };
  bool will_gen_subuser() { return gen_subuser; };
  bool will_purge_keys() { return purge_keys; };
  bool will_purge_data() { return purge_data; };
  void set_populated() { populated = true; };
  void set_initialized() { initialized = true; };
  void set_existing_user() { existing_user = true; };
  void set_existing_key() { existing_key = true; };
  void set_existing_subuser() { existing_subuser = true; };
  void set_existing_email() { existing_email = true; };
  void set_purge_keys() { purge_keys = true; };
  void set_purge_data() { purge_data = true; };


  __u8 get_suspension_status() { return suspended; };
  int32_t get_key_type() {return key_type; };
  uint32_t get_subuser_perm() { return perm_mask; };
  uint32_t get_max_buckets() { return max_buckets; };

  std::string get_user_id() { return user_id; };
  std::string get_subuser() { return subuser; };
  std::string get_access_key() { return id; };
  std::string get_secret_key() { return key; };
  std::string get_caps() { return caps; };
  std::string get_user_email() { return user_email; };
  std::string get_display_name() { return display_name; };

  RGWUserInfo get_user_info() { return info; };

  map<std::string, RGWAccessKey> *get_swift_keys() { return &info.swift_keys; };
  map<std::string, RGWAccessKey> *get_access_keys() { return &info.access_keys; };
  map<std::string, RGWSubUser> *get_subusers() { return &info.subusers; };

  RGWUserCaps *get_caps_obj() { return &info.caps; };

  std::string build_default_swift_kid() {
    if (user_id.empty() || subuser.empty())
      return "";

    std::string kid = user_id;
    kid.append(":");
    kid.append(subuser);

    return kid;
  }

  RGWUserAdminRequest()
  {
    user_id = RGW_USER_ANON_ID;
    display_name = "";
    user_email = "";
    id = "";
    key = "";

    max_buckets = RGW_DEFAULT_MAX_BUCKETS;
    key_type = -1;
    perm_mask = 0;
    suspended = 0;

    existing_user = false;
    existing_key = false;
    existing_subuser = false;
    existing_email = false;
    subuser_specified = false;
    caps_specified = false;
    perm_specified = false;
    purge_keys = false;
    gen_secret = false;
    gen_access = false;
    gen_subuser = false;
    id_specified = false;
    key_specified = false;
    type_specified = false;
    purge_data = false;
    purge_keys = false;
    display_name_specified = false;
    user_email_specified = false;
    max_buckets_specified = false;
    perm_specified = false;
    suspension_op = false;
    key_op = false;
    populated = false;
    initialized = false;
  }
};

class RGWUser;

class RGWAccessKeyPool
{
  RGWUser *user;

  std::map<std::string, int, ltstr_nocase> key_type_map;
  std::string user_id;
  RGWRados *store;

  map<std::string, RGWAccessKey> *swift_keys;
  map<std::string, RGWAccessKey> *access_keys;

  // we don't want to allow keys for the anonymous user or a null user
  bool keys_allowed;

private:

  bool create_key(RGWUserAdminRequest& req, string& err_msg);
  bool generate_key(RGWUserAdminRequest& req, string& err_msg);
  bool modify_key(RGWUserAdminRequest& req, string& err_msg);

  bool check_key_owner(RGWUserAdminRequest& req);
  bool check_existing_key(RGWUserAdminRequest& req);
  bool check_request(RGWUserAdminRequest& req, string& err_msg);

  /* API Contract Fulfilment */
  bool execute_add(RGWUserAdminRequest& req, string& err_msg, bool defer_save);
  bool execute_remove(RGWUserAdminRequest& req, string& err_msg, bool defer_save);

  friend class RGWUser;
  friend class RGWSubUserPool;

public:

  RGWAccessKeyPool(RGWUser *user);
  RGWAccessKeyPool(RGWUser *user, RGWUserAdminRequest& req);

  ~RGWAccessKeyPool();

  bool init(RGWUserAdminRequest& req);


  bool add(RGWUserAdminRequest& req, string& err_msg, bool defer_save);
  bool remove(RGWUserAdminRequest& req, string& err_msg, bool defer_save);

  /* API Contracted Methods */
  bool add(RGWUserAdminRequest& req, string& err_msg);
  bool remove(RGWUserAdminRequest& req, string& err_msg);
};

class RGWSubUserPool
{
  RGWUser *user;

  string user_id;
  RGWRados *store;
  bool subusers_allowed;

  map<string, RGWSubUser> *subuser_map;

private:
  bool check_request(RGWUserAdminRequest& req, string& err_msg);

  /* API Contract Fulfillment */
  bool execute_add(RGWUserAdminRequest& req, string& err_msg, bool defer_save);
  bool execute_remove(RGWUserAdminRequest& req, string& err_msg, bool defer_save);
  bool execute_modify(RGWUserAdminRequest& req, string& err_msg, bool defer_save);

public:

  RGWSubUserPool(RGWUser *user);
  ~RGWSubUserPool();

  bool exists(std::string subuser);
  bool init(RGWUserAdminRequest& req);

  bool add(RGWUserAdminRequest& req, string& err_msg, bool defer_save);
  bool remove(RGWUserAdminRequest& req, string& err_msg, bool defer_save);
  bool modify(RGWUserAdminRequest& req, string& err_msg, bool defer_save);

  /* API contracted methods */
  bool add(RGWUserAdminRequest& req, string& err_msg);
  bool remove(RGWUserAdminRequest& req, string& err_msg);
  bool modify(RGWUserAdminRequest& req, string& err_msg);

  friend class RGWUser;
};


class RGWUserCapPool
{
  RGWUserCaps *caps;
  bool caps_allowed;
  RGWUser *user;

private:
public:

  RGWUserCapPool(RGWUser *user);
  ~RGWUserCapPool();

  bool init(RGWUserAdminRequest& req);

  bool add(RGWUserAdminRequest& req, std::string& err_msg, bool defer_save);
  bool remove(RGWUserAdminRequest& req, std::string& err_msg, bool defer_save);

  /* API contracted methods */
  bool add(RGWUserAdminRequest& req, std::string& err_msg);
  bool remove(RGWUserAdminRequest& req, std::string& err_msg);

  friend class RGWUser;
};

class RGWUser
{

private:
  RGWUserInfo old_info;
  RGWRados *store;

  string user_id;
  bool failure;
  bool info_stored;

  void set_failure() { failure = true; };
  void clear_failure() { failure = false; };

  void set_populated() { info_stored = true; };
  void clear_populated() { info_stored = false; };
  bool is_populated() { return info_stored; };

  bool check_request(RGWUserAdminRequest&  req, string& err_msg);
  bool update(RGWUserAdminRequest& req, std::string& err_msg);

  void clear_members();

  /* API Contract Fulfillment */
  bool execute_add(RGWUserAdminRequest& req, string& err_msg);
  bool execute_remove(RGWUserAdminRequest& req, string& err_msg);
  bool execute_modify(RGWUserAdminRequest& req, string& err_msg);

public:
  RGWUser(RGWRados *storage, RGWUserAdminRequest& req);

  /* this will need to be initialized at some point in order to be useful */
  RGWUser(RGWRados *storage);

  /* anonymous user info */
  RGWUser();

  ~RGWUser();

  bool init_storage(RGWRados *storage);
  bool init(RGWUserAdminRequest& req);
  bool init_members(RGWUserAdminRequest& req);

  RGWRados *get_store() { return store; };
  bool has_failed() { return failure; };

  /* API Contracted Members */
  RGWUserCapPool *caps;
  RGWAccessKeyPool *keys;
  RGWSubUserPool *subusers;

  /* API Contracted Methods */
  bool add(RGWUserAdminRequest& req, string& err_msg);
  bool remove(RGWUserAdminRequest& req, string& err_msg);

  /* remove an already populated RGWUser */
  bool remove(string& err_msg);
  bool modify(RGWUserAdminRequest& req, string& err_msg);

  /* retrieve info from an existing user in the RGW system */
  bool info (std::pair<uint32_t, std::string> id, RGWUserInfo& fetched_info, string& err_msg);
  bool info (RGWUserAdminRequest& req, RGWUserInfo& fetched_info, string& err_msg);

  /* info from an already populated RGWUser */
  bool info (RGWUserInfo& fetched_info, string& err_msg);


  friend class RGWAccessKeyPool;
  friend class RGWSubUserPool;
  friend class RGWUserCapPool;
};

#endif
