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
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fstream>
#include <map>
#include <list>
extern "C"{
#include <curl/curl.h>
}
#include "common/ceph_crypto.h"
#include "include/str_list.h"
#include "common/ceph_json.h"
#include "common/code_environment.h"
#include "common/ceph_argparse.h"
#include "common/Finisher.h"
#include "global/global_init.h"
#include "rgw/rgw_common.h"
#include "rgw/rgw_bucket.h"
#include "rgw/rgw_rados.h"
#include "rgw/rgw_user.h"
#include "include/utime.h"
#include "include/object.h"
#define GTEST
#ifdef GTEST
#include <gtest/gtest.h>
#else
#define TEST(x, y) void y()
#define ASSERT_EQ(v, s) if(v != s)cout << "Error at " << __LINE__ << "(" << #v << "!= " << #s << "\n"; \
                                else cout << "(" << #v << "==" << #s << ") PASSED\n";
#define EXPECT_EQ(v, s) ASSERT_EQ(v, s)
#define ASSERT_TRUE(c) if(c)cout << "Error at " << __LINE__ << "(" << #c << ")" << "\n"; \
                          else cout << "(" << #c << ") PASSED\n";
#define EXPECT_TRUE(c) ASSERT_TRUE(c) 
#endif
using namespace std;

#define HTTP_RESPONSE_STR "RespCode"
#define CEPH_CRYPTO_HMACSHA1_DIGESTSIZE 20
#define RGW_ADMIN_RESP_PATH "/tmp/.test_rgw_admin_resp"
#define TEST_BUCKET_NAME "test_bucket"
#define TEST_BUCKET_OBJECT "test_object"
#define TEST_BUCKET_OBJECT_1 "test_object1"
#define TEST_BUCKET_OBJECT_SIZE 1024
#define DEFAULT_TEMP_URL_KEY "jlaslkjd"

static int CURL_VERBOSE = 0;
static string uid = "ceph";
static string display_name = "CEPH";

extern "C" int ceph_armor(char *dst, const char *dst_end, 
                          const char *src, const char *end);

static void print_usage(char *exec){
  cout << "Usage: " << exec << " <Options>\n";
  cout << "Options:\n"
          "-g <gw-ip> - The ip address of the gateway\n"
          "-p <gw-port> - The port number of the gateway\n"
          "-c <ceph.conf> - Absolute path of ceph config file\n"
          "-rgw-admin <path/to/radosgw-admin> - radosgw-admin absolute path\n";
}

namespace temp_url {
class test_helper {
  private:
    string host;
    string port;
    string auth_token;
    string rgw_admin_path;
    string conf_path;
    CURL *curl_inst;
    map<string, string> response;
    list<string> extra_hdrs;
    string *resp_data;
    unsigned resp_code;
  public:
    test_helper() : resp_data(NULL){
      curl_global_init(CURL_GLOBAL_ALL);
    }
    ~test_helper(){
      curl_global_cleanup();
    }
    int send_request(string method, string uri, 
                     size_t (*function)(void *,size_t,size_t,void *) = 0,
                     void *ud = 0, size_t length = 0);
    int extract_input(int argc, char *argv[]);
    string& get_response(string hdr){
      return response[hdr];
    }
    void set_extra_header(string hdr){
      extra_hdrs.push_back(hdr);
    }
    void set_response(char *val);
    void set_response_data(char *data, size_t len){
      if(resp_data) delete resp_data;
      resp_data = new string(data, len);
    }
    string& get_rgw_admin_path() {
      return rgw_admin_path;
    }
    string& get_ceph_conf_path() {
      return conf_path;
    }
    void set_auth_token(string c) {
      auth_token = c;
    }
    void get_auth_token(string& c) {
      c= auth_token;
    }
    const string *get_response_data(){return resp_data;}
    unsigned get_resp_code(){return resp_code;}
};

int test_helper::extract_input(int argc, char *argv[]){
#define ERR_CHECK_NEXT_PARAM(o) \
  if(((int)loop + 1) >= argc)return -1;		\
  else o = argv[loop+1];

  for(unsigned loop = 1;loop < (unsigned)argc; loop += 2){
    if(strcmp(argv[loop], "-g") == 0){
      ERR_CHECK_NEXT_PARAM(host);
    }else if(strcmp(argv[loop],"-p") == 0){
      ERR_CHECK_NEXT_PARAM(port);
    }else if(strcmp(argv[loop], "-c") == 0){
      ERR_CHECK_NEXT_PARAM(conf_path);
    }else if(strcmp(argv[loop], "-rgw-admin") == 0){
      ERR_CHECK_NEXT_PARAM(rgw_admin_path);
    }else return -1;
  }
  if(host.length() <= 0 ||
     rgw_admin_path.length() <= 0)
    return -1;
  return 0;
}

void test_helper::set_response(char *r){
  string sr(r), h, v;
  size_t off = sr.find(": ");
  if(off != string::npos){
    h.assign(sr, 0, off);
    v.assign(sr, off + 2, sr.find("\r\n") - (off+2));
  }else{
    /*Could be the status code*/
    if(sr.find("HTTP/") != string::npos){
      h.assign(HTTP_RESPONSE_STR);
      off = sr.find(" ");
      v.assign(sr, off + 1, sr.find("\r\n") - (off + 1));
      resp_code = atoi((v.substr(0, 3)).c_str());
    }
  }
  response[h] = v;
}

size_t write_header(void *ptr, size_t size, size_t nmemb, void *ud){
  test_helper *h = (test_helper *)ud;
  h->set_response((char *)ptr);
  return size*nmemb;
}

size_t write_data(void *ptr, size_t size, size_t nmemb, void *ud){
  test_helper *h = (test_helper *)ud;
  h->set_response_data((char *)ptr, size*nmemb);
  return size*nmemb;
}

void get_date(string& d){
  struct timeval tv;
  char date[64];
  struct tm tm;
  char *days[] = {(char *)"Sun", (char *)"Mon", (char *)"Tue",
                  (char *)"Wed", (char *)"Thu", (char *)"Fri", 
                  (char *)"Sat"};
  char *months[] = {(char *)"Jan", (char *)"Feb", (char *)"Mar", 
                    (char *)"Apr", (char *)"May", (char *)"Jun",
                    (char *)"Jul",(char *) "Aug", (char *)"Sep", 
                    (char *)"Oct", (char *)"Nov", (char *)"Dec"};
  gettimeofday(&tv, NULL);
  gmtime_r(&tv.tv_sec, &tm);
  sprintf(date, "%s, %d %s %d %d:%d:%d GMT", 
          days[tm.tm_wday], 
          tm.tm_mday, months[tm.tm_mon], 
          tm.tm_year + 1900,
          tm.tm_hour, tm.tm_min, tm.tm_sec);
  d = date;
}

int test_helper::send_request(string method, string res, 
                                   size_t (*read_function)( void *,size_t,size_t,void *),
                                   void *ud,
                                   size_t length){
  string url;
  string auth, date;
  url.append(string("http://") + host);
  if(port.length() > 0)url.append(string(":") + port);
  url.append(res);
  curl_inst = curl_easy_init();
  if(curl_inst){
    curl_easy_setopt(curl_inst, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_inst, CURLOPT_CUSTOMREQUEST, method.c_str());
    curl_easy_setopt(curl_inst, CURLOPT_VERBOSE, CURL_VERBOSE);
    curl_easy_setopt(curl_inst, CURLOPT_HEADERFUNCTION, temp_url::write_header);
    curl_easy_setopt(curl_inst, CURLOPT_WRITEHEADER, (void *)this);
    curl_easy_setopt(curl_inst, CURLOPT_WRITEFUNCTION, temp_url::write_data);
    curl_easy_setopt(curl_inst, CURLOPT_WRITEDATA, (void *)this);
    if(read_function){
      curl_easy_setopt(curl_inst, CURLOPT_READFUNCTION, read_function);
      curl_easy_setopt(curl_inst, CURLOPT_READDATA, (void *)ud);
      curl_easy_setopt(curl_inst, CURLOPT_UPLOAD, 1L);
      curl_easy_setopt(curl_inst, CURLOPT_INFILESIZE_LARGE, (curl_off_t)length);
    }

    get_date(date);
    string http_date;
    http_date.append(string("Date: ") + date);

    if (!auth_token.empty()) {
      auth = "X-Auth-Token: ";
      auth.append(auth_token);
    }
    struct curl_slist *slist = NULL;
    slist = curl_slist_append(slist, auth.c_str());
    slist = curl_slist_append(slist, http_date.c_str());
    for(list<string>::iterator it = extra_hdrs.begin();
        it != extra_hdrs.end(); ++it){
      slist = curl_slist_append(slist, (*it).c_str());
    }
    if(read_function)
      curl_slist_append(slist, "Expect:");
    curl_easy_setopt(curl_inst, CURLOPT_HTTPHEADER, slist); 

    response.erase(response.begin(), response.end());
    extra_hdrs.erase(extra_hdrs.begin(), extra_hdrs.end());
    CURLcode res = curl_easy_perform(curl_inst);
    if(res != CURLE_OK){
      cout << "Curl perform failed for " << url << ", res: " << 
        curl_easy_strerror(res) << "\n";
      return -1;
    }
    curl_slist_free_all(slist);
  }
  curl_easy_cleanup(curl_inst);
  return 0;
}
};

temp_url::test_helper *g_test;
Finisher *finisher;
RGWRados *store;

int run_rgw_admin(string& cmd, string& resp) {
  pid_t pid;
  pid = fork();
  if (pid == 0) {
    /* child */
    list<string> l;
    get_str_list(cmd, " \t", l);
    char *argv[l.size()];
    unsigned loop = 1;

    argv[0] = (char *)"radosgw-admin";
    for (list<string>::iterator it = l.begin(); 
         it != l.end(); ++it) {
      argv[loop++] = (char *)(*it).c_str();
    }
    argv[loop] = NULL;
    close(1);
    stdout = fopen(RGW_ADMIN_RESP_PATH, "w+");
    if (!stdout) {
      cout << "Unable to open stdout file" << std::endl;
    }
    execv((g_test->get_rgw_admin_path()).c_str(), argv); 
  } else if (pid > 0) {
    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
      if(WEXITSTATUS(status) != 0) {
        cout << "Child exited with status " << WEXITSTATUS(status) << std::endl;
        return -1;
      }
    }
    ifstream in;
    struct stat st;

    if (stat(RGW_ADMIN_RESP_PATH, &st) < 0) {
      cout << "Error stating the admin response file, errno " << errno << std::endl;
      return -1;
    } else {
      char *data = (char *)malloc(st.st_size + 1);
      in.open(RGW_ADMIN_RESP_PATH);
      in.read(data, st.st_size);
      in.close();
      data[st.st_size] = 0;
      resp = data;
      free(data);
      unlink(RGW_ADMIN_RESP_PATH);
      /* cout << "radosgw-admin " << cmd << ": " << resp << std::endl; */
    }
  } else 
    return -1;
  return 0;
}

int get_creds(string& json, string& user, string& secret, string& temp_url_key) {
  JSONParser parser;
  if(!parser.parse(json.c_str(), json.length())) {
    cout << "Error parsing create user response" << std::endl;
    return -1;
  }
  RGWUserInfo info;
  decode_json_obj(info, &parser);
  for(map<string, RGWAccessKey>::iterator it = info.swift_keys.begin();
      it != info.swift_keys.end(); ++it) {
    RGWAccessKey _k = it->second;
    /*cout << "accesskeys [ " << it->first << " ] = " << 
      "{ " << _k.id << ", " << _k.key << ", " << _k.subuser << "}" << std::endl;*/
    if (it->first.compare(".tempurl")) {
      user = _k.id;
      secret = _k.key;
    } else {
      temp_url_key = _k.key;
    }
  }
  return 0;
}

int user_create(string& uid, string& display_name) {
  stringstream ss;
  string creds;
  ss << "-c " << g_test->get_ceph_conf_path() << " user create --subuser=" << uid << ":" << uid
    << " --display-name=" << display_name << " --key-type=swift";

  string out;
  string cmd = ss.str();
  if(run_rgw_admin(cmd, out) != 0) {
    cout << "Error creating user" << std::endl;
    return -1;
  }

  string user, key, temp_url, x_auth_user, x_auth_key;
  get_creds(out, user, key, temp_url);

  x_auth_user = "X-Auth-User: ";
  x_auth_user.append(user);

  x_auth_key = "X-Auth-Key: ";
  x_auth_key.append(key);

  string req = "/auth/v1/";
  g_test->set_extra_header(x_auth_user);
  g_test->set_extra_header(x_auth_key);
  g_test->send_request(string("GET"), req);
  if (g_test->get_resp_code() != 204U) {
    cout << "Unexpected reponse from auth request " << g_test->get_resp_code() << std::endl;
    return -1;
  }

  creds = g_test->get_response(string("X-Auth-Token"));
  if (creds.empty()) {
    cout << "Not able to find X-Auth-Token in auth response" << std::endl;
    return -1;
  }
  g_test->set_auth_token(creds);
  return 0;
}

int user_info(string& uid, string& display_name, string& temp_url) {
  stringstream ss;
  string creds;

  RGWUserInfo user_info;
  if (!store)
    store = RGWStoreManager::get_storage(g_ceph_context, false);
  int r = rgw_get_user_info_by_uid(store, uid, user_info);
  if (r < 0)
    return r;
  for (map<string, RGWAccessKey>::iterator it = user_info.swift_keys.begin();
       it != user_info.swift_keys.end(); it++) {
    if (it->first.compare(".tempurl") == 0) {
      temp_url = it->second.key;
    }
  }
  return 0;
}

int user_rm(string& uid, string& display_name) {
  stringstream ss;
  string creds;
  ss << "-c " << g_test->get_ceph_conf_path() << 
    " user rm --uid=" << uid << " --display name=" << display_name;

  string out;
  string cmd = ss.str();
  if(run_rgw_admin(cmd, out) != 0) {
    cout << "Error removing user" << std::endl;
    return -1;
  }

  g_test->set_auth_token(creds);
  return 0;
}

static int create_bucket(void){
  g_test->send_request(string("PUT"), string("/swift/v1/"TEST_BUCKET_NAME));
  if(g_test->get_resp_code() != 201U){
    cout << "Error creating bucket, http code " << g_test->get_resp_code();
    return -1;
  }
  return 0;
}

static int delete_bucket(void){
  g_test->send_request(string("DELETE"), string("/swift/v1/"TEST_BUCKET_NAME));
  if(g_test->get_resp_code() != 204U){
    cout << "Error deleting bucket, http code " << g_test->get_resp_code();
    return -1;
  }
  return 0;
}

size_t read_bucket_object(void *ptr, size_t s, size_t n, void *ud) {
  memcpy(ptr, ud, TEST_BUCKET_OBJECT_SIZE);
  return TEST_BUCKET_OBJECT_SIZE;
}

static int put_bucket_obj(const char *obj_name, char *data, unsigned len) {
  string req = "/swift/v1/"TEST_BUCKET_NAME"/";
  req.append(obj_name);
  g_test->send_request(string("PUT"), req,
                       read_bucket_object, (void *)data, (size_t)len);
  if (g_test->get_resp_code() != 201U) {
    cout << "Errror sending object to the bucket, http_code " << g_test->get_resp_code();
    return -1;
  }
  return 0;
}

static int delete_obj(const char *obj_name) {
  string req = "/swift/v1/"TEST_BUCKET_NAME"/";
  req.append(obj_name);
  g_test->send_request(string("DELETE"), req);
  if (g_test->get_resp_code() != 204U) {
    cout << "Errror deleting object from bucket, http_code " << g_test->get_resp_code();
    return -1;
  }
  return 0;
}

static void rgw_create_swift_temp_url_header(const char *method,
                                             const char *expires,
                                             const char *object,
                                             string& out_hdr) {
  string hdr;

  hdr = method;
  hdr.append("\n");

  hdr.append(expires);
  hdr.append("\n");

  hdr.append(object);
  hdr.append("\n");

  out_hdr = hdr;
}

static int rgw_get_temp_url_digest(const string& auth_hdr, const string& key, string& digest) {
  char hmac_sha1[CEPH_CRYPTO_HMACSHA1_DIGESTSIZE];

  calc_hmac_sha1(key.c_str(), key.size(), auth_hdr.c_str(), auth_hdr.size(), hmac_sha1);

  char b64[64];
  int ret = ceph_armor(b64, b64 + 64, hmac_sha1,
		       hmac_sha1 + CEPH_CRYPTO_HMACSHA1_DIGESTSIZE);
  if (ret < 0) {
    cerr << "ceph_armor failed" << std::endl;
    return ret;
  }
  b64[ret] = '\0';

  digest = b64;

  return 0;
}

int  get_temp_url_sig(const char *obj, 
                      const char *method, time_t exp, string key, string& temp_url_sig) {
  ostringstream oss;
  oss << exp;

  string auth_hdr;
  rgw_create_swift_temp_url_header(method, oss.str().c_str(), obj, auth_hdr);
  
  if (rgw_get_temp_url_digest(auth_hdr, key, temp_url_sig) < 0) {
    return -1;
  }

  char ret[128];
  int len = 0;
  for (unsigned loop = 0; loop < temp_url_sig.length(); loop++) {
    if (temp_url_sig[loop] == '+') {
      ret[len++] = '%';
      ret[len++] = '2';
      ret[len++] = 'B';
    } else 
      ret[len++] = temp_url_sig[loop];
  }
  ret[len] = 0;
  temp_url_sig.assign(ret);
  return 0;
}

size_t read_dummy_post(void *ptr, size_t s, size_t n, void *ud) {
  int dummy = 0;
  memcpy(ptr, &dummy, sizeof(dummy));
  return sizeof(dummy);
}

TEST(TestRGWTempUrl, create_modify) {
  string temp_key, rest_req;

  ASSERT_EQ(0, user_create(uid, display_name));
  
  rest_req = "/swift/v1/";
  g_test->set_extra_header(string("X-Account-Meta-Temp-Url-Key: "DEFAULT_TEMP_URL_KEY));
  g_test->send_request(string("POST"), rest_req, read_dummy_post, NULL, sizeof(int));
  EXPECT_EQ(200U, g_test->get_resp_code());

  EXPECT_EQ(0, user_info(uid, display_name, temp_key));
  EXPECT_TRUE(temp_key.compare(DEFAULT_TEMP_URL_KEY) == 0);

  rest_req = "/swift/v1/";
  g_test->set_extra_header(string("X-Account-Meta-Temp-Url-Key: "DEFAULT_TEMP_URL_KEY"aaa"));
  g_test->send_request(string("POST"), rest_req, read_dummy_post, NULL, sizeof(int));
  EXPECT_EQ(200U, g_test->get_resp_code());

  EXPECT_EQ(0, user_info(uid, display_name, temp_key));
  EXPECT_TRUE(temp_key.compare(DEFAULT_TEMP_URL_KEY"aaa") == 0);


  ASSERT_EQ(0, user_rm(uid, display_name));
}

TEST(TestRGWTempUrl, get) {
  string temp_key, rest_req;

  ASSERT_EQ(0, user_create(uid, display_name));
  
  rest_req = "/swift/v1/";
  g_test->set_extra_header(string("X-Account-Meta-Temp-Url-Key: "DEFAULT_TEMP_URL_KEY));
  g_test->send_request(string("POST"), rest_req, read_dummy_post, NULL, sizeof(int));
  EXPECT_EQ(200U, g_test->get_resp_code());

  EXPECT_EQ(0, user_info(uid, display_name, temp_key));
  EXPECT_EQ(0, temp_key.compare(DEFAULT_TEMP_URL_KEY));

  EXPECT_EQ(0, create_bucket());

  char *data = new char[TEST_BUCKET_OBJECT_SIZE];
  memset((void *)data, 0, TEST_BUCKET_OBJECT_SIZE);
  EXPECT_EQ(0, put_bucket_obj(TEST_BUCKET_OBJECT, data, TEST_BUCKET_OBJECT_SIZE));

  string temp_url_sig, auth_token;
  g_test->get_auth_token(auth_token);
  g_test->set_auth_token(string(""));

  time_t exp = ceph_clock_now(g_ceph_context);
  exp += 5;
  EXPECT_EQ(0, get_temp_url_sig("/v1/"TEST_BUCKET_NAME"/"TEST_BUCKET_OBJECT, 
                                "GET", exp, temp_key, temp_url_sig));
  ostringstream oss;
  oss << "/swift/v1/"TEST_BUCKET_NAME"/"TEST_BUCKET_OBJECT"?temp_url_sig="
     << temp_url_sig << "&temp_url_expires=" << exp;
  g_test->send_request(string("GET"), oss.str());
  EXPECT_EQ(200U, g_test->get_resp_code());

  EXPECT_EQ(0, memcmp((void *)g_test->get_response_data()->c_str(), (void *)data, TEST_BUCKET_OBJECT_SIZE));

  time_t now = ceph_clock_now(g_ceph_context);
  sleep((exp - now)+1);
  
  g_test->send_request(string("GET"), oss.str());
  EXPECT_EQ(401U, g_test->get_resp_code());


  delete data;
  g_test->set_auth_token(auth_token);
  EXPECT_EQ(0, delete_obj(TEST_BUCKET_OBJECT));
  EXPECT_EQ(0, delete_bucket());
  ASSERT_EQ(0, user_rm(uid, display_name));
}

TEST(TestRGWTempUrl, put) {
  string temp_key, rest_req;

  ASSERT_EQ(0, user_create(uid, display_name));
  
  rest_req = "/swift/v1/";
  g_test->set_extra_header(string("X-Account-Meta-Temp-Url-Key: "DEFAULT_TEMP_URL_KEY));
  g_test->send_request(string("POST"), rest_req, read_dummy_post, NULL, sizeof(int));
  EXPECT_EQ(200U, g_test->get_resp_code());

  EXPECT_EQ(0, user_info(uid, display_name, temp_key));
  EXPECT_EQ(0, temp_key.compare(DEFAULT_TEMP_URL_KEY));

  EXPECT_EQ(0, create_bucket());

  char *data = new char[TEST_BUCKET_OBJECT_SIZE];
  memset((void *)data, 0, TEST_BUCKET_OBJECT_SIZE);

  string temp_url_sig, auth_token;
  g_test->get_auth_token(auth_token);
  g_test->set_auth_token(string(""));

  time_t exp = ceph_clock_now(g_ceph_context);
  exp += 5;
  EXPECT_EQ(0, get_temp_url_sig("/v1/"TEST_BUCKET_NAME"/"TEST_BUCKET_OBJECT, 
                                "PUT", exp, temp_key, temp_url_sig));
  ostringstream oss;
  oss << "/swift/v1/"TEST_BUCKET_NAME"/"TEST_BUCKET_OBJECT"?temp_url_sig="
     << temp_url_sig << "&temp_url_expires=" << exp;
  g_test->send_request(string("PUT"), oss.str(),
                       read_bucket_object, (void *)data, (size_t)TEST_BUCKET_OBJECT_SIZE);
  EXPECT_EQ(201U, g_test->get_resp_code());

  time_t now = ceph_clock_now(g_ceph_context);
  sleep((exp - now)+1);
  
  g_test->send_request(string("PUT"), oss.str(),
                       read_bucket_object, (void *)data, (size_t)TEST_BUCKET_OBJECT_SIZE);
  EXPECT_EQ(401U, g_test->get_resp_code());

  g_test->set_auth_token(auth_token);
  g_test->send_request(string("GET"), "/swift/v1/"TEST_BUCKET_NAME"/"TEST_BUCKET_OBJECT);
  EXPECT_EQ(200U, g_test->get_resp_code());
  EXPECT_EQ(0, memcmp((void *)g_test->get_response_data()->c_str(), (void *)data, TEST_BUCKET_OBJECT_SIZE));

  /*Overriding the filename*/
  g_test->get_auth_token(auth_token);
  g_test->set_auth_token(string(""));

  exp = ceph_clock_now(g_ceph_context);
  exp += 5;
  EXPECT_EQ(0, get_temp_url_sig("/v1/"TEST_BUCKET_NAME"/"TEST_BUCKET_OBJECT, 
                                "PUT", exp, temp_key, temp_url_sig));
  oss.str("");
  oss << "/swift/v1/"TEST_BUCKET_NAME"/"TEST_BUCKET_OBJECT"?temp_url_sig="
     << temp_url_sig << "&temp_url_expires=" << exp << "&filename="TEST_BUCKET_OBJECT_1;
  g_test->send_request(string("PUT"), oss.str(),
                       read_bucket_object, (void *)data, (size_t)TEST_BUCKET_OBJECT_SIZE);
  EXPECT_EQ(201U, g_test->get_resp_code());
  
  g_test->set_auth_token(auth_token);
  g_test->send_request(string("GET"), "/swift/v1/"TEST_BUCKET_NAME"/"TEST_BUCKET_OBJECT_1);
  EXPECT_EQ(200U, g_test->get_resp_code());
  EXPECT_EQ(0, memcmp((void *)g_test->get_response_data()->c_str(), (void *)data, TEST_BUCKET_OBJECT_SIZE));
  EXPECT_EQ(0, delete_obj(TEST_BUCKET_OBJECT_1));

  delete data;
  EXPECT_EQ(0, delete_obj(TEST_BUCKET_OBJECT));
  EXPECT_EQ(0, delete_bucket());
  ASSERT_EQ(0, user_rm(uid, display_name));
}

TEST(TestRGWTempUrl, head) {
  string temp_key, rest_req;

  ASSERT_EQ(0, user_create(uid, display_name));
  
  rest_req = "/swift/v1/";
  g_test->set_extra_header(string("X-Account-Meta-Temp-Url-Key: "DEFAULT_TEMP_URL_KEY));
  g_test->send_request(string("POST"), rest_req, read_dummy_post, NULL, sizeof(int));
  EXPECT_EQ(200U, g_test->get_resp_code());

  EXPECT_EQ(0, user_info(uid, display_name, temp_key));
  EXPECT_EQ(0, temp_key.compare(DEFAULT_TEMP_URL_KEY));

  EXPECT_EQ(0, create_bucket());

  char *data = new char[TEST_BUCKET_OBJECT_SIZE];
  memset((void *)data, 0, TEST_BUCKET_OBJECT_SIZE);
  EXPECT_EQ(0, put_bucket_obj(TEST_BUCKET_OBJECT, data, TEST_BUCKET_OBJECT_SIZE));

  string temp_url_sig, auth_token;
  g_test->get_auth_token(auth_token);
  g_test->set_auth_token(string(""));

  time_t exp = ceph_clock_now(g_ceph_context);
  exp += 5;
  EXPECT_EQ(0, get_temp_url_sig("/v1/"TEST_BUCKET_NAME"/"TEST_BUCKET_OBJECT, 
                                "GET", exp, temp_key, temp_url_sig));
  ostringstream oss;
  oss << "/swift/v1/"TEST_BUCKET_NAME"/"TEST_BUCKET_OBJECT"?temp_url_sig="
     << temp_url_sig << "&temp_url_expires=" << exp;
  g_test->send_request(string("HEAD"), oss.str());
  EXPECT_EQ(200U, g_test->get_resp_code());
 
  exp += 5;
  EXPECT_EQ(0, get_temp_url_sig("/v1/"TEST_BUCKET_NAME"/"TEST_BUCKET_OBJECT, 
                                "PUT", exp, temp_key, temp_url_sig));
  oss.str("");
  oss << "/swift/v1/"TEST_BUCKET_NAME"/"TEST_BUCKET_OBJECT"?temp_url_sig="
     << temp_url_sig << "&temp_url_expires=" << exp;
  g_test->send_request(string("HEAD"), oss.str());
  EXPECT_EQ(200U, g_test->get_resp_code());

  delete data;
  g_test->set_auth_token(auth_token);
  EXPECT_EQ(0, delete_obj(TEST_BUCKET_OBJECT));
  EXPECT_EQ(0, delete_bucket());
  ASSERT_EQ(0, user_rm(uid, display_name));
}

int main(int argc, char *argv[]){
  vector<const char*> args;
  argv_to_vec(argc, (const char **)argv, args);

  global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT, CODE_ENVIRONMENT_UTILITY, 0);
  common_init_finish(g_ceph_context);
  g_test = new temp_url::test_helper();
  finisher = new Finisher(g_ceph_context);
#ifdef GTEST
  ::testing::InitGoogleTest(&argc, argv);
#endif
  finisher->start();

  if(g_test->extract_input(argc, argv) < 0){
    print_usage(argv[0]);
    return -1;
  }
#ifdef GTEST
  int r = RUN_ALL_TESTS();
  if (r >= 0) {
    cout << "There are no failures in the test case\n";
  } else {
    cout << "There are some failures\n";
  }
#endif
  finisher->stop();
  return 0;
}
