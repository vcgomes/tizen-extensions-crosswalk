// Copyright (c) 2013 Intel Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "bluetooth/bluetooth_context.h"
#include "common/picojson.h"

#if defined(TIZEN_MOBILE)
#include <bluetooth.h>
#endif

#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/uuid.h>

#define RFCOMM_RECORD "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>	\
<record>								\
  <attribute id=\"0x0001\">						\
    <sequence>								\
      <uuid value=\"%s\"/>						\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0004\">						\
    <sequence>								\
      <sequence>							\
        <uuid value=\"0x0100\"/>					\
      </sequence>							\
      <sequence>							\
        <uuid value=\"0x0003\"/>					\
        <uint8 value=\"%u\" name=\"channel\"/>				\
      </sequence>							\
    </sequence>								\
  </attribute>								\
									\
  <attribute id=\"0x0100\">						\
    <text value=\"%s\" name=\"name\"/>					\
  </attribute>								\
</record>"

typedef struct OnSDPServiceFoundData_ {
  std::string address;
  void* bt_context;
} OnSDPServiceFoundData;

typedef void (*rfcomm_callback_t) (uint8_t channel, int err, gpointer user_data);

static int bt_string2uuid(uuid_t *uuid, const char *string) {
  uint32_t data0, data4;
  uint16_t data1, data2, data3, data5;

  if (sscanf(string, "%08x-%04hx-%04hx-%04hx-%08x%04hx",
             &data0, &data1, &data2, &data3, &data4, &data5) == 6) {
    uint8_t val[16];

    data0 = g_htonl(data0);
    data1 = g_htons(data1);
    data2 = g_htons(data2);
    data3 = g_htons(data3);
    data4 = g_htonl(data4);
    data5 = g_htons(data5);

    memcpy(&val[0], &data0, 4);
    memcpy(&val[4], &data1, 2);
    memcpy(&val[6], &data2, 2);
    memcpy(&val[8], &data3, 2);
    memcpy(&val[10], &data4, 4);
    memcpy(&val[14], &data5, 2);

    sdp_uuid128_create(uuid, val);

    return 0;
  }

  return -EINVAL;
}

static uint32_t rfcomm_get_channel(int fd) {
  struct sockaddr_rc laddr;
  socklen_t alen = sizeof(laddr);

  memset(&laddr, 0, alen);

  if (getsockname(fd, (struct sockaddr *) &laddr, &alen) < 0)
    return 0;

  return laddr.rc_channel;
}

static int rfcomm_get_peer(int fd, char* address) {
  if (!address)
    return -1;

  struct sockaddr_rc raddr;
  socklen_t alen = sizeof(raddr);

  memset(&raddr, 0, alen);

  if (getpeername(fd, (struct sockaddr *) &raddr, &alen) < 0)
    return -1;

  ba2str(&raddr.rc_bdaddr, address);

  return 0;
}

// Returns an fd listening on 'channel' RFCOMM Channel
static int rfcomm_listen(uint8_t *channel) {
  int sk = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
  if (sk < 0)
    return -1;

  struct sockaddr_rc laddr;
  // All zeros means BDADDR_ANY and any channel.
  memset(&laddr, 0, sizeof(laddr));
  laddr.rc_family = AF_BLUETOOTH;

  if (bind(sk, (struct sockaddr *) &laddr, sizeof(laddr)) < 0) {
    close(sk);
    return -1;
  }

  listen(sk, 10);

  if (channel)
    *channel = rfcomm_get_channel(sk);

  return sk;
}

static int rfcomm_connect(const char *address, uint8_t channel) {
  int sk = socket(AF_BLUETOOTH, SOCK_STREAM | SOCK_NONBLOCK, BTPROTO_RFCOMM);
  if (sk < 0)
    return -1;

  struct sockaddr_rc laddr;
  // All zeros means BDADDR_ANY and any channel.
  memset(&laddr, 0, sizeof(laddr));

  laddr.rc_family = AF_BLUETOOTH;

  if (bind(sk, (struct sockaddr *) &laddr, sizeof(laddr)) < 0) {
    close(sk);
    return -1;
  }

  struct sockaddr_rc raddr;
  memset(&raddr, 0, sizeof(raddr));
  raddr.rc_family = AF_BLUETOOTH;
  raddr.rc_channel = channel;
  str2ba(address, &raddr.rc_bdaddr);

  if (connect(sk, (struct sockaddr *) &raddr, sizeof(raddr)) < 0)
    if (errno != EINPROGRESS)
      return -1;

  return sk;
}

struct search_context {
  bdaddr_t dst;
  sdp_session_t *session;
  rfcomm_callback_t cb;
  gpointer user_data;
  uuid_t uuid;
};

static void search_completed_cb(uint8_t type, uint16_t status,
                                uint8_t *rsp, size_t size, void *user_data) {
  struct search_context *ctxt = (struct search_context *) user_data;
  sdp_list_t *recs = NULL;
  sdp_record_t *record = NULL;
  sdp_list_t *protos;
  int scanned, seqlen = 0, bytesleft = size;
  uint8_t dataType, channel;
  int err = 0;

  if (status || type != SDP_SVC_SEARCH_ATTR_RSP) {
    g_printerr("status %d type %d\n", status, type);
    err = -EPROTO;
    goto done;
  }

  scanned = sdp_extract_seqtype(rsp, bytesleft, &dataType, &seqlen);
  if (!scanned || !seqlen)
    goto done;

  rsp += scanned;
  bytesleft -= scanned;
  do {
    sdp_record_t *rec;
    int recsize;

    recsize = 0;
    rec = sdp_extract_pdu(rsp, bytesleft, &recsize);
    if (!rec)
      break;

    if (!recsize) {
      sdp_record_free(rec);
      break;
    }

    scanned += recsize;
    rsp += recsize;
    bytesleft -= recsize;

    recs = sdp_list_append(recs, rec);
  } while (scanned < (ssize_t) size && bytesleft > 0);

  if (!recs || !recs->data)
    goto done;

  record = (sdp_record_t *) recs->data;

  if (sdp_get_access_protos(record, &protos) < 0)
    goto done;

  channel = sdp_get_proto_port(protos, RFCOMM_UUID);

done:
  if (ctxt->cb)
    ctxt->cb(channel, err, ctxt->user_data);

  if (recs)
    sdp_list_free(recs, (sdp_free_func_t) sdp_record_free);
}

static gboolean search_process_cb(GIOChannel *chan, GIOCondition cond,
                                  gpointer user_data) {
  struct search_context *ctxt = (struct search_context *) user_data;
  int err = 0;

  if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
    err = EIO;
    goto failed;
  }

  if (sdp_process(ctxt->session) < 0)
    goto failed;

  return TRUE;

failed:
  if (err) {
    sdp_close(ctxt->session);
    ctxt->session = NULL;

    if (ctxt->cb)
      ctxt->cb(0, err, ctxt->user_data);
  }

  return FALSE;
}

static gboolean connect_watch(GIOChannel *chan, GIOCondition cond,
                              gpointer user_data)
{
  struct search_context *ctxt = (struct search_context *) user_data;
  sdp_list_t *search, *attrids;
  uint32_t range = 0x0000ffff;
  socklen_t len;
  int sk, err, sk_err = 0;

  sk = g_io_channel_unix_get_fd(chan);

  len = sizeof(sk_err);
  if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &sk_err, &len) < 0)
    err = -errno;
  else
    err = -sk_err;

  if (err != 0)
    goto failed;

  if (sdp_set_notify(ctxt->session, search_completed_cb, ctxt) < 0) {
    err = -EIO;
    goto failed;
  }

  search = sdp_list_append(NULL, &ctxt->uuid);
  attrids = sdp_list_append(NULL, &range);
  if (sdp_service_search_attr_async(ctxt->session,
                                    search, SDP_ATTR_REQ_RANGE, attrids) < 0) {
    sdp_list_free(attrids, NULL);
    sdp_list_free(search, NULL);
    err = -EIO;
    goto failed;
  }

  sdp_list_free(attrids, NULL);
  sdp_list_free(search, NULL);

  /* Set callback responsible for update the internal SDP transaction */
  g_io_add_watch(chan, (GIOCondition) (G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL),
                 search_process_cb, ctxt);
  return FALSE;

failed:
  sdp_close(ctxt->session);
  ctxt->session = NULL;

  if (ctxt->cb)
    ctxt->cb(0, err, ctxt->user_data);

  return FALSE;
}

static struct search_context *create_search_context(const char *address,
                                                    const char *uuid) {
  struct search_context *ctxt;
  sdp_session_t *s;
  GIOChannel *chan;
  uint32_t prio = 1;
  bdaddr_t src, dst;
  int sk;

  memset(&src, 0, sizeof(src));
  str2ba(address, &dst);

  s = sdp_connect(&src, &dst, SDP_NON_BLOCKING);
  if (!s)
    return NULL;

  ctxt = (struct search_context *) g_try_malloc0(sizeof(struct search_context));
  if (!ctxt) {
    sdp_close(s);
    return NULL;
  }

  bacpy(&ctxt->dst, &dst);
  ctxt->session = s;
  bt_string2uuid(&ctxt->uuid, uuid);

  sk = sdp_get_socket(s);
  /* Set low priority for the SDP connection not to interfere with
   * other potential traffic.
   */
  if (setsockopt(sk, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio)) < 0)
    g_printerr("Setting SDP priority failed: %s (%d)\n",
               strerror(errno), errno);

  chan = g_io_channel_unix_new(sk);
  g_io_add_watch(chan, (GIOCondition) (G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL),
                 connect_watch, ctxt);

  g_io_channel_unref(chan);

  return ctxt;
}

static int bt_search_service(const char *address, const char *uuid,
                             rfcomm_callback_t cb, void *user_data) {
  struct search_context *ctxt;

  if (!cb)
    return -EINVAL;

  ctxt = create_search_context(address, uuid);
  if (ctxt < 0)
    return -ENOTCONN;

  ctxt->cb = cb;
  ctxt->user_data = user_data;

  return 0;
}

static void getPropertyValue(const char* key, GVariant* value,
    picojson::value::object& o) {
  if (!strcmp(key, "Class")) {
    guint32 class_id = g_variant_get_uint32(value);
    o[key] = picojson::value(static_cast<double>(class_id));
  } else if (!strcmp(key, "RSSI")) {
    gint16 class_id = g_variant_get_int16(value);
    o[key] = picojson::value(static_cast<double>(class_id));
  } else if (strcmp(key, "Devices")) { // FIXME(jeez): Handle 'Devices' property.
    std::string value_str;
    if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING))
      value_str = g_variant_get_string(value, NULL);
    else
      value_str = g_variant_print(value, false);
    o[key] = picojson::value(value_str);
  }
}

void BluetoothContext::OnSignal(GDBusProxy* proxy, gchar* sender, gchar* signal,
      GVariant* parameters, gpointer data) {
  BluetoothContext* handler = reinterpret_cast<BluetoothContext*>(data);

  if (!strcmp(signal, "DeviceFound")) {
    char* address;
    GVariantIter* it;

    g_variant_get(parameters, "(sa{sv})", &address, &it);
    handler->DeviceFound(std::string(address), it);
  } else if (!strcmp(signal, "PropertyChanged")) {
    char* name;
    GVariant* value;

    g_variant_get(parameters, "(sv)", &name, &value);

    if (!strcmp(name, "Devices")) {
      char* path;
      GVariantIter *iter;

      g_variant_get(value, "ao", &iter);

      while (g_variant_iter_loop(iter, "o", &path)) {
        g_dbus_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
                                 NULL,
                                 /* GDBusInterfaceInfo */
                                 "org.bluez", path, "org.bluez.Device",
                                 NULL,
                                 /* GCancellable */
                                 OnDeviceProxyCreatedThunk, data);
      }

      g_variant_iter_free(iter);
    } else {
      picojson::value::object property_updated;
      property_updated["cmd"] = picojson::value("AdapterUpdated");
      property_updated[name] = picojson::value(handler->adapter_info_[name]);
      handler->PostMessage(picojson::value(property_updated));

      // If in our callback ids map we have a reply_id related to the property
      // being updated now, then we must also reply to the PostMessage call.
      // This way we enforce that our JavaScript context calls the onsuccess
      // return callback only after the property has actually been modified.
      std::map<std::string, std::string>::iterator it =
          handler->callbacks_map_.find(name);

      if (it != handler->callbacks_map_.end()) {
        picojson::value::object property_changed;
        property_changed["cmd"] = picojson::value("");
        property_changed["reply_id"] = picojson::value(it->second);
        property_changed["error"] = picojson::value(static_cast<double>(0));
        handler->PostMessage(picojson::value(property_changed));
        handler->callbacks_map_.erase(it);
      }

      g_variant_unref(value);
    }
  }
}

void BluetoothContext::OnDeviceSignal(GDBusProxy* proxy, gchar* sender, gchar* signal,
      GVariant* parameters, gpointer data) {
  BluetoothContext* handler = reinterpret_cast<BluetoothContext*>(data);
  const char* iface = g_dbus_proxy_get_interface_name(proxy);

  // We only want org.bluez.Device signals.
  if (strcmp(iface, "org.bluez.Device"))
    return;

  // More specifically, PropertyChanged ones.
  if (strcmp(signal, "PropertyChanged"))
    return;

  const char* path = g_dbus_proxy_get_object_path(proxy);

  std::map<std::string, std::string>::iterator it =
      handler->object_path_address_map_.find(path);
  if (it == handler->object_path_address_map_.end())
    return;

  const char *address = it->second.c_str();

  const gchar* key;
  GVariant* value;
  picojson::value::object o;

  o["cmd"] = picojson::value("DeviceUpdated");
  o["found_on_discovery"] = picojson::value(false);
  o["Address"] = picojson::value(address);

  g_variant_get(parameters, "(sv)", &key, &value);

  getPropertyValue(key, value, o);

  handler->PostMessage(picojson::value(o));
}

void BluetoothContext::OnGotAdapterProperties(GObject*, GAsyncResult* res) {
  GError* error = 0;
  GVariant* result = g_dbus_proxy_call_finish(adapter_proxy_, res, &error);

  if (!result) {
    g_printerr("\n\nError Got DefaultAdapter Properties: %s\n", error->message);
    g_error_free(error);
    return;
  }

  const gchar* key;
  GVariant* value;
  GVariantIter* it;
  g_variant_get(result, "(a{sv})", &it);

  while (g_variant_iter_loop(it, "{sv}", &key, &value)) {
    if (!strcmp(key, "Devices")) {
      char* path;
      GVariantIter *iter;

      g_variant_get(value, "ao", &iter);

      while (g_variant_iter_loop(iter, "o", &path)) {
        DeviceMap::iterator it = known_devices_.find(path);
        if (it != known_devices_.end())
          continue;

        g_dbus_proxy_new_for_bus(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE,
                                 NULL,
                                 /* GDBusInterfaceInfo */
                                 "org.bluez", path, "org.bluez.Device",
                                 NULL,
                                 /* GCancellable */
                                 OnDeviceProxyCreatedThunk, this);
      }

      g_variant_iter_free(iter);
    } else {
      if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING))
        adapter_info_[key] = std::string(g_variant_get_string(value, NULL));
      else
        adapter_info_[key] = g_variant_print(value, false);
    }
  }

  if (!default_adapter_reply_id_.empty()) {
    picojson::value::object o;

    o["reply_id"] = picojson::value(default_adapter_reply_id_);
    default_adapter_reply_id_.clear();

    AdapterInfoToValue(o);
    SetSyncReply(picojson::value(o));
  }

  is_js_context_initialized_ = true;

  g_variant_iter_free(it);
}

void BluetoothContext::OnAdapterPropertySet(std::string property, GAsyncResult* res) {
  GError* error = 0;
  GVariant* result = g_dbus_proxy_call_finish(adapter_proxy_, res, &error);

  // We should only reply to the PostMessage here if an error happened when
  // changing the property. For replying to the successful property change
  // we wait until BluetoothContext::OnSignal receives the related PropertyChange
  // signal, so we avoid that our JavaScript context calls the onsuccess return
  // callback before the property was actually updated on the adapter.
  if (!result) {
    g_printerr("\n\nError Got DefaultAdapter Property SET: %s\n", error->message);
    g_error_free(error);
    picojson::value::object o;
    o["cmd"] = picojson::value("");
    o["reply_id"] = picojson::value(callbacks_map_[property]);

    // No matter the error info here, BlueZ4's documentation says the only
    // error that can be raised here is org.bluez.Error.InvalidArguments.
    o["error"] = picojson::value(static_cast<double>(1));
    PostMessage(picojson::value(o));

    callbacks_map_.erase(property);
    return;
  }

  g_variant_unref(result);
}

void BluetoothContext::OnAdapterProxyCreated(GObject*, GAsyncResult* res) {
  GError* error = 0;
  adapter_proxy_ = g_dbus_proxy_new_for_bus_finish(res, &error);

  if (!adapter_proxy_) {
    g_printerr("\n\n## adapter_proxy_ creation error: %s\n", error->message);
    g_error_free(error);
    return;
  }

  g_dbus_proxy_call(adapter_proxy_, "GetProperties", NULL,
    G_DBUS_CALL_FLAGS_NONE, 5000, NULL, OnGotAdapterPropertiesThunk, this);

  g_signal_connect(adapter_proxy_, "g-signal",
    G_CALLBACK(BluetoothContext::OnSignal), this);
}

void BluetoothContext::OnServiceProxyCreated(GObject*, GAsyncResult* res) {
  GError* error = 0;
  service_proxy_ = g_dbus_proxy_new_for_bus_finish(res, &error);

  if (!service_proxy_) {
    g_printerr("\n\n## adapter_proxy_ creation error: %s\n", error->message);
    g_error_free(error);
  }
}

void BluetoothContext::OnManagerCreated(GObject*, GAsyncResult* res) {
  GError* err = 0;
  manager_proxy_ = g_dbus_proxy_new_for_bus_finish(res, &err);

  if (!manager_proxy_) {
    g_printerr("## Manager Proxy creation error: %s\n", err->message);
    g_error_free(err);
    return;
  }

  g_dbus_proxy_call(manager_proxy_, "DefaultAdapter", NULL,
      G_DBUS_CALL_FLAGS_NONE, 5000, NULL, OnGotDefaultAdapterPathThunk, this);
}

void BluetoothContext::OnGotDefaultAdapterPath(GObject*, GAsyncResult* res) {
  GError* error = 0;
  GVariant* result = g_dbus_proxy_call_finish(manager_proxy_, res, &error);

  if (!result) {
    g_printerr("\n\nError Got DefaultAdapter Path: %s\n", error->message);
    g_error_free(error);
    return;
  }

  char* path;
  g_variant_get(result, "(o)", &path);

  g_dbus_proxy_new_for_bus(G_BUS_TYPE_SYSTEM,
      G_DBUS_PROXY_FLAGS_NONE,
      NULL, /* GDBusInterfaceInfo */
      "org.bluez",
      path,
      "org.bluez.Adapter",
      NULL, /* GCancellable */
      OnAdapterProxyCreatedThunk,
      this);

  g_dbus_proxy_new_for_bus(G_BUS_TYPE_SYSTEM,
      G_DBUS_PROXY_FLAGS_NONE,
      NULL, /* GDBusInterfaceInfo */
      "org.bluez",
      path,
      "org.bluez.Service",
      NULL, /* GCancellable */
      OnServiceProxyCreatedThunk,
      this);

  g_variant_unref(result);
  g_free(path);
}

void BluetoothContext::OnAdapterCreateBonding(GObject*, GAsyncResult* res) {
  GError* error = 0;
  GVariant* result = g_dbus_proxy_call_finish(adapter_proxy_, res, &error);

  picojson::value::object o;
  o["cmd"] = picojson::value("");
  o["reply_id"] = picojson::value(callbacks_map_["CreateBonding"]);
  o["error"] = picojson::value(static_cast<double>(0));

  if (!result) {
    g_printerr("\n\nError on creating adapter bonding: %s\n", error->message);
    g_error_free(error);

    o["error"] = picojson::value(static_cast<double>(1));
  } else {
    g_variant_unref(result);
  }

  PostMessage(picojson::value(o));
  callbacks_map_.erase("CreateBonding");
}

void BluetoothContext::OnAdapterDestroyBonding(GObject*, GAsyncResult* res) {
  GError* error = 0;
  GVariant* result = g_dbus_proxy_call_finish(adapter_proxy_, res, &error);

  picojson::value::object o;
  o["cmd"] = picojson::value("");
  o["reply_id"] = picojson::value(callbacks_map_["DestroyBonding"]);
  o["error"] = picojson::value(static_cast<double>(0));

  if (!result) {
    g_printerr("\n\nError on destroying adapter bonding: %s\n", error->message);
    g_error_free(error);

    o["error"] = picojson::value(static_cast<double>(2));
  } else {
    g_variant_unref(result);
  }

  PostMessage(picojson::value(o));
  callbacks_map_.erase("DestroyBonding");
}

void BluetoothContext::OnFoundDevice(GObject*, GAsyncResult* res) {
  picojson::value::object o;
  char* object_path;
  GError* error = 0;
  GVariant* result = g_dbus_proxy_call_finish(adapter_proxy_, res, &error);

  if (!result) {
    g_printerr("\n\nError on destroying adapter bonding: %s\n", error->message);
    g_error_free(error);

    o["cmd"] = picojson::value("");
    o["reply_id"] = picojson::value(callbacks_map_["DestroyBonding"]);
    o["error"] = picojson::value(static_cast<double>(1));

    PostMessage(picojson::value(o));
    callbacks_map_.erase("DestroyBonding");
    return;
  }

  g_variant_get(result, "(o)", &object_path);
  g_dbus_proxy_call(adapter_proxy_, "RemoveDevice",
      g_variant_new("(o)", object_path),
      G_DBUS_CALL_FLAGS_NONE, -1, NULL, OnAdapterDestroyBondingThunk, this);

  g_variant_unref(result);
}

BluetoothContext::~BluetoothContext() {
  delete api_;

  if (adapter_proxy_)
    g_object_unref(adapter_proxy_);

  DeviceMap::iterator it;
  for (it = known_devices_.begin(); it != known_devices_.end(); ++it)
    g_object_unref(it->second);

#if defined(TIZEN_MOBILE)
    bt_deinitialize();
#endif
}

void BluetoothContext::PlatformInitialize() {
  adapter_proxy_ = 0;
  manager_proxy_ = 0;
  pending_listen_socket_ = -1;

  rfcomm_listener_ = g_socket_listener_new();

  is_js_context_initialized_ = false;

  default_adapter_reply_id_ = std::string();

  g_dbus_proxy_new_for_bus(G_BUS_TYPE_SYSTEM,
      G_DBUS_PROXY_FLAGS_NONE,
      NULL, /* GDBusInterfaceInfo */
      "org.bluez",
      "/",
      "org.bluez.Manager",
      NULL, /* GCancellable */
      OnManagerCreatedThunk,
      this);
}

void BluetoothContext::HandleGetDefaultAdapter(const picojson::value& msg) {
  picojson::value::object o;

  // We still don't have the information. It was requested during
  // initialization, so it should arrive eventually.
  if (adapter_info_.empty()) {
    default_adapter_reply_id_ = msg.get("reply_id").to_str();
    return;
  }

  o["reply_id"] = picojson::value(msg.get("reply_id").to_str());
  AdapterInfoToValue(o);

  // This is the JS API entry point, so we should clean our message queue
  // on the next PostMessage call.
  if (!is_js_context_initialized_)
    is_js_context_initialized_ = true;

  picojson::value v(o);
  SetSyncReply(v);
}

void BluetoothContext::DeviceFound(std::string address, GVariantIter* properties) {
  const gchar* key;
  GVariant* value;
  picojson::value::object o;

  o["cmd"] = picojson::value("DeviceFound");
  o["found_on_discovery"] = picojson::value(true);

  while (g_variant_iter_loop(properties, "{sv}", &key, &value))
    getPropertyValue(key, value, o);

  picojson::value v(o);
  PostMessage(v);
}

void BluetoothContext::HandleSetAdapterProperty(const picojson::value& msg) {
  std::string property = msg.get("property").to_str();

  GVariant* value = 0;
  if (property == "Name")
    value = g_variant_new("s", msg.get("value").to_str().c_str());
  else if (property == "Discoverable") {
    value = g_variant_new("b", msg.get("value").get<bool>());

    if (msg.contains("timeout")) {
      const guint32 timeout = static_cast<guint32>(msg.get("timeout").get<double>());
      g_dbus_proxy_call(adapter_proxy_, "SetProperty",
          g_variant_new("(sv)", "DiscoverableTimeout", g_variant_new("u", timeout)),
          G_DBUS_CALL_FLAGS_NONE, 5000, NULL, NULL, NULL);
    }
  } else if (property == "Powered")
    value = g_variant_new("b", msg.get("value").get<bool>());

  assert(value);

  callbacks_map_[property] = msg.get("reply_id").to_str();

  OnAdapterPropertySetData* property_set_callback_data_ =
      new OnAdapterPropertySetData;
  property_set_callback_data_->property = property;
  property_set_callback_data_->bt_context = this;

  g_dbus_proxy_call(adapter_proxy_, "SetProperty",
      g_variant_new("(sv)", property.c_str(), value),
      G_DBUS_CALL_FLAGS_NONE, 5000, NULL, OnAdapterPropertySetThunk,
      property_set_callback_data_);
}

void BluetoothContext::HandleCreateBonding(const picojson::value& msg) {
  std::string address = msg.get("address").to_str();
  callbacks_map_["CreateBonding"] = msg.get("reply_id").to_str();

  g_dbus_proxy_call(adapter_proxy_, "CreatePairedDevice",
      g_variant_new ("(sos)", address.c_str(), "/", "KeyboardDisplay"),
      G_DBUS_CALL_FLAGS_NONE, -1, NULL, OnAdapterCreateBondingThunk, this);
}

void BluetoothContext::HandleDestroyBonding(const picojson::value& msg) {
  std::string address = msg.get("address").to_str();
  callbacks_map_["DestroyBonding"] = msg.get("reply_id").to_str();

  g_dbus_proxy_call(adapter_proxy_, "FindDevice",
      g_variant_new("(s)", address.c_str()),
      G_DBUS_CALL_FLAGS_NONE, -1, NULL, OnFoundDeviceThunk, this);
}

gboolean BluetoothContext::OnSocketHasData(GSocket* client, GIOCondition cond,
                                              gpointer user_data) {
  BluetoothContext* handler = reinterpret_cast<BluetoothContext*>(user_data);
  int fd = g_socket_get_fd(client);
  picojson::value::object o;

  if (cond & G_IO_ERR || cond & G_IO_HUP) {
    o["cmd"] = picojson::value("SocketClosed");
    o["socket_fd"] = picojson::value(static_cast<double>(fd));

    handler->PostMessage(picojson::value(o));

    return false;
  }

  gchar buf[512];
  gssize len;

  len = g_socket_receive(client, buf, sizeof(buf), NULL, NULL);
  if (len < 0)
    return false;

  o["cmd"] = picojson::value("SocketHasData");
  o["socket_fd"] = picojson::value(static_cast<double>(fd));
  o["data"] = picojson::value(buf, len);

  handler->PostMessage(picojson::value(o));

  return true;
}

void BluetoothContext::OnListenerAccept(GObject* object, GAsyncResult* res) {
  GError* error = 0;
  GSocket *socket = g_socket_listener_accept_socket_finish(rfcomm_listener_, res,
                                                           NULL, &error);
  if (!socket) {
    g_printerr("\n\nlistener_accept_socket_finish failed %s\n", error->message);
    return;
  }

  sockets_.push_back(socket);

  int fd = g_socket_get_fd(socket);
  uint32_t channel = rfcomm_get_channel(fd);
  char address[18]; // "XX:XX:XX:XX:XX:XX"
  picojson::value::object o;

  rfcomm_get_peer(fd, address);

  o["cmd"] = picojson::value("RFCOMMSocketAccept");
  o["channel"] = picojson::value(static_cast<double>(channel));
  o["socket_fd"] = picojson::value(static_cast<double>(fd));
  o["peer"] = picojson::value(address);

  PostMessage(picojson::value(o));

  GSource *source = g_socket_create_source(socket, G_IO_IN, NULL);

  g_source_set_callback(source, (GSourceFunc) BluetoothContext::OnSocketHasData,
                        this, NULL);
  g_source_attach(source, NULL);
  g_source_unref(source);
}

void BluetoothContext::OnServiceAddRecord(GObject* object, GAsyncResult* res) {
  GError* error = 0;
  picojson::value::object o;
  GVariant* result = g_dbus_proxy_call_finish(service_proxy_, res, &error);

  o["cmd"] = picojson::value("");
  o["reply_id"] = picojson::value(callbacks_map_["RFCOMMListen"]);

  if (!result) {
    o["error"] = picojson::value(static_cast<double>(1));

    close(pending_listen_socket_);

    pending_listen_socket_ = -1;

    g_printerr("\n\nError OnServiceAddRecord: %s\n", error->message);
    g_error_free(error);
  } else {
    uint32_t handle;
    int sk = pending_listen_socket_;
    pending_listen_socket_ = -1;

    GSocket *socket = g_socket_new_from_fd(sk, NULL);
    g_socket_set_blocking(socket, false);

    servers_.push_back(socket);

    g_socket_listener_add_socket(rfcomm_listener_, socket, NULL, NULL);

    g_socket_listener_accept_async(rfcomm_listener_, NULL,
                                   OnListenerAcceptThunk, this);

    g_variant_get(result, "(u)", &handle);

    o["error"] = picojson::value(static_cast<double>(0));
    o["server_fd"] = picojson::value(static_cast<double>(sk));
    o["sdp_handle"] = picojson::value(static_cast<double>(handle));
    o["channel"] = picojson::value(static_cast<double>(rfcomm_get_channel(sk)));
  }

  callbacks_map_.erase("RFCOMMListen");
  g_variant_unref(result);

  PostMessage(picojson::value(o));
}

void BluetoothContext::HandleRFCOMMListen(const picojson::value& msg) {
  std::string name = msg.get("name").to_str();
  std::string uuid = msg.get("uuid").to_str();
  uint8_t channel = 0;
  int sk;

  // FIXME(vcgomes): Error handling
  if (pending_listen_socket_ >= 0)
    return;

  sk = rfcomm_listen(&channel);
  if (sk < 0)
    return;

  callbacks_map_["RFCOMMListen"] = msg.get("reply_id").to_str();

  pending_listen_socket_ = sk;

  char *record = g_strdup_printf(RFCOMM_RECORD, uuid.c_str(), channel, name.c_str());

  g_dbus_proxy_call(service_proxy_, "AddRecord", g_variant_new("(s)", record),
                    G_DBUS_CALL_FLAGS_NONE, -1, NULL, OnServiceAddRecordThunk, this);
}

void BluetoothContext::OnSDPServiceFound(uint8_t channel, int err, gpointer user_data)
{
  OnSDPServiceFoundData* data = reinterpret_cast<OnSDPServiceFoundData*>(user_data);
  BluetoothContext *context = reinterpret_cast<BluetoothContext*>(data->bt_context);
  picojson::value::object o;

  o["cmd"] = picojson::value("");
  o["reply_id"] = picojson::value(context->callbacks_map_["ConnectRFCOMMByUUID"]);

  context->callbacks_map_.erase("ConnectRFCOMMByUUID");

  if (err < 0) {
    o["error"] = picojson::value(static_cast<double>(1));

  } else {
    int sk = rfcomm_connect(data->address.c_str(), channel);

    if (sk < 0) {
      g_printerr("\nOnSDPServiceFound Connect err %d\n", err);
      o["error"] = picojson::value(static_cast<double>(1));

    } else {
      GSocket *socket = g_socket_new_from_fd(sk, NULL);
      GSource *source = g_socket_create_source(socket, G_IO_IN, NULL);

      context->sockets_.push_back(socket);

      g_source_set_callback(source, (GSourceFunc) BluetoothContext::OnSocketHasData,
                            context, NULL);
      g_source_attach(source, NULL);
      g_source_unref(source);

      o["socket_fd"] = picojson::value(static_cast<double>(sk));
      o["error"] = picojson::value(static_cast<double>(0));
    }
  }

  picojson::value v(o);
  context->PostMessage(v);
}

void BluetoothContext::HandleRFCOMMConnectByUUID(const picojson::value& msg) {
  std::map<std::string, std::string>::iterator it = object_path_address_map_.begin();

  callbacks_map_["ConnectRFCOMMByUUID"] = msg.get("reply_id").to_str();

  OnSDPServiceFoundData* data = new OnSDPServiceFoundData;

  data->address = msg.get("peer").to_str();
  data->bt_context = this;

  std::string uuid = msg.get("uuid").to_str();

  if (bt_search_service(data->address.c_str(), uuid.c_str(),
                        BluetoothContext::OnSDPServiceFound, data) < 0) {
    g_printerr("Could not make a SDP search\n");
    return;
  }
}

void BluetoothContext::OnDeviceProxyCreated(GObject* object, GAsyncResult* res) {
  GDBusProxy* device_proxy;
  GError* error = 0;

  device_proxy = g_dbus_proxy_new_for_bus_finish(res, &error);
  if (!device_proxy) {
    g_printerr("\n\n## device_proxy creation error: %s\n", error->message);
    g_error_free(error);
    return;
  }

  const char* path = g_dbus_proxy_get_object_path(device_proxy);
  known_devices_[path] = device_proxy;

  g_dbus_proxy_call(device_proxy, "GetProperties", NULL,
    G_DBUS_CALL_FLAGS_NONE, 5000, NULL, OnGotDevicePropertiesThunk, this);

  g_signal_connect(device_proxy, "g-signal",
    G_CALLBACK(BluetoothContext::OnDeviceSignal), this);
}

void BluetoothContext::OnGotDeviceProperties(GObject* object, GAsyncResult* res) {
  GError* error = 0;
  GDBusProxy *device_proxy = reinterpret_cast<GDBusProxy*>(object);
  GVariant* result = g_dbus_proxy_call_finish(device_proxy, res, &error);

  if (!result) {
    g_printerr("\n\nError OnGotDeviceProperties: %s\n", error->message);
    g_error_free(error);
    return;
  }

  const gchar* key;
  GVariant* value;
  GVariantIter* it;
  picojson::value::object o;

  o["cmd"] = picojson::value("DeviceUpdated");
  o["found_on_discovery"] = picojson::value(false);

  g_variant_get(result, "(a{sv})", &it);

  while (g_variant_iter_loop(it, "{sv}", &key, &value)) {
    if (!strcmp(key, "Address")) {
      const char* address = g_variant_get_string(value, NULL);
      const char* path = g_dbus_proxy_get_object_path(device_proxy);

      object_path_address_map_[path] = address;
    }

    getPropertyValue(key, value, o);

  }

  picojson::value v(o);
  PostMessage(v);
}

void BluetoothContext::HandleSocketWriteData(const picojson::value& msg) {
  int fd = static_cast<int>(msg.get("socket_fd").get<double>());
  std::vector<GSocket*>::iterator it = sockets_.begin();
  gssize len = 0;

  for (; it != sockets_.end(); ++it) {
    GSocket *socket = *it;

    if (g_socket_get_fd(socket) == fd) {
      std::string data = msg.get("data").to_str();

      len = g_socket_send(socket, data.c_str(), data.length(), NULL, NULL);
      break;
    }
  }

  picojson::value::object o;
  o["size"] = picojson::value(static_cast<double>(len));
  SetSyncReply(picojson::value(o));
}

void BluetoothContext::HandleCloseSocket(const picojson::value& msg) {
  int fd = static_cast<int>(msg.get("socket_fd").get<double>());
  std::vector<GSocket*>::iterator it = sockets_.begin();

  for (; it != sockets_.end(); ++it) {
    GSocket *socket = *it;

    if (g_socket_get_fd(socket) == fd) {
      g_socket_close(socket, NULL);
      break;
    }
  }

  picojson::value::object o;
  o["cmd"] = picojson::value("");
  o["reply_id"] = msg.get("reply_id");
  o["error"] = picojson::value(static_cast<double>(0));

  picojson::value v(o);
  PostMessage(v);
}

void BluetoothContext::OnServiceRemoveRecord(GObject* object, GAsyncResult* res) {
  GError* error = 0;
  GVariant* result = g_dbus_proxy_call_finish(service_proxy_, res, &error);
  picojson::value::object o;

  if (!result) {
    o["error"] = picojson::value(static_cast<double>(1));
  } else {
    o["error"] = picojson::value(static_cast<double>(0));
    g_variant_unref(result);
  }

  o["cmd"] = picojson::value("");
  o["reply_id"] = picojson::value(callbacks_map_["UnregisterServer"]);

  callbacks_map_.erase("UnregisterServer");

  PostMessage(picojson::value(o));
}

void BluetoothContext::HandleUnregisterServer(const picojson::value& msg) {
  int fd = static_cast<int>(msg.get("server_fd").get<double>());
  uint32_t handle = static_cast<uint32_t>(msg.get("sdp_handle").get<double>());
  std::vector<GSocket*>::iterator it = servers_.begin();

  for (; it != servers_.end(); ++it) {
    GSocket *socket = *it;

    if (g_socket_get_fd(socket) == fd) {
      g_socket_close(socket, NULL);
      break;
    }
  }

  callbacks_map_["UnregisterServer"] = msg.get("reply_id").to_str();

  g_dbus_proxy_call(service_proxy_, "RemoveRecord", g_variant_new("(u)", handle),
                    G_DBUS_CALL_FLAGS_NONE, -1, NULL, OnServiceRemoveRecordThunk, this);
}
