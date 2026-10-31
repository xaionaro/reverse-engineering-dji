/*
 * DJI DUML over BLE Wireshark Dissector
 *
 * This dissector handles DJI's DUML (DJI Unified Message Language) protocol
 * when transported over BLE (Bluetooth Low Energy) and Ethernet.
 *
 * The dissector identifies DUML packets within Bluetooth ATT notifications
 * and indications, as well as standalone Ethernet packets.
 */

#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/proto_data.h>
#include <stdbool.h>
#include <stddef.h>
#include <ws_symbol_export.h>
#include <ws_version.h>
#include <wsutil/plugins.h>

#define DUML_MAGIC 0x55
#define BLE_MAGIC 0xEE

static int proto_dji_duml = -1;
static expert_field ei_duml_incomplete = EI_INIT;

/* DUML Header fields */
static int hf_duml_magic = -1;
static int hf_duml_len = -1;
static int hf_duml_ver = -1;
static int hf_duml_crc8 = -1;
static int hf_duml_src = -1;
static int hf_duml_dst = -1;
static int hf_duml_seq = -1;
static int hf_duml_flags = -1;
static int hf_duml_set = -1;
static int hf_duml_id = -1;
static int hf_duml_payload = -1;
static int hf_duml_crc16 = -1;

/* Payload specific fields */
static int hf_duml_battery_cap = -1;
static int hf_duml_pairing_pin = -1;
static int hf_duml_pairing_device_id = -1;
static int hf_duml_rc_rh = -1;
static int hf_duml_rc_rv = -1;
static int hf_duml_rc_lh = -1;
static int hf_duml_rc_lv = -1;
static int hf_duml_rc_buttons = -1;
static int hf_duml_rtmp_url = -1;
static int hf_duml_param_name = -1;
static int hf_duml_param_val = -1;
static int hf_duml_param_type = -1;
static int hf_duml_param_len = -1;
static int hf_duml_param_id = -1;
static int hf_duml_param_unknown0 = -1;
static int hf_duml_param_unknown1 = -1;
static int hf_duml_wifi_ssid = -1;
static int hf_duml_wifi_psk = -1;
static int hf_duml_conf_res = -1;
static int hf_duml_conf_bitrate = -1;
static int hf_duml_conf_fps = -1;
static int hf_duml_conf_url_len = -1;
static int hf_duml_version = -1;
static int hf_duml_sn = -1;

#define DUML_CMD(set, id) (((set) << 8) | (id))

/* Command IDs */
#define CMD_GET_SERIAL_NUM DUML_CMD(0x00, 0x0A)
#define CMD_PAIRING_STAGE2 DUML_CMD(0x00, 0x32)
#define CMD_FCC_SUPPORT DUML_CMD(0x00, 0xDE)
#define CMD_GET_PRODUCT_ID DUML_CMD(0x01, 0x0D)
#define CMD_GET_VERSION DUML_CMD(0x01, 0x1E)
#define CMD_OSMO_BROADCAST DUML_CMD(0x02, 0x08)
#define CMD_VIDEO_STREAM_SUBSCRIBE DUML_CMD(0x02, 0x3C)
#define CMD_VIDEO_STREAM_UNSUBSCRIBE DUML_CMD(0x02, 0x3D)
#define CMD_PAIRING_STARTED DUML_CMD(0x02, 0x80)
#define CMD_HEARTBEAT_V1 DUML_CMD(0x00, 0x2b)
#define CMD_PARAMETER_PUSH DUML_CMD(0x00, 0x99)
#define CMD_PARAM_PUSH DUML_CMD(0x00, 0x99)
#define CMD_SHOT_INFO_GET DUML_CMD(0x02, 0x99)
#define CMD_START_STOP_STREAMING DUML_CMD(0x02, 0x8E)
#define CMD_PREP_STREAMING DUML_CMD(0x02, 0xE1)
#define CMD_MOTOR_CONTROL DUML_CMD(0x03, 0x21)
#define CMD_GOGGLES_MODE DUML_CMD(0x03, 0x3D)
#define CMD_GIMBAL_STATUS DUML_CMD(0x04, 0x05)
#define CMD_KEEP_ALIVE DUML_CMD(0x04, 0x27)
#define CMD_FLIGHT_STICK_DATA DUML_CMD(0x03, 0x02)
#define CMD_RC_SIM_DATA DUML_CMD(0x06, 0x24)
#define CMD_CAMERA_AP_INFO DUML_CMD(0x07, 0x07)
#define CMD_CAMERA_AP_PSK DUML_CMD(0x07, 0x0E)
#define CMD_SET_PAIRING_PIN DUML_CMD(0x07, 0x45)
#define CMD_CONNECT_WIFI DUML_CMD(0x07, 0x47)
#define CMD_START_SCANNING_WIFI DUML_CMD(0x07, 0xAB)
#define CMD_WIFI_SCAN_REPORT DUML_CMD(0x07, 0xAC)
#define CMD_CONFIGURE_STREAMING DUML_CMD(0x08, 0x78)
#define CMD_BATTERY_STATUS DUML_CMD(0x0D, 0x02)
#define CMD_GET_BATTERY_INFO DUML_CMD(0x0D, 0x03)
#define CMD_CONF_STREAMING DUML_CMD(0x40, 0x08)

/* BLE Wrapper fields */
static int hf_dji_ble_magic = -1;
static int hf_dji_ble_len = -1;
static int hf_dji_ble_ver = -1;
static int hf_dji_ble_type = -1;

static int ett_dji_duml = -1;
static int ett_dji_ble = -1;
static int ett_dji_payload = -1;

/* clang-format off */
static const value_string dji_component_ids[] = {
    {0x01, "camera"},
    {0x02, "app"},
    {0x03, "gimbal"},
    {0x04, "flight_controller"},
    {0x05, "wifi_air"},
    {0x06, "remote_controller"},
    {0x07, "wifi_ground_station"},
    {0x08, "video_transmission"},
    {0x09, "battery"},
    {0x0e, "gimbal2"},
    {0x11, "vision"},
    {0x17, "goggles"},
    {0x21, "payload"},
    {0x28, "camera_ext"},
    {0x88, "pairer"},
    {0, NULL}
};

static const value_string dji_component_shorthands[] = {
    {0x01, "cam"},
    {0x02, "app"},
    {0x03, "gim"},
    {0x04, "fc"},
    {0x05, "wair"},
    {0x06, "rc"},
    {0x07, "wgs"},
    {0x08, "vtx"},
    {0x09, "bat"},
    {0x0e, "gim2"},
    {0x11, "vis"},
    {0x17, "gog"},
    {0x21, "pay"},
    {0x28, "cex"},
    {0x88, "pr"},
    {0, NULL}
};

static const value_string dji_ble_types[] = {
    {0x00, "Handshake"},
    {0x01, "DroneCmdEx"},
    {0x02, "Video"},
    {0x03, "DroneCmd"},
    {0, NULL}
};

static const value_string dji_cmd_sets[] = {
    {0x00, "General/Common"},
    {0x01, "General/Info"},
    {0x02, "Camera/Video"},
    {0x03, "FlightControl"},
    {0x04, "Gimbal"},
    {0x06, "RemoteController"},
    {0x07, "WiFi/Pairing"},
    {0x08, "Config"},
    {0x0a, "Vision"},
    {0x0d, "Battery"},
    {0, NULL}
};
/* clang-format on */

/* clang-format off */
static const value_string dji_resolutions[] = {
    {0x04, "720p"},  /* [djictl/pkg/duml/resolution.go#L21] */
    {0x0a, "1080p"}, /* [djictl/pkg/duml/resolution.go#L23] */
    {0x47, "480p"},  /* [djictl/pkg/duml/resolution.go#L19] */
    {0, NULL}
};

static const value_string dji_fps_vals[] = {
    {0x02, "25 FPS"}, /* [djictl/pkg/duml/fps.go#L17] */
    {0x03, "30 FPS"}, /* [djictl/pkg/duml/fps.go#L18] */
    {0, NULL}
};

static const value_string dji_cmd_names[] = {
    {0x0001, "get_version"},
    {0x000A, "get_serial_num"},
    {0x002B, "heartbeat?"},
    {0x0032, "pairing_stage2"},
    {0x00DE, "fcc_support"},
    {0x0099, "parameter_push"},
    {0x010D, "get_product_id"},
    {0x011E, "get_version"},
    {0x0201, "take_photo?"},
    {0x0202, "start_stop_record?"},
    {0x0206, "goggles_mode_toggle?"},
    {0x0208, "osmo_broadcast_config"},
    {0x023C, "video_stream_subscribe"},
    {0x023D, "video_stream_unsubscribe"},
    {0x0280, "pairing_started/camera_status"},
    {0x028E, "start_stop_streaming"},
    {0x0299, "shot_info_get"},
    {0x02E1, "prepare_to_live_stream"},
    {0x0301, "get_flight_status?"},
    {0x0302, "flight_stick_data"},
    {0x0321, "motor_control"},
    {0x0329, "joystick_command?"},
    {0x033D, "goggles_mode"},
    {0x0405, "gimbal_status"},
    {0x0427, "keep_alive"},
    {0x0624, "remote_controller_simulator_data"},
    {0x0707, "camera_ap_info"},
    {0x070E, "camera_ap_info_psk"},
    {0x0745, "set_pairing_pin/status"},
    {0x0746, "pairing_pin_approved?"},
    {0x0747, "connect_to_wifi"},
    {0x07AB, "start_scanning_wifi"},
    {0x07AC, "wifi_scan_results"},
    {0x0878, "configure_streaming"},
    {0x0D01, "battery_static_info?"},
    {0x0D02, "battery_status"},
    {0x0D03, "get_battery_info"},
    {0x4008, "video_streaming_config"},
    {0, NULL}
};

/* clang-format on */

typedef struct {
  tvbuff_t *tvb;
  packet_info *pinfo;
  proto_tree *payload_tree;
  guint offset;
  guint length;
  guint8 flags;
  bool is_request;
  char *content;
  size_t content_size;
} duml_payload_t;

typedef struct {
  guint16 length;
  guint8 src;
  guint8 dst;
  guint8 seq_hi;
  guint8 seq_lo;
  guint16 seq;
  guint8 flags;
  guint8 set;
  guint8 id;
  guint8 version;
  guint8 header_size;
} duml_header_t;

static void dissect_duml_pairing(duml_payload_t *ctx);
static void dissect_duml_wifi(duml_payload_t *ctx, guint8 id);
static void dissect_duml_battery(duml_payload_t *ctx);
static void dissect_duml_stream_config(duml_payload_t *ctx);
static void dissect_duml_rc_simulator(duml_payload_t *ctx);
static void dissect_duml_param_push(duml_payload_t *ctx);
static void dissect_duml_version(duml_payload_t *ctx);
static void dissect_duml_broadcast(duml_payload_t *ctx);
static void dissect_duml_fcc(duml_payload_t *ctx);
static void dissect_duml_serial(duml_payload_t *ctx);

static void dissect_duml_pairing(duml_payload_t *ctx) {
  if (ctx->length < 1)
    return;

  if (ctx->is_request) {
    /* Handle simple 6-character PIN typically used for pairing */
    if (ctx->length == 6) {
      proto_tree_add_item(ctx->payload_tree, hf_duml_pairing_pin, ctx->tvb,
                          ctx->offset, 6, ENC_ASCII | ENC_NA);
      g_snprintf(ctx->content, ctx->content_size, "pin:%s",
                 tvb_format_text(ctx->pinfo->pool, ctx->tvb, ctx->offset, 6));
      return;
    }

    /* Fallback to length-prefixed ID + PIN */
    guint8 len1 = tvb_get_uint8(ctx->tvb, ctx->offset);
    if (ctx->length >= (guint)(1 + len1 + 1)) {
      proto_tree_add_item(ctx->payload_tree, hf_duml_pairing_device_id, ctx->tvb,
                          ctx->offset + 1, len1, ENC_ASCII | ENC_NA);
      guint8 len2 = tvb_get_uint8(ctx->tvb, ctx->offset + 1 + len1);
      if (ctx->length >= (guint)(1 + len1 + 1 + len2)) {
        proto_tree_add_item(ctx->payload_tree, hf_duml_pairing_pin, ctx->tvb,
                            ctx->offset + 1 + len1 + 1, len2,
                            ENC_ASCII | ENC_NA);
        g_snprintf(ctx->content, ctx->content_size, "device:%s, pin:%s",
                   tvb_format_text(ctx->pinfo->pool, ctx->tvb, ctx->offset + 1,
                                   len1),
                   tvb_format_text(ctx->pinfo->pool, ctx->tvb,
                                   ctx->offset + 1 + len1 + 1, len2));
      }
    }
  } else {
    g_snprintf(ctx->content, ctx->content_size, "pairing response payload:%s",
               tvb_bytes_to_str(ctx->pinfo->pool, ctx->tvb, ctx->offset,
                                ctx->length));
  }
}

static void dissect_duml_wifi(duml_payload_t *ctx, guint8 id) {
  if (id == 0xAB) { /* start_scanning_wifi */
    g_snprintf(ctx->content, ctx->content_size, "%s",
               ctx->is_request ? "scan request" : "scan response");
    return;
  }
  if (id == 0xAC) { /* wifi_scan_results */
    g_snprintf(ctx->content, ctx->content_size, "%s",
               ctx->is_request ? "scan results report" : "scan results response");
    return;
  }
  if (id == 0x47) { /* connect_to_wifi */
    if (!ctx->is_request) {
      if (ctx->length >= 1) {
        guint8 status = tvb_get_uint8(ctx->tvb, ctx->offset);
        g_snprintf(ctx->content, ctx->content_size, "status:%u", status);
      }
      return;
    }

    if (ctx->length < 1)
      return;
    guint8 s_len = tvb_get_uint8(ctx->tvb, ctx->offset);
    if (ctx->length < (guint)(1 + s_len + 1))
      return;

    proto_tree_add_item(ctx->payload_tree, hf_duml_wifi_ssid, ctx->tvb,
                        ctx->offset + 1, s_len, ENC_ASCII | ENC_NA);
    guint8 p_len = tvb_get_uint8(ctx->tvb, ctx->offset + 1 + s_len);
    if (ctx->length < (guint)(1 + s_len + 1 + p_len)) {
      g_snprintf(
          ctx->content, ctx->content_size, "ssid:%s",
          tvb_format_text(ctx->pinfo->pool, ctx->tvb, ctx->offset + 1, s_len));
      return;
    }

    proto_tree_add_item(ctx->payload_tree, hf_duml_wifi_psk, ctx->tvb,
                        ctx->offset + 1 + s_len + 1, p_len, ENC_ASCII | ENC_NA);
    g_snprintf(
        ctx->content, ctx->content_size, "ssid:%s, psk:%s",
        tvb_format_text(ctx->pinfo->pool, ctx->tvb, ctx->offset + 1, s_len),
        tvb_format_text(ctx->pinfo->pool, ctx->tvb, ctx->offset + 1 + s_len + 1,
                        p_len));
    return;
  }

  if ((id == 0x07 || id == 0x0E) && !ctx->is_request && ctx->length >= 2) {
    guint16 slen = tvb_get_ntohs(ctx->tvb, ctx->offset);
    if (ctx->length < (guint)(2 + slen))
      return;

    if (id == 0x07) {
      proto_tree_add_item(ctx->payload_tree, hf_duml_wifi_ssid, ctx->tvb,
                          ctx->offset + 2, slen, ENC_ASCII | ENC_NA);
      g_snprintf(
          ctx->content, ctx->content_size, "ssid:%s",
          tvb_format_text(ctx->pinfo->pool, ctx->tvb, ctx->offset + 2, slen));
    } else {
      proto_tree_add_item(ctx->payload_tree, hf_duml_wifi_psk, ctx->tvb,
                          ctx->offset + 2, slen, ENC_ASCII | ENC_NA);
      g_snprintf(
          ctx->content, ctx->content_size, "psk:%s",
          tvb_format_text(ctx->pinfo->pool, ctx->tvb, ctx->offset + 2, slen));
    }
  }
}

static void dissect_duml_battery(duml_payload_t *ctx) {
  guint8 cap = 0;
  if (ctx->length >= 21) {
    cap = tvb_get_uint8(ctx->tvb, ctx->offset + 20);
    proto_tree_add_uint(ctx->payload_tree, hf_duml_battery_cap, ctx->tvb,
                        ctx->offset + 20, 1, cap);
  } else if (ctx->length >= 13) {
    cap = tvb_get_uint8(ctx->tvb, ctx->offset + 12);
    proto_tree_add_uint(ctx->payload_tree, hf_duml_battery_cap, ctx->tvb,
                        ctx->offset + 12, 1, cap);
  } else {
    return;
  }
  g_snprintf(ctx->content, ctx->content_size, "cap:%u%%", cap);
}

static void dissect_duml_stream_config(duml_payload_t *ctx) {
  if (ctx->length < 1)
    return;

  if (ctx->is_request) {
    /* Based on djictl Example:
       00 32 00 0a 7017 0200 03 000000 2700 rtmp...
       0: 0x00
       1: type
       2: 0x00
       3: resolution
       4-5: bitrate (LE)
       6-7: 0x0200
       8: fps
       9-11: 0x000000
       12-13: url_len (LE)
       14+: url
    */
    if (ctx->length >= 4) {
      proto_tree_add_item(ctx->payload_tree, hf_duml_conf_res, ctx->tvb,
                          ctx->offset + 3, 1, ENC_NA);
    }
    if (ctx->length >= 6) {
      proto_tree_add_item(ctx->payload_tree, hf_duml_conf_bitrate, ctx->tvb,
                          ctx->offset + 4, 2, ENC_LITTLE_ENDIAN);
    }
    if (ctx->length >= 9) {
      proto_tree_add_item(ctx->payload_tree, hf_duml_conf_fps, ctx->tvb,
                          ctx->offset + 8, 1, ENC_NA);
    }
    if (ctx->length >= 14) {
      guint16 url_len = tvb_get_letohs(ctx->tvb, ctx->offset + 12);
      proto_tree_add_item(ctx->payload_tree, hf_duml_conf_url_len, ctx->tvb,
                          ctx->offset + 12, 2, ENC_LITTLE_ENDIAN);
      if (ctx->length >= (guint)(14 + url_len)) {
        proto_tree_add_item(ctx->payload_tree, hf_duml_rtmp_url, ctx->tvb,
                            ctx->offset + 14, url_len, ENC_ASCII | ENC_NA);
        g_snprintf(ctx->content, ctx->content_size, "url:%s",
                   tvb_format_text(ctx->pinfo->pool, ctx->tvb, ctx->offset + 14,
                                   url_len));
      }
    }
  } else {
    guint8 status = tvb_get_uint8(ctx->tvb, ctx->offset);
    g_snprintf(ctx->content, ctx->content_size, "status:%u", status);
  }
}

static void dissect_duml_rc_simulator(duml_payload_t *ctx) {
  if (ctx->length < 8)
    return;
  proto_tree_add_item(ctx->payload_tree, hf_duml_rc_rh, ctx->tvb, ctx->offset,
                      2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(ctx->payload_tree, hf_duml_rc_rv, ctx->tvb,
                      ctx->offset + 2, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(ctx->payload_tree, hf_duml_rc_lv, ctx->tvb,
                      ctx->offset + 4, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(ctx->payload_tree, hf_duml_rc_lh, ctx->tvb,
                      ctx->offset + 6, 2, ENC_LITTLE_ENDIAN);

  guint32 buttons = 0;
  if (ctx->length >= 12) {
    proto_tree_add_item(ctx->payload_tree, hf_duml_rc_buttons, ctx->tvb,
                        ctx->offset + 8, 4, ENC_LITTLE_ENDIAN);
    buttons = tvb_get_letohl(ctx->tvb, ctx->offset + 8);
  }

  g_snprintf(ctx->content, ctx->content_size, "RH:%u RV:%u LV:%u LH:%u BTN:0x%X",
             tvb_get_letohs(ctx->tvb, ctx->offset),
             tvb_get_letohs(ctx->tvb, ctx->offset + 2),
             tvb_get_letohs(ctx->tvb, ctx->offset + 4),
             tvb_get_letohs(ctx->tvb, ctx->offset + 6), buttons);
}

static void dissect_duml_param_recursive(proto_tree *tree, tvbuff_t *tvb,
                                         guint offset, guint length) {
  guint rem = length;
  guint off = offset;

  while (rem >= 2) {
    guint z_start = off;
    while (rem > 0 && tvb_get_uint8(tvb, off) == 0) {
      off++;
      rem--;
    }
    guint z_len = off - z_start;

    if (rem < 1) {
      if (z_len > 0) {
        proto_tree_add_item(tree, hf_duml_param_val, tvb, z_start, z_len,
                            ENC_NA);
      }
      return;
    }

    guint8 sub_len = tvb_get_uint8(tvb, off);
    if (sub_len == 0 || (guint)(sub_len + 1) > rem) {
      proto_tree_add_item(tree, hf_duml_param_val, tvb, z_start, z_len + rem,
                          ENC_NA);
      return;
    }

    if (z_len > 0) {
      proto_tree_add_item(tree, hf_duml_param_val, tvb, z_start, z_len, ENC_NA);
    }

    proto_item *ti = proto_tree_add_item(tree, hf_duml_param_val, tvb, off,
                                         1 + sub_len, ENC_NA);
    proto_item_set_text(ti, "Sub-block: Len %u", sub_len);
    proto_tree *sub_tree = proto_item_add_subtree(ti, ett_dji_payload);

    proto_tree_add_item(sub_tree, hf_duml_param_len, tvb, off, 1, ENC_NA);

    if (sub_len >= 1) {
      proto_tree_add_item(sub_tree, hf_duml_param_type, tvb, off + 1, 1, ENC_NA);
      if (sub_len > 1) {
        dissect_duml_param_recursive(sub_tree, tvb, off + 2, sub_len - 1);
      }
    }

    off += (1 + sub_len);
    rem -= (1 + sub_len);
  }

  if (rem > 0) {
    proto_tree_add_item(tree, hf_duml_param_val, tvb, off, rem, ENC_NA);
  }
}

static void dissect_duml_param_push(duml_payload_t *ctx) {
  guint offset = ctx->offset;
  guint remaining = ctx->length;
  int count = 0;

  while (remaining >= 2) {
    /* Skip any leading zeros */
    while (remaining > 0 && tvb_get_uint8(ctx->tvb, offset) == 0) {
      offset++;
      remaining--;
    }

    if (remaining < 2)
      break;

    guint8 first = tvb_get_uint8(ctx->tvb, offset);
    guint8 second = tvb_get_uint8(ctx->tvb, offset + 1);

    if (first == 0x02) {
      /* Metadata Block Tag 0x02 */
      guint8 len = second;
      if (len == 0 || (guint)(len + 2) > remaining) {
        proto_tree_add_item(ctx->payload_tree, hf_duml_payload, ctx->tvb, offset,
                            remaining, ENC_NA);
        break;
      }

      proto_item *ti = proto_tree_add_item(ctx->payload_tree, hf_duml_param_val,
                                           ctx->tvb, offset, 2 + len, ENC_NA);
      proto_item_set_text(ti, "Metadata Block: Tag 0x%02X, Len %u", first, len);
      proto_tree *block_tree = proto_item_add_subtree(ti, ett_dji_payload);
      proto_tree_add_uint_format(block_tree, hf_duml_param_type, ctx->tvb,
                                 offset, 1, first, "Tag/Type?: 0x%02X", first);
      proto_tree_add_uint_format(block_tree, hf_duml_param_len, ctx->tvb,
                                 offset + 1, 1, len, "Length?: %u", len);

      if (len >= 3 && tvb_get_uint8(ctx->tvb, offset + 2) == 0 &&
          tvb_get_uint8(ctx->tvb, offset + 3) == 0) {
        proto_tree_add_item(block_tree, hf_duml_param_unknown0, ctx->tvb,
                            offset + 2, 2, ENC_NA); /* zeros */
        proto_tree_add_item(block_tree, hf_duml_param_id, ctx->tvb, offset + 4,
                            1, ENC_NA);
        if (len > 3) {
          proto_tree_add_item(block_tree, hf_duml_param_unknown1, ctx->tvb,
                              offset + 5, len - 3, ENC_NA);
        }
      } else {
        proto_tree_add_item(block_tree, hf_duml_param_unknown0, ctx->tvb,
                            offset + 2, len, ENC_NA);
      }

      offset += (2 + len);
      remaining -= (2 + len);
    } else {
      /* Try the [total_len(2)] [name_len(2)] pattern */
      if (remaining < 4) {
        proto_tree_add_item(ctx->payload_tree, hf_duml_payload, ctx->tvb, offset,
                            remaining, ENC_NA);
        break;
      }

      guint16 total_len = tvb_get_letohs(ctx->tvb, offset);
      guint16 name_len = tvb_get_letohs(ctx->tvb, offset + 2);

      if (name_len == 0 || (guint)(name_len + 2) > total_len ||
          (guint)(total_len + 2) > remaining) {
        /* Not this pattern, just dump and exit */
        proto_tree_add_item(ctx->payload_tree, hf_duml_payload, ctx->tvb, offset,
                            remaining, ENC_NA);
        break;
      }

      const char *pname =
          tvb_format_text(ctx->pinfo->pool, ctx->tvb, offset + 4, name_len);

      /* Update info column */
      if (count == 0) {
        g_snprintf(ctx->content, ctx->content_size, "param:%s", pname);
      } else if (count < 3) {
        size_t cur_len = strlen(ctx->content);
        g_snprintf(ctx->content + cur_len, ctx->content_size - cur_len, ", %s",
                   pname);
      } else if (count == 3) {
        size_t cur_len = strlen(ctx->content);
        g_snprintf(ctx->content + cur_len, ctx->content_size - cur_len, "...");
      }

      proto_item *ti = proto_tree_add_item(ctx->payload_tree, hf_duml_param_val,
                                           ctx->tvb, offset, 2 + total_len,
                                           ENC_NA);
      proto_item_set_text(ti, "Param: %s", pname);
      proto_tree *block_tree = proto_item_add_subtree(ti, ett_dji_payload);

      proto_tree_add_item(block_tree, hf_duml_param_name, ctx->tvb, offset + 4,
                          name_len, ENC_ASCII | ENC_NA);

      dissect_duml_param_recursive(block_tree, ctx->tvb, offset + 4 + name_len,
                                   total_len - name_len - 2);

      offset += (2 + total_len);
      remaining -= (2 + total_len);
      count++;
    }
  }
}

static const char *duml_cmd_to_str(wmem_allocator_t *pool, guint8 set, guint8 id) {
  const char *set_str = try_val_to_str(set, dji_cmd_sets);
  const char *cmd_name = try_val_to_str(DUML_CMD(set, id), dji_cmd_names);
  if (!set_str)
    set_str = wmem_strdup_printf(pool, "Set 0x%02x", set);
  if (!cmd_name)
    return wmem_strdup_printf(pool, "%s ID 0x%02x", set_str, id);
  return wmem_strdup_printf(pool, "%s (%s)", cmd_name, set_str);
}

static void dissect_duml_param_push(duml_payload_t *ctx);

static void dissect_duml_version(duml_payload_t *ctx) {
  if (ctx->length < 1)
    return;
  proto_tree_add_item(ctx->payload_tree, hf_duml_version, ctx->tvb, ctx->offset,
                      ctx->length, ENC_ASCII | ENC_NA);
  g_snprintf(ctx->content, ctx->content_size, "ver:%s",
             tvb_format_text(ctx->pinfo->pool, ctx->tvb, ctx->offset,
                             ctx->length));
}

static void dissect_duml_broadcast(duml_payload_t *ctx) {
  if (ctx->length < 1)
    return;
  guint8 active = tvb_get_uint8(ctx->tvb, ctx->offset);
  g_snprintf(ctx->content, ctx->content_size, "broadcast:%s",
             active ? "ON" : "OFF");
}

static void dissect_duml_fcc(duml_payload_t *ctx) {
  if (ctx->length < 1)
    return;
  guint8 active = tvb_get_uint8(ctx->tvb, ctx->offset);
  g_snprintf(ctx->content, ctx->content_size, "fcc:%s", active ? "ON" : "OFF");
}

static void dissect_duml_serial(duml_payload_t *ctx) {
  if (ctx->length < 1)
    return;
  proto_tree_add_item(ctx->payload_tree, hf_duml_sn, ctx->tvb, ctx->offset,
                      ctx->length, ENC_ASCII | ENC_NA);
  g_snprintf(ctx->content, ctx->content_size, "sn:%s",
             tvb_format_text(ctx->pinfo->pool, ctx->tvb, ctx->offset,
                             ctx->length));
}

static void dissect_dji_duml_payload_dispatch(duml_payload_t *ctx, guint8 set,
                                              guint8 id) {
  switch (DUML_CMD(set, id)) {
  case CMD_GET_VERSION:
  case CMD_GET_PRODUCT_ID:
  case 0x0001: /* CMD_GET_VERSION_V1 */
    dissect_duml_version(ctx);
    break;
  case CMD_HEARTBEAT_V1:
    g_snprintf(ctx->content, ctx->content_size, "heartbeat? payload:%s",
               tvb_bytes_to_str(ctx->pinfo->pool, ctx->tvb, ctx->offset,
                               ctx->length));
    break;
  case CMD_GET_SERIAL_NUM:
    dissect_duml_serial(ctx);
    break;
  case CMD_FCC_SUPPORT:
    dissect_duml_fcc(ctx);
    break;
  case CMD_OSMO_BROADCAST:
    dissect_duml_broadcast(ctx);
    break;
  case CMD_SET_PAIRING_PIN:
    dissect_duml_pairing(ctx);
    break;
  case CMD_CONNECT_WIFI:
  case CMD_CAMERA_AP_INFO:
  case CMD_CAMERA_AP_PSK:
  case CMD_START_SCANNING_WIFI:
  case CMD_WIFI_SCAN_REPORT:
    dissect_duml_wifi(ctx, id);
    break;
  case CMD_BATTERY_STATUS:
    dissect_duml_battery(ctx);
    break;
  case CMD_RC_SIM_DATA:
  case CMD_FLIGHT_STICK_DATA:
    dissect_duml_rc_simulator(ctx);
    break;
  case CMD_CONFIGURE_STREAMING:
  case CMD_CONF_STREAMING:
    dissect_duml_stream_config(ctx);
    break;
  case CMD_START_STOP_STREAMING:
    g_snprintf(
        ctx->content, ctx->content_size, "start/stop payload:%s",
        tvb_bytes_to_str(ctx->pinfo->pool, ctx->tvb, ctx->offset, ctx->length));
    break;
  case CMD_PREP_STREAMING:
    g_snprintf(
        ctx->content, ctx->content_size, "prepare payload:%s",
        tvb_bytes_to_str(ctx->pinfo->pool, ctx->tvb, ctx->offset, ctx->length));
    break;
  case CMD_PARAM_PUSH:
    dissect_duml_param_push(ctx);
    break;
  default:
    if (!ctx->is_request && ctx->length == 1) {
      guint8 status = tvb_get_uint8(ctx->tvb, ctx->offset);
      g_snprintf(ctx->content, ctx->content_size, "status:%u", status);
    }
    break;
  }
}

static bool parse_duml_header(tvbuff_t *tvb, guint offset, int remaining,
                              duml_header_t *h) {
  if (remaining < 11)
    return false;
  if (tvb_get_uint8(tvb, offset) != DUML_MAGIC)
    return false;

  h->version = (tvb_get_uint8(tvb, offset + 2) & 0xFC) >> 2;
  h->length = tvb_get_uint8(tvb, offset + 1) |
              ((tvb_get_uint8(tvb, offset + 2) & 0x03) << 8);
  h->flags = tvb_get_uint8(tvb, offset + 8);
  h->set = tvb_get_uint8(tvb, offset + 9);
  h->id = tvb_get_uint8(tvb, offset + 10);
  h->header_size = 11;
  h->src = tvb_get_uint8(tvb, offset + 4);
  h->dst = tvb_get_uint8(tvb, offset + 5);
  h->seq = tvb_get_ntohs(tvb, offset + 6);

  return true;
}

/* DUML header CRC8: reflected polynomial 0x31, reflected initial value 0xEE. */
static bool duml_header_crc_valid(tvbuff_t *tvb, guint offset) {
  guint8 crc = 0x77;
  for (guint i = 0; i < 3; i++) {
    crc ^= tvb_get_uint8(tvb, offset + i);
    for (guint bit = 0; bit < 8; bit++)
      crc = (crc & 1) ? (crc >> 1) ^ 0x8c : crc >> 1;
  }
  return crc == tvb_get_uint8(tvb, offset + 3);
}

static void dissect_dji_duml_internal(tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *tree, guint offset) {
  duml_header_t h;
  int remaining = tvb_captured_length_remaining(tvb, offset);

  if (!parse_duml_header(tvb, offset, remaining, &h) || h.length < 13) {
    return;
  }

  const char *cmd_name = duml_cmd_to_str(pinfo->pool, h.set, h.id);
  char content_buf[128] = "";

  proto_item *ti = proto_tree_add_protocol_format(
      tree, proto_dji_duml, tvb, offset, MIN(h.length, (guint)remaining),
      "DJI DUML: %s (Set=0x%02X ID=0x%02X Len=%u Seq=%u Src=%u Dst=%u)",
      cmd_name, h.set, h.id, h.length, h.seq, h.src, h.dst);
  proto_tree *duml_tree = proto_item_add_subtree(ti, ett_dji_duml);

  proto_tree_add_item(duml_tree, hf_duml_magic, tvb, offset, 1, ENC_NA);
  proto_tree_add_item(duml_tree, hf_duml_len, tvb, offset + 1, 2,
                      ENC_LITTLE_ENDIAN);
  proto_tree_add_item(duml_tree, hf_duml_ver, tvb, offset + 2, 1, ENC_NA);
  proto_tree_add_item(duml_tree, hf_duml_crc8, tvb, offset + 3, 1, ENC_NA);
  proto_tree_add_item(duml_tree, hf_duml_src, tvb, offset + 4, 1, ENC_NA);
  proto_tree_add_item(duml_tree, hf_duml_dst, tvb, offset + 5, 1, ENC_NA);
  proto_tree_add_item(duml_tree, hf_duml_seq, tvb, offset + 6, 2,
                      ENC_BIG_ENDIAN);
  proto_tree_add_item(duml_tree, hf_duml_flags, tvb, offset + 8, 1, ENC_NA);
  proto_tree_add_item(duml_tree, hf_duml_set, tvb, offset + 9, 1, ENC_NA);
  proto_tree_add_item(duml_tree, hf_duml_id, tvb, offset + 10, 1, ENC_NA);

  if (h.length > (guint)remaining) {
    if (remaining > h.header_size)
      proto_tree_add_item(duml_tree, hf_duml_payload, tvb, offset + h.header_size,
                          remaining - h.header_size, ENC_NA);
    expert_add_info_format(pinfo, ti, &ei_duml_incomplete,
                           "Incomplete DUML message: declared %u bytes, available %d bytes",
                           h.length, remaining);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DUML");
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s: incomplete DUML message (%d/%u bytes)",
                 cmd_name, remaining, h.length);
    return;
  }

  if (h.length < h.header_size)
    return;

  guint pl_off = offset + h.header_size;
  int pl_len = (int)h.length - (int)h.header_size - 2;

  if (pl_len < 0)
    pl_len = 0;

  if (pl_off + pl_len > (guint)remaining + offset) {
    pl_len = (int)(remaining + offset - pl_off);
  }

  if (pl_len > 0) {
    proto_item *pi_payload = proto_tree_add_item(duml_tree, hf_duml_payload,
                                                 tvb, pl_off, pl_len, ENC_NA);
    proto_tree *payload_tree =
        proto_item_add_subtree(pi_payload, ett_dji_payload);

    duml_payload_t payload_ctx = {.tvb = tvb,
                                  .pinfo = pinfo,
                                  .payload_tree = payload_tree,
                                  .offset = pl_off,
                                  .length = (guint)pl_len,
                                  .flags = h.flags,
                                  .is_request = (h.flags & 0x80) == 0,
                                  .content = content_buf,
                                  .content_size = sizeof(content_buf)};
    dissect_dji_duml_payload_dispatch(&payload_ctx, h.set, h.id);
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DUML");
  const char *src_str = try_val_to_str(h.src, dji_component_shorthands);
  const char *dst_str = try_val_to_str(h.dst, dji_component_shorthands);
  if (!src_str)
    src_str = wmem_strdup_printf(pinfo->pool, "0x%02x", h.src);
  if (!dst_str)
    dst_str = wmem_strdup_printf(pinfo->pool, "0x%02x", h.dst);

  if (content_buf[0]) {
    proto_item_append_text(ti, ": %s", content_buf);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%s->%s) seq:%u: %s", cmd_name,
                 src_str, dst_str, h.seq, content_buf);
  } else {
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%s->%s) seq:%u", cmd_name, src_str,
                 dst_str, h.seq);
  }

  int crc_off = offset + h.length - 2;
  if (crc_off >= (int)offset && crc_off + 2 <= remaining + (int)offset) {
    proto_tree_add_item(duml_tree, hf_duml_crc16, tvb, crc_off, 2,
                        ENC_LITTLE_ENDIAN);
  }
}

static void dissect_dji_ble_packet_ee(tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *ble_tree, int length) {
  if (length < 4)
    return;
  proto_tree_add_item(ble_tree, hf_dji_ble_magic, tvb, 0, 1, ENC_NA);
  proto_tree_add_item(ble_tree, hf_dji_ble_len, tvb, 1, 1, ENC_NA);
  proto_tree_add_item(ble_tree, hf_dji_ble_ver, tvb, 2, 1, ENC_NA);
  proto_tree_add_item(ble_tree, hf_dji_ble_type, tvb, 3, 1, ENC_NA);

  guint8 magic = tvb_get_uint8(tvb, 0);
  guint8 type = tvb_get_uint8(tvb, 3);

  if (magic == 0x02 && length >= 13 && tvb_get_uint8(tvb, 12) == DUML_MAGIC) {
    dissect_dji_duml_internal(tvb, pinfo, ble_tree, 12);
  } else if ((magic == BLE_MAGIC || type == 1 || type == 3) && length >= 5 &&
             tvb_get_uint8(tvb, 4) == DUML_MAGIC) {
    dissect_dji_duml_internal(tvb, pinfo, ble_tree, 4);
  }
}

static int dissect_dji_ble(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           void *data _U_) {
  guint8 magic;
  proto_item *ti;
  proto_tree *ble_tree;
  int length = tvb_captured_length(tvb);

  if (length < 1)
    return 0;
  magic = tvb_get_uint8(tvb, 0);

  guint offset;
  if (magic == DUML_MAGIC)
    offset = 0;
  else if (magic == 0x02 && length >= 13 && tvb_get_uint8(tvb, 12) == DUML_MAGIC)
    offset = 12;
  else if ((magic == BLE_MAGIC ||
            (magic == 0x02 && length >= 4 &&
             (tvb_get_uint8(tvb, 3) == 1 || tvb_get_uint8(tvb, 3) == 3))) &&
           length >= 5 && tvb_get_uint8(tvb, 4) == DUML_MAGIC)
    offset = 4;
  else
    return 0;

  duml_header_t header;
  int remaining = length - offset;
  if (!parse_duml_header(tvb, offset, remaining, &header) || header.length < 13)
    return 0;
  if (header.length > (guint)remaining &&
      (header.version != 1 || !duml_header_crc_valid(tvb, offset)))
    return 0;

  ti = proto_tree_add_item(tree, proto_dji_duml, tvb, 0, -1, ENC_NA);
  ble_tree = proto_item_add_subtree(ti, ett_dji_ble);

  if (magic == DUML_MAGIC) {
    proto_tree_add_item(ble_tree, hf_dji_ble_magic, tvb, 0, 1, ENC_NA);
    dissect_dji_duml_internal(tvb, pinfo, ble_tree, 0);
    return length;
  }

  if (magic == BLE_MAGIC || magic == 0x02) {
    dissect_dji_ble_packet_ee(tvb, pinfo, ble_tree, length);
    return length;
  }

  return 0;
}

void proto_register_dji_duml(void) {
  static hf_register_info hf[] = {
      {&hf_dji_ble_magic,
       {"BLE Magic", "dji_ble.magic", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_dji_ble_len,
       {"BLE Length", "dji_ble.len", FT_UINT8, BASE_DEC, NULL, 0x0, NULL,
        HFILL}},
      {&hf_dji_ble_ver,
       {"BLE Version", "dji_ble.ver", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_dji_ble_type,
       {"BLE Type", "dji_ble.type", FT_UINT8, BASE_HEX, VALS(dji_ble_types),
        0x0, NULL, HFILL}},

      {&hf_duml_magic,
       {"Magic", "dji_duml.magic", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_duml_len,
       {"Total Length", "dji_duml.len", FT_UINT16, BASE_DEC, NULL, 0x03FF, NULL,
        HFILL}},
      {&hf_duml_ver,
       {"Version", "dji_duml.ver", FT_UINT8, BASE_HEX, NULL, 0xFC, NULL,
        HFILL}},
      {&hf_duml_crc8,
       {"Header CRC8", "dji_duml.crc8", FT_UINT8, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_duml_src,
       {"Source", "dji_duml.src", FT_UINT8, BASE_HEX, VALS(dji_component_ids),
        0x0, NULL, HFILL}},
      {&hf_duml_dst,
       {"Destination", "dji_duml.dst", FT_UINT8, BASE_HEX,
        VALS(dji_component_ids), 0x0, NULL, HFILL}},
      {&hf_duml_seq,
       {"Sequence", "dji_duml.seq", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
        HFILL}},
      {&hf_duml_flags,
       {"Flags", "dji_duml.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_duml_set,
       {"Cmd Set", "dji_duml.set", FT_UINT8, BASE_HEX, VALS(dji_cmd_sets), 0x0,
        NULL, HFILL}},
      {&hf_duml_id,
       {"Cmd ID", "dji_duml.id", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},
      {&hf_duml_payload,
       {"Payload", "dji_duml.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL,
        HFILL}},
      {&hf_duml_crc16,
       {"CRC16", "dji_duml.crc16", FT_UINT16, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},

      {&hf_duml_battery_cap,
       {"Capacity", "dji_duml.battery.cap", FT_UINT8, BASE_DEC, NULL, 0x0, NULL,
        HFILL}},
      {&hf_duml_pairing_pin,
       {"Pairing PIN", "dji_duml.pairing.pin", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
      {&hf_duml_pairing_device_id,
       {"Device ID", "dji_duml.pairing.device_id", FT_STRING, BASE_NONE, NULL,
        0x0, NULL, HFILL}},
      {&hf_duml_rc_rh,
       {"Right Stick Horizontal", "dji_duml.rc.rh", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL}},
      {&hf_duml_rc_rv,
       {"Right Stick Vertical", "dji_duml.rc.rv", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL}},
      {&hf_duml_rc_lh,
       {"Left Stick Horizontal", "dji_duml.rc.lh", FT_UINT16, BASE_DEC, NULL,
        0x0, NULL, HFILL}},
      {&hf_duml_rc_lv,
       {"Left Stick Vertical", "dji_duml.rc.lv", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
      {&hf_duml_rc_buttons,
       {"Buttons", "dji_duml.rc.buttons", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
        HFILL}},
      {&hf_duml_rtmp_url,
       {"RTMP URL", "dji_duml.url", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
        HFILL}},
      {&hf_duml_param_name,
       {"Parameter Name", "dji_duml.param.name", FT_STRING, BASE_NONE, NULL,
        0x0, NULL, HFILL}},
      {&hf_duml_param_val,
       {"UnknownField", "dji_duml.param.val", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
      {&hf_duml_param_type,
       {"Type", "dji_duml.param.type", FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL}},
      {&hf_duml_param_len,
       {"Length", "dji_duml.param.len", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
      {&hf_duml_param_id,
       {"Parameter ID", "dji_duml.param.id", FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL}},
      {&hf_duml_param_unknown0,
       {"UnknownField0", "dji_duml.param.unknown0", FT_BYTES, BASE_NONE, NULL,
        0x0, NULL, HFILL}},
      {&hf_duml_param_unknown1,
       {"UnknownField1", "dji_duml.param.unknown1", FT_BYTES, BASE_NONE, NULL,
        0x0, NULL, HFILL}},

      {&hf_duml_conf_res,
       {"Resolution (V1)", "dji_duml.conf.res", FT_UINT8, BASE_HEX,
        VALS(dji_resolutions), 0x0, NULL, HFILL}},
      {&hf_duml_conf_fps,
       {"FPS (V1)", "dji_duml.conf.fps", FT_UINT8, BASE_HEX, VALS(dji_fps_vals),
        0x0, NULL, HFILL}},
      {&hf_duml_conf_bitrate,
       {"Bitrate", "dji_duml.conf.bitrate", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},
      {&hf_duml_conf_url_len,
       {"URL Length", "dji_duml.conf.url_len", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL}},

      {&hf_duml_wifi_ssid,
       {"WiFi SSID", "dji_duml.wifi.ssid", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
      {&hf_duml_wifi_psk,
       {"WiFi PSK", "dji_duml.wifi.psk", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
        HFILL}},
      {&hf_duml_version,
       {"Version String", "dji_duml.version", FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL}},
      {&hf_duml_sn,
       {"Serial Number", "dji_duml.sn", FT_STRING, BASE_NONE, NULL, 0x0, NULL,
        HFILL}},
  };

  static int *ett[] = {&ett_dji_duml, &ett_dji_ble,
                       &ett_dji_payload};
  static ei_register_info ei[] = {
      {&ei_duml_incomplete,
       {"dji_duml.incomplete", PI_REASSEMBLE, PI_WARN,
        "Incomplete DUML message", EXPFILL}},
  };

  proto_dji_duml =
      proto_register_protocol("DJI DUML over BLE", "DUML", "dji_duml");
  proto_register_field_array(proto_dji_duml, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_module_t *expert = expert_register_protocol(proto_dji_duml);
  expert_register_field_array(expert, ei, array_length(ei));
}

void proto_reg_handoff_dji_duml(void) {
  dissector_handle_t dji_handle =
      register_dissector("dji_ble", dissect_dji_ble, proto_dji_duml);

  dissector_add_uint("btatt.handle", 0x002D, dji_handle);
  dissector_add_uint("btatt.handle", 0x0030, dji_handle);
  dissector_add_uint("udp.port", 9004, dji_handle);
}

WS_DLL_PUBLIC const gchar plugin_version[];
WS_DLL_PUBLIC const gchar plugin_release[];
WS_DLL_PUBLIC const int plugin_want_major;
WS_DLL_PUBLIC const int plugin_want_minor;
WS_DLL_PUBLIC uint32_t plugin_describe(void);

const gchar plugin_version[] = "1.0.1";
const gchar plugin_release[] = "1.0.1";
const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC uint32_t plugin_describe(void) {
  return WS_PLUGIN_DESC_DISSECTOR;
}

WS_DLL_PUBLIC void plugin_register(void) {
  static proto_plugin plug;

  plug.register_protoinfo = proto_register_dji_duml;
  plug.register_handoff = proto_reg_handoff_dji_duml;
  proto_register_plugin(&plug);
}
