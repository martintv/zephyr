/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 * Copyright (c) 2021 Nordic Semiconductor
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>

#include <zephyr/types.h>
#include <sys/printk.h>
#include <sys/util.h>
#include <sys/byteorder.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/gatt.h>
#include <bluetooth/uuid.h>
#include <bluetooth/conn.h>

#include "bs_types.h"
#include "bs_tracing.h"
#include "bstests.h"

extern enum bst_result_t bst_result;

#define FAIL(...)					\
	do {						\
		bst_result = Failed;			\
		bs_trace_error_time_line(__VA_ARGS__);	\
	} while (0)

#define PASS(...)					\
	do {						\
		bst_result = Passed;			\
		bs_trace_info_time(1, __VA_ARGS__);	\
	} while (0)

static struct bt_conn *default_conn;

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
};

static struct bt_gatt_discover_params discover_params, discover_params_2;

static bool volatile  is_connected;
static bool volatile  all_attributes_found = false;
static bool volatile  read_char_in_progress = false;

static uint16_t service_handle = 0;

static struct bt_uuid_128 uuid_primary = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xf5173300, 0x32a3, 0x4b22, 0xa47b, 0x7644d578b069));

static struct bt_uuid_128 uuid_char_1 = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xf5173301, 0x32a3, 0x4b22, 0xa47b, 0x7644d578b069));

static struct bt_uuid_128 uuid_char_2 = BT_UUID_INIT_128(
	BT_UUID_128_ENCODE(0xf5173302, 0x32a3, 0x4b22, 0xa47b, 0x7644d578b069));


#define LENGTH_CHAR_1	1500
#define LENGTH_CHAR_2	10

static uint8_t char_1_data[LENGTH_CHAR_1];
static uint8_t char_2_data[LENGTH_CHAR_2];

static uint16_t char_1_attr_handle = 0;
static uint16_t char_2_attr_handle = 0;
static struct bt_gatt_exchange_params exchange_params;


static ssize_t read_char_1(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			 void *buf, uint16_t len, uint16_t offset)
{
	const uint8_t *value = char_1_data;
	printk("read_char_1. Len %d, offset %d\n", len, offset);

	return bt_gatt_attr_read(conn, attr, buf, len, offset, value,
				 LENGTH_CHAR_1);
}

static ssize_t write_char_1(struct bt_conn *conn,
			  const struct bt_gatt_attr *attr, const void *buf,
			  uint16_t len, uint16_t offset, uint8_t flags)
{
	uint8_t *value = char_1_data;

	printk("write_char_2. Len %d, offset %d\n", len, offset);

	if (offset > LENGTH_CHAR_1) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}
	if (offset + len > LENGTH_CHAR_1)
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);


	memcpy(value + offset, buf, len);

	return len;
}

static ssize_t read_char_2(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			 void *buf, uint16_t len, uint16_t offset)
{
	printk("read_char_2. Len %d, offset %d\n", len, offset);
	const uint8_t *value = char_2_data;

	return bt_gatt_attr_read(conn, attr, buf, len, offset, value,
				 LENGTH_CHAR_2);
}

static ssize_t write_char_2(struct bt_conn *conn,
			  const struct bt_gatt_attr *attr, const void *buf,
			  uint16_t len, uint16_t offset, uint8_t flags)
{
	uint8_t *value = char_2_data;

	printk("write_char_2. Len %d, offset %d\n", len, offset);

	if (offset > LENGTH_CHAR_2) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}
	if (offset + len > LENGTH_CHAR_2)
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_ATTRIBUTE_LEN);


	memcpy(value + offset, buf, len);

	return len;
}

struct bt_gatt_attr gatt_attributes[] = {
	BT_GATT_PRIMARY_SERVICE(&uuid_primary),
	BT_GATT_CHARACTERISTIC(&uuid_char_1.uuid,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
			       read_char_1, write_char_1, char_1_data),
	BT_GATT_CHARACTERISTIC(&uuid_char_2.uuid,
			       BT_GATT_CHRC_READ | BT_GATT_CHRC_WRITE,
			       BT_GATT_PERM_READ | BT_GATT_PERM_WRITE,
			       read_char_2, write_char_2, char_2_data)
};

static struct bt_gatt_service gatt_service = BT_GATT_SERVICE(gatt_attributes);

static void exchange_func(struct bt_conn *conn, uint8_t att_err,
			  struct bt_gatt_exchange_params *params)
{
	struct bt_conn_info info = {0};
	int err;

	printk("MTU exchange %s\n", att_err == 0 ? "successful" : "failed");
}


static void connected(struct bt_conn *conn, uint8_t conn_err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (conn_err) {
		FAIL("Failed to connect to %s (%u)\n", addr, conn_err);
		bt_conn_unref(default_conn);
		default_conn = NULL;
		return;
	}

	default_conn = bt_conn_ref(conn);
	printk("Connected: %s\n", addr);
	is_connected = true;
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	printk("Disconnected: %s (reason 0x%02x)\n", addr, reason);

	if (default_conn != conn) {
		FAIL("Conn mismatch disconnect %s %s)\n", default_conn, conn);
		return;
	}

	bt_conn_unref(default_conn);
	default_conn = NULL;
	is_connected = false;
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
};


static void test_peripheral_main(void)
{
	int err;

	printk("\n*EATT Peripheral started*\n");

	err = bt_enable(NULL);
	if (err) {
		FAIL("Can't enable Bluetooth (err %d)\n", err);
		return;
	}
	printk("Peripheral Bluetooth initialized.\n");

	for (uint16_t i = 0; i < LENGTH_CHAR_1; i++) {
		char_1_data[i] = (uint8_t) i;
	}

	for (uint16_t i = 0; i < LENGTH_CHAR_2; i++) {
		char_2_data[i] = (uint8_t) i + 50;
	}

	bt_gatt_service_register(&gatt_service);


	uint16_t handle_char_1 = bt_gatt_attr_get_handle(bt_gatt_find_by_uuid(NULL, 0, &uuid_char_1.uuid));
	uint16_t handle_char_2 = bt_gatt_attr_get_handle(bt_gatt_find_by_uuid(NULL, 0, &uuid_char_2.uuid));

	printk("Handle char 1: %d, Handle char 2: %d\n", handle_char_1, handle_char_2);

	printk("Connectable advertising...\n");
	err = bt_le_adv_start(BT_LE_ADV_CONN_NAME, ad, ARRAY_SIZE(ad), NULL, 0);
	if (err) {
		FAIL("Advertising failed to start (err %d)\n", err);
		return;
	}
	printk("Advertising started.\n");

	printk("Peripheral waiting for connection...\n");
	while (!is_connected) {
		k_sleep(K_MSEC(100));
	}
	printk("Peripheral Connected.\n");

	/* Wait a bit to ensure that all LLCP have time to finish */
	k_sleep(K_MSEC(1000));

	/* Wait for a while to disconnect */
	k_sleep(K_MSEC(100000));

	/* Disconnect */
	printk("Peripheral Disconnecting....\n");
	err = bt_conn_disconnect(default_conn,
				 BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	printk("Peripheral tried to disconnect \n");
	if (err) {
		FAIL("Disconnection failed (err %d)\n", err);
		return ;
	}

	while (is_connected) {
		printk("Peripheral still connected.\n");
		k_sleep(K_MSEC(100));
	}
	printk("Peripheral Disconnected.\n");

	PASS("EATT Peripheral tests Passed\n");
	bs_trace_silent_exit(0);

	return;
}

static uint8_t discover_char_2_func(struct bt_conn *conn,
		const struct bt_gatt_attr *attr,
		struct bt_gatt_discover_params *params)
{
	int err;

	if (!attr) {
		printk("Discover complete\n");
		memset(params, 0, sizeof(*params));
		return BT_GATT_ITER_STOP;
	}

	printk("[ATTRIBUTE] handle %u\n", attr->handle);

	printk("Discover Char 2 found\n");
	// TODO Figure out why + 1 is needed to the handle
	char_2_attr_handle = attr->handle + 1;

	all_attributes_found = true;
	return BT_GATT_ITER_STOP;
}

static uint8_t discover_char_1_func(struct bt_conn *conn,
		const struct bt_gatt_attr *attr,
		struct bt_gatt_discover_params *params)
{
	int err;

	if (!attr) {
		printk("Discover complete\n");
		memset(params, 0, sizeof(*params));
		return BT_GATT_ITER_STOP;
	}

	printk("[ATTRIBUTE] handle %u\n", attr->handle);

	printk("Discover Char 1 found\n");
	// TODO Figure out why + 1 is needed to the handle
	char_1_attr_handle = attr->handle + 1;

	discover_params_2.uuid = &uuid_char_2.uuid;
	discover_params_2.start_handle = service_handle + 1;
	discover_params_2.type = BT_GATT_DISCOVER_CHARACTERISTIC;
	discover_params_2.end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
	discover_params_2.func = discover_char_2_func;

	err = bt_gatt_discover(conn, &discover_params_2);
	return BT_GATT_ITER_STOP;
}

static uint8_t discover_primary_handler_func(struct bt_conn *conn,
		const struct bt_gatt_attr *attr,
		struct bt_gatt_discover_params *params)
{
	int err;

	if (!attr) {
		printk("Discover complete\n");
		memset(params, 0, sizeof(*params));
		return BT_GATT_ITER_STOP;
	}

	service_handle = attr->handle;

	printk("[ATTRIBUTE] handle %u\n", attr->handle);

	printk("Discover Primary found\n");
	discover_params_2.uuid = &uuid_char_1.uuid;
	discover_params_2.start_handle = attr->handle + 1;
	discover_params_2.type = BT_GATT_DISCOVER_CHARACTERISTIC;
	discover_params_2.end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
	discover_params_2.func = discover_char_1_func;

	err = bt_gatt_discover(conn, &discover_params_2);
	if (err) {
		FAIL("Discover failed (err %d)\n", err);
	}

	return BT_GATT_ITER_STOP;

}
static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
		struct net_buf_simple *ad)
{
	struct bt_le_conn_param *param;
	int err;

	err = bt_le_scan_stop();
	if (err) {
		FAIL("Stop LE scan failed (err %d)\n", err);
		return;
	}

	param = BT_LE_CONN_PARAM_DEFAULT;
	err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN,
				param, &default_conn);

	if (err) {
		FAIL("Create conn failed (err %d)\n", err);
		return;
	}
	printk("Device connected\n");
}

volatile uint32_t m_time_char1_was_read;
volatile uint32_t m_time_char2_was_read;
uint8_t gatt_read_1_cb(struct bt_conn *conn, uint8_t err,
		     struct bt_gatt_read_params *params,
		     const void *data, uint16_t length)
{
	static uint16_t gatt_read_cb_counter = 0;
	printk("gatt_read_1_cb: read data: %d, length: %d, err: %d\n", gatt_read_cb_counter++, length, err);
	const uint8_t *formatted_data = data;

	/* read complete */
	if (!data) {
		printk("gatt_read_cb: no data received\n");
		read_char_in_progress = false;
		return BT_GATT_ITER_STOP;
	} else {
		printk("Data1: ");
		for (uint16_t i = 0; i < length; i++) {
			printk("%d, ", *formatted_data);
			formatted_data++;
		}
		printk("\n");
		m_time_char1_was_read = k_cycle_get_32();
	}


	return BT_GATT_ITER_CONTINUE;
}

uint8_t gatt_read_2_cb(struct bt_conn *conn, uint8_t err,
		     struct bt_gatt_read_params *params,
		     const void *data, uint16_t length)
{
	static uint16_t gatt_read_cb_counter = 0;
	printk("gatt_read_2_cb: read data: %d, length: %d, err: %d\n", gatt_read_cb_counter++, length, err);
	const uint8_t *formatted_data = data;

	/* read complete */
	if (!data) {
		printk("gatt_read_cb: no data received\n");
		read_char_in_progress = false;
		return BT_GATT_ITER_STOP;
	} else {
		m_time_char2_was_read = k_cycle_get_32();
		printk("Data2: ");
		for (uint16_t i = 0; i < length; i++) {
			printk("%d, ", *formatted_data);
			formatted_data++;
		}
		printk("\n");
	}


	return BT_GATT_ITER_CONTINUE;
}
static void test_central_main(void)
{
	struct bt_le_scan_param scan_param = {
		.type       = BT_LE_SCAN_TYPE_ACTIVE,
		.options    = BT_LE_SCAN_OPT_NONE,
		.interval   = BT_GAP_SCAN_FAST_INTERVAL,
		.window     = BT_GAP_SCAN_FAST_WINDOW,
	};

	int err;

	printk("\n*EATT Central started*\n");

	err = bt_enable(NULL);
	if (err) {
		FAIL("Can't enable Bluetooth (err %d)\n", err);
		return;
	}
	printk("Central Bluetooth initialized.\n");


	err = bt_le_scan_start(&scan_param, device_found);
	if (err) {
		FAIL("Scanning failed to start (err %d)\n", err);
		return;
	}

	printk("Scanning successfully started\n");

	printk("Central waiting for connection...\n");
	while (!is_connected) {
		k_sleep(K_MSEC(100));
	}
	printk("Central Connected.\n");
	exchange_params.func = exchange_func;

	err = bt_gatt_exchange_mtu(default_conn, &exchange_params);
	if (err) {
		printk("MTU exchange failed (err %d)\n", err);
	} else {
		printk("MTU exchange pending\n");
	}

	/* Wait a bit to ensure that all LLCP have time to finish */
	k_sleep(K_MSEC(1000));

	discover_params.uuid = &uuid_primary.uuid;
	discover_params.func = discover_primary_handler_func;
	discover_params.start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
	discover_params.end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
	discover_params.type = BT_GATT_DISCOVER_PRIMARY;

	printk("Discover attributes\n");
	err = bt_gatt_discover(default_conn, &discover_params);
	if (err) {
		FAIL("Discover failed(err %d)\n", err);
		return;
	}

	while (!all_attributes_found) {
		k_sleep(K_MSEC(100));
	}

	printk("Attr handle char_1_attr_handle: %d\n", char_1_attr_handle);
	printk("Attr handle char_2_attr_handle: %d\n", char_2_attr_handle);

	/* Read characterstic 1 */
	struct bt_gatt_read_params read_params;

	read_params.handle_count = 1;
	read_params.single.handle = char_1_attr_handle;
	read_params.single.offset = 0x0000;
	read_params.func = gatt_read_1_cb;

	read_char_in_progress = true;
	err = bt_gatt_read(default_conn, &read_params);
	if (err) {
		FAIL("Gatt Read failed (err %d)\n", err);
		return;
	}
	struct bt_gatt_read_params read_params_2;
	read_params_2.handle_count = 1;
	read_params_2.single.handle = char_2_attr_handle;
	read_params_2.single.offset = 0x0000;
	read_params_2.func = gatt_read_2_cb;

	read_char_in_progress = true;
	err = bt_gatt_read(default_conn, &read_params_2);
	if (err) {
		FAIL("Gatt Read failed (err %d)\n", err);
		return;
	}
	k_sleep(K_MSEC(10000)); /*takes 6s ish do to the read on char1*/
	int timediff_read2_read1 = m_time_char2_was_read - m_time_char1_was_read;
	if (m_time_char1_was_read == 0 || m_time_char2_was_read == 0)
	{
		printk("Verdict: Something went wrong chars where not read m_time_char1_was_read=%i m_time_char2_was_read=%i", m_time_char1_was_read, m_time_char2_was_read);
	} 
	else if (timediff_read2_read1 > 0)
	{
		printk("Verdict: Pass. With EATT disabled char2 should finish seccond, diff %i\n", timediff_read2_read1);
	} else
	{
		printk("Verdict: Fail. With EATT disabled char2 should finish seccond, diff %i\n", timediff_read2_read1);
	}

	printk("Connecting EATT channels\n");
	int retval = bt_eatt_connect(default_conn, 2);
	printk("bt_eatt_connect returned %i\n", retval);
	k_sleep(K_MSEC(100)); /*wait a while for eatt enabeling finishing*/
	m_time_char1_was_read = 0;
	m_time_char2_was_read = 0;

	err = bt_gatt_read(default_conn, &read_params);
	if (err) {
		FAIL("Gatt Read failed (err %d)\n", err);
		return;
	}
	err = bt_gatt_read(default_conn, &read_params_2);
	if (err) {
		FAIL("Gatt Read failed (err %d)\n", err);
		return;
	}
	k_sleep(K_MSEC(10000)); /*takes 6s ish do to the read on char1*/
	timediff_read2_read1 = m_time_char2_was_read - m_time_char1_was_read;
	if (m_time_char1_was_read == 0 || m_time_char2_was_read == 0)
	{
		printk("Verdict: Something went wrong chars where not read m_time_char1_was_read=%i m_time_char2_was_read=%i", m_time_char1_was_read, m_time_char2_was_read);
	} 
	else if (timediff_read2_read1 > 0)
	{
		printk("Verdict: Fail. With EATT enabled char1 should finish seccond, diff %i\n", timediff_read2_read1);
	} else
	{
		printk("Verdict: Pass. With EATT enabled char1 should finish seccond, diff %i\n", timediff_read2_read1);
	}

	/* Wait for disconnect */
	while (is_connected) {
		k_sleep(K_MSEC(100));
	}
	printk("Central Disconnected.\n");

	PASS("EATT Central tests Passed\n");

	return;
}

static void test_init(void)
{
	bst_ticker_set_next_tick_absolute(60e6); /* 60 seconds */
	bst_result = In_progress;
}

static void test_tick(bs_time_t HW_device_time)
{
	bst_result = Failed;
	bs_trace_error_line("Test EATT finished.\n");
}

static const struct bst_test_instance test_def[] = {
	{
		.test_id = "peripheral",
		.test_descr = "Peripheral EATT",
		.test_post_init_f = test_init,
		.test_tick_f = test_tick,
		.test_main_f = test_peripheral_main
	},
	{
		.test_id = "central",
		.test_descr = "Central EATT",
		.test_post_init_f = test_init,
		.test_tick_f = test_tick,
		.test_main_f = test_central_main
	},
	BSTEST_END_MARKER
};

struct bst_test_list *test_main_eatt_install(struct bst_test_list *tests)
{
	return bst_add_tests(tests, test_def);
}
