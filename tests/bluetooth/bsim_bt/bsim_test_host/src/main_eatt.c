/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
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
#include <bluetooth/l2cap.h>

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

#define DATA_MTU 128
#define DATA_BUF_SIZE BT_L2CAP_SDU_BUF_SIZE(DATA_MTU)
#define L2CAP_CHANNELS 5
#define SERVERS 1

NET_BUF_POOL_FIXED_DEFINE(data_pool, L2CAP_CHANNELS, DATA_BUF_SIZE, 8, NULL);

static struct channel {
	uint8_t chan_id; /* Internal number that identifies L2CAP channel. */
	struct bt_l2cap_le_chan le;
	bool in_use;
} channels[L2CAP_CHANNELS];

static struct channel *get_free_channel()
{
	uint8_t i;
	struct channel *chan;

	for (i = 0U; i < L2CAP_CHANNELS; i++) {
		if (channels[i].in_use) {
			continue;
		}

		chan = &channels[i];

		(void)memset(chan, 0, sizeof(*chan));
		chan->chan_id = i;

		channels[i].in_use = true;

		return chan;
	}

	return NULL;
}

static struct bt_l2cap_server servers[SERVERS];

static struct net_buf *chan_alloc_buf_cb(struct bt_l2cap_chan *chan)
{
	return net_buf_alloc(&data_pool, K_FOREVER);
}

static int chan_recv_cb(struct bt_l2cap_chan *l2cap_chan, struct net_buf *buf)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	printk("chan_recv_cb: chan_id: %d, data_length: %d\n\n", chan->chan_id, buf->len);

	/* TODO something with the received data. */

	return 0;
}

static void chan_sent_cb(struct bt_l2cap_chan *l2cap_chan)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	printk("chan_sent_cb: chan_id: %d\n", chan->chan_id);
}

static void chan_connected_cb(struct bt_l2cap_chan *l2cap_chan)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	printk("chan_connected_cb: chan_id: %d\n", chan->chan_id);

	printk("chan_connected_cb: tx.mtu %d, tx.mps: %d, rx.mtu: %d, rx.mps %d\n",
			sys_cpu_to_le16(chan->le.tx.mtu),
			sys_cpu_to_le16(chan->le.tx.mps),
			sys_cpu_to_le16(chan->le.rx.mtu),
			sys_cpu_to_le16(chan->le.rx.mps));

	/* TODO something when channel is connected */
}

static void chan_disconnected_cb(struct bt_l2cap_chan *l2cap_chan)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	printk("chan_disconnected_cb: chan_id: %d\n", chan->chan_id);

	chan->in_use = false;

	/* TODO something when channel is disconnected */
}

static void chan_status_cb(struct bt_l2cap_chan *l2cap_chan, atomic_t *status)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	printk("chan_status_cb: chan_id: %d, status: %ld\n", chan->chan_id, *status);
}

static void chan_released_cb(struct bt_l2cap_chan *l2cap_chan)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	printk("chan_released_cb: chan_id: %d\n", chan->chan_id);

}

static void chan_reconfigured_cb(struct bt_l2cap_chan *l2cap_chan)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	printk("chan_reconfigured_cb: chan_id: %d\n", chan->chan_id);

	/* TODO something when channel is reconfigured */
}

static const struct bt_l2cap_chan_ops l2cap_ops = {
	.alloc_buf	= chan_alloc_buf_cb,
	.recv		= chan_recv_cb,
	.sent		= chan_sent_cb,
	.connected	= chan_connected_cb,
	.disconnected	= chan_disconnected_cb,
	.status 	= chan_status_cb,
	.released 	= chan_released_cb,
	.reconfigured	= chan_reconfigured_cb,
};


static void connect_num_channels(uint8_t num_l2cap_channels)
{
	struct channel *chan = NULL;
	struct bt_l2cap_chan *allocated_channels[L2CAP_CHANNELS] = {NULL};
	uint8_t i = 0;
	int err = 0;

	for (i = 0U; i < num_l2cap_channels; i++) {
		chan = get_free_channel();
		if (!chan) {
			printk("connect_num_channels: failed, chan not free \n");
			/* TODO should fail */
			return;
		}
		chan->le.chan.ops = &l2cap_ops;
		chan->le.tx.mtu = DATA_MTU;
		allocated_channels[i] = &chan->le.chan;
	}

	err = bt_l2cap_ecred_chan_connect(default_conn, allocated_channels,
						servers[0].psm);
	if (err) {
		printk("connect_num_channels: can't connect ecred %d \n", err);
	}
}

static int accept(struct bt_conn *conn, struct bt_l2cap_chan **l2cap_chan)
{
	struct channel *chan;

	chan = get_free_channel();
	if (!chan) {
		return -ENOMEM;
	}

	chan->le.chan.ops = &l2cap_ops;
	chan->le.rx.mtu = DATA_MTU;

	*l2cap_chan = &chan->le.chan;

	return 0;
}

static struct bt_l2cap_server *get_free_server(void)
{
	uint8_t i;

	for (i = 0U; i < SERVERS ; i++) {
		if (servers[i].psm) {
			continue;
		}

		return &servers[i];
	}

	return NULL;
}

static void register_l2cap_server(void)
{
	struct bt_l2cap_server *server;

	server = get_free_server();
	if (!server) {
		FAIL("Failed to get free server\n");
		return;
	}

	server->accept = accept;
	/* This should be 0 for dynamically allocated channels. 0x27 for EATT.
	   If 0 is used, then a newly allocated value will have been assigned to it (0x80 is the first)
	   The value is expected to be exposed by a GATT service.
	   But it writes it directly to the server as well, so we can use it without GATT */
	server->psm = 0;

	if (bt_l2cap_server_register(server) < 0) {
		FAIL("Failed to get free server\n");
		return;
	}

	printk("L2CAP server registered, PSM:0x%X\n", server->psm);
}

static bool volatile  is_connected;

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

	register_l2cap_server();
	connect_num_channels(5);

	/* Wait a bit, to let the connection be done. */
	k_sleep(K_MSEC(1000));

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

	/* Create the server, as it is needed to connect L2CAP channels */
	register_l2cap_server();

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