/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 * Copyright (c) 2021 Nordic Semiconductor
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>

#include <zephyr/types.h>
#include <sys/util.h>
#include <sys/byteorder.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>
#include "bs_types.h"
#include "bs_tracing.h"
#include "bstests.h"

#define LOG_MODULE_NAME main_l2cap_ecred
#include <logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME, LOG_LEVEL_DBG);

extern enum bst_result_t bst_result;

#define FAIL(...)				       \
	do {					       \
		bst_result = Failed;		       \
		bs_trace_error_time_line(__VA_ARGS__); \
	} while (0)

#define PASS(...)				    \
	do {					    \
		bst_result = Passed;		    \
		bs_trace_info_time(1, __VA_ARGS__); \
	} while (0)

static struct bt_conn *default_conn;

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
};

#define DATA_MTU 2000
#define DATA_MPS 65
#define DATA_BUF_SIZE BT_L2CAP_SDU_BUF_SIZE(DATA_MTU)
#define L2CAP_CHANNELS 5
#define SERVERS 1

NET_BUF_POOL_FIXED_DEFINE(rx_data_pool, L2CAP_CHANNELS, BT_L2CAP_BUF_SIZE(DATA_BUF_SIZE), 8, NULL);

NET_BUF_POOL_FIXED_DEFINE(tx_data_pool0, 1, BT_L2CAP_BUF_SIZE(DATA_MTU), 0, NULL);

NET_BUF_POOL_FIXED_DEFINE(tx_data_pool1, 1, BT_L2CAP_BUF_SIZE(DATA_MTU), 0, NULL);

static struct channel {
	uint8_t chan_id; /* Internal number that identifies L2CAP channel. */
	struct bt_l2cap_le_chan le;
	bool in_use;
	uint32_t time_of_first_received_sdu;
} channels[L2CAP_CHANNELS];
static bool volatile is_connected;
static struct bt_l2cap_server servers[SERVERS];

static struct channel *get_free_channel(void)
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

static struct net_buf *chan_alloc_buf_cb(struct bt_l2cap_chan *chan)
{
	LOG_DBG("Allocated on chan %p", chan);
	return net_buf_alloc(&rx_data_pool, K_FOREVER);
}

static int chan_recv_cb(struct bt_l2cap_chan *l2cap_chan, struct net_buf *buf)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	chan->time_of_first_received_sdu = k_cycle_get_32();
	LOG_DBG("chan_id: %d, data_length: %d time:%d", chan->chan_id, buf->len,
		chan->time_of_first_received_sdu);
	return 0;
}

static void chan_sent_cb(struct bt_l2cap_chan *l2cap_chan)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	LOG_DBG("chan_id: %d", chan->chan_id);
}

static volatile int num_connect_chans;
static void chan_connected_cb(struct bt_l2cap_chan *l2cap_chan)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	LOG_DBG("chan_id: %d", chan->chan_id);

	LOG_DBG("tx.mtu %d, tx.mps: %d, rx.mtu: %d, rx.mps %d", sys_cpu_to_le16(chan->le.tx.mtu),
		sys_cpu_to_le16(chan->le.tx.mps), sys_cpu_to_le16(chan->le.rx.mtu),
		sys_cpu_to_le16(chan->le.rx.mps));

	num_connect_chans++;
}

static void chan_disconnected_cb(struct bt_l2cap_chan *l2cap_chan)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	LOG_DBG("chan_id: %d", chan->chan_id);

	chan->in_use = false;
}

static void chan_status_cb(struct bt_l2cap_chan *l2cap_chan, atomic_t *status)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	LOG_DBG("chan_id: %d, status: %ld", chan->chan_id, *status);
}

static void chan_released_cb(struct bt_l2cap_chan *l2cap_chan)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	LOG_DBG("chan_id: %d", chan->chan_id);
}

static void chan_reconfigured_cb(struct bt_l2cap_chan *l2cap_chan)
{
	struct channel *chan = CONTAINER_OF(l2cap_chan, struct channel, le);

	LOG_DBG("chan_id: %d", chan->chan_id);
}

static const struct bt_l2cap_chan_ops l2cap_ops = {
	.alloc_buf = chan_alloc_buf_cb,
	.recv = chan_recv_cb,
	.sent = chan_sent_cb,
	.connected = chan_connected_cb,
	.disconnected = chan_disconnected_cb,
	.status = chan_status_cb,
	.released = chan_released_cb,
	.reconfigured = chan_reconfigured_cb,
};

static void connect_num_channels(uint8_t num_l2cap_channels)
{
	struct channel *chan = NULL;
	struct bt_l2cap_chan *allocated_channels[L2CAP_CHANNELS] = { NULL };
	uint8_t i = 0;
	int err = 0;

	for (i = 0U; i < num_l2cap_channels; i++) {
		chan = get_free_channel();
		if (!chan) {
			FAIL("failed, chan not free");
			return;
		}
		chan->le.chan.ops = &l2cap_ops;
		chan->le.rx.mtu = DATA_MTU;
		chan->le.rx.mps = DATA_MPS;
		allocated_channels[i] = &chan->le.chan;
	}

	err = bt_l2cap_ecred_chan_connect(default_conn, allocated_channels, servers[0].psm);
	if (err) {
		FAIL("can't connect ecred %d ", err);
	}
}

static void disconnect_all_channels(void)
{
	uint8_t i = 0;
	int err = 0;

	for (i = 0U; i < ARRAY_SIZE(channels); i++) {
		if (channels[i].in_use) {
			LOG_DBG("Disconnecting channel: %d)", channels[i].chan_id);
			err = bt_l2cap_chan_disconnect(&channels[i].le.chan);
			if (err) {
				LOG_DBG("can't disconnnect channel (err: %d)", err);
			}
			channels[i].in_use = false;
		}
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
	chan->le.tx.mtu = DATA_MTU;
	chan->le.rx.mtu = DATA_MTU;

	*l2cap_chan = &chan->le.chan;

	return 0;
}

static struct bt_l2cap_server *get_free_server(void)
{
	uint8_t i;

	for (i = 0U; i < SERVERS; i++) {
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
		FAIL("Failed to get free server");
		return;
	}

	server->accept = accept;
	server->psm = 0;

	if (bt_l2cap_server_register(server) < 0) {
		FAIL("Failed to get free server");
		return;
	}

	LOG_DBG("L2CAP server registered, PSM:0x%X", server->psm);
}

static void connected(struct bt_conn *conn, uint8_t conn_err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (conn_err) {
		FAIL("Failed to connect to %s (%u)", addr, conn_err);
		bt_conn_unref(default_conn);
		default_conn = NULL;
		return;
	}

	default_conn = bt_conn_ref(conn);
	LOG_DBG("%s", addr);

	is_connected = true;
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_DBG("%s (reason 0x%02x)", addr, reason);

	if (default_conn != conn) {
		FAIL("Conn mismatch disconnect %s %s)", default_conn, conn);
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

static void send_sdu(int chan_idx, int bytes)
{
	static uint8_t data_to_send[3000];

	for (int i = 0; i < 3000; i++) {
		data_to_send[i] = i % 0xff;
	}
	struct bt_l2cap_chan *chan = &channels[chan_idx].le.chan;
	struct net_buf *buf;

	switch (chan_idx) {
	case 0:
		buf = net_buf_alloc(&tx_data_pool0, K_NO_WAIT);
		break;
	case 1:
		buf = net_buf_alloc(&tx_data_pool1, K_NO_WAIT);
		break;
	default:
		LOG_DBG("not enough pool");
		break;
	}
	if (buf == NULL) {
		LOG_DBG("Error: didn't get buffer");
	}
	net_buf_reserve(buf, BT_L2CAP_CHAN_SEND_RESERVE + BT_L2CAP_SDU_HDR_SIZE);
	net_buf_add_mem(buf, data_to_send, bytes);

	int ret = bt_l2cap_chan_send(chan, buf);

	LOG_DBG("bt_l2cap_chan_send returned: %i", ret);

	if (ret < 0) {
		LOG_DBG("Error: send failed error: %i", ret);
		net_buf_unref(buf);
	}
}

static void test_peripheral_main(void)
{
	int err;

	LOG_DBG("*L2CAP ECRED Peripheral started*");

	err = bt_enable(NULL);
	if (err) {
		FAIL("Can't enable Bluetooth (err %d)", err);
		return;
	}
	LOG_DBG("Peripheral Bluetooth initialized.");

	LOG_DBG("Connectable advertising...");
	err = bt_le_adv_start(BT_LE_ADV_CONN_NAME, ad, ARRAY_SIZE(ad), NULL, 0);
	if (err) {
		FAIL("Advertising failed to start (err %d)", err);
		return;
	}
	LOG_DBG("Advertising started.");

	LOG_DBG("Peripheral waiting for connection...");
	while (!is_connected) {
		k_sleep(K_MSEC(100));
	}
	LOG_DBG("Peripheral Connected.");

	/* Wait a bit to ensure that all LLCP have time to finish */
	k_sleep(K_MSEC(1000));

	register_l2cap_server();

	connect_num_channels(L2CAP_CHANNELS);

	k_sleep(K_MSEC(500));

	LOG_DBG("Sendign on chan0");
	send_sdu(0, DATA_MTU - 2);  /*Send a full SDU on channel 0*/
	LOG_DBG("Sendign on chan1");
	send_sdu(1, DATA_MPS - 2);  /*Send only one PDU on channel 0. This should finish first*/

	k_sleep(K_MSEC(5000));

	/* Disconnect */
	LOG_DBG("Peripheral Disconnecting....");
	err = bt_conn_disconnect(default_conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	LOG_DBG("Peripheral tried to disconnect");
	if (err) {
		FAIL("Disconnection failed (err %d)", err);
		return;
	}

	while (is_connected) {
		LOG_DBG("Peripheral still connected.");
		k_sleep(K_MSEC(100));
	}
	LOG_DBG("Peripheral Disconnected.");

	PASS("L2CAP ECRED Peripheral tests Passed");
	bs_trace_silent_exit(0);
}

static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			 struct net_buf_simple *ad)
{
	struct bt_le_conn_param *param;
	int err;

	err = bt_le_scan_stop();
	if (err) {
		FAIL("Stop LE scan failed (err %d)", err);
		return;
	}

	param = BT_LE_CONN_PARAM_DEFAULT;
	err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN, param, &default_conn);
	if (err) {
		FAIL("Create conn failed (err %d)", err);
		return;
	}
}

static void test_central_main(void)
{
	struct bt_le_scan_param scan_param = {
		.type = BT_LE_SCAN_TYPE_ACTIVE,
		.options = BT_LE_SCAN_OPT_NONE,
		.interval = BT_GAP_SCAN_FAST_INTERVAL,
		.window = BT_GAP_SCAN_FAST_WINDOW,
	};

	int err;

	LOG_DBG("*L2CAP ECRED Central started*");

	err = bt_enable(NULL);
	if (err) {
		FAIL("Can't enable Bluetooth (err %d)\n", err);
		return;
	}
	LOG_DBG("Central Bluetooth initialized.\n");

	err = bt_le_scan_start(&scan_param, device_found);
	if (err) {
		FAIL("Scanning failed to start (err %d)\n", err);
		return;
	}

	LOG_DBG("Scanning successfully started\n");

	LOG_DBG("Central waiting for connection...\n");
	while (!is_connected) {
		k_sleep(K_MSEC(100));
	}
	LOG_DBG("Central Connected.\n");

	/* Wait a bit to ensure that all LLCP have time to finish */
	k_sleep(K_MSEC(1000));

	register_l2cap_server();
	k_sleep(K_MSEC(5000));
	LOG_DBG("chan0 received at time: %i chan1 received at time: %i",
		channels[0].time_of_first_received_sdu, channels[1].time_of_first_received_sdu);
	if (channels[0].time_of_first_received_sdu == 0 ||
	    channels[1].time_of_first_received_sdu == 0) {
		FAIL("Did not receive both SDUs");
	} else if (channels[0].time_of_first_received_sdu <
		   channels[1].time_of_first_received_sdu) {
		FAIL("Received SDU0 first, thats the big one that should let SDU1 go first");
	}
	disconnect_all_channels();
	/* Wait for disconnect */
	while (is_connected) {
		k_sleep(K_MSEC(100));
	}
	LOG_DBG("Central Disconnected.");

	PASS("L2CAP ECRED Central tests Passed\n");
}

static void test_init(void)
{
	bst_result = In_progress;
}
static void test_tick(bs_time_t HW_device_time)
{
}

static const struct bst_test_instance test_def[] = { { .test_id = "peripheral",
						       .test_descr = "Peripheral L2CAP ECRED",
						       .test_post_init_f = test_init,
						       .test_tick_f = test_tick,
						       .test_main_f = test_peripheral_main },
						     { .test_id = "central",
						       .test_descr = "Central L2CAP ECRED",
						       .test_post_init_f = test_init,
						       .test_tick_f = test_tick,
						       .test_main_f = test_central_main },
						     BSTEST_END_MARKER };

struct bst_test_list *test_main_l2cap_ecred_install(struct bst_test_list *tests)
{
	return bst_add_tests(tests, test_def);
}
