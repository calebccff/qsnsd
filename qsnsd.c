#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libqrtr.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "list.h"
#include "util.h"

#include "qmi_sns.h"

// TLV debugging stuff
struct qmi_tlv;
void qmi_tlv_dump(struct qmi_tlv *tlv);

// Binary protobuf request used during downstream init
// obviously this should be replaced by a real protobuf impl.
// it looks something like this:
/*
root:
    1 <chunk> = message:
        1 <64bit> = 0xABABABABABABABAB / -6076574518398440533 / -2.5301707e-98
        2 <64bit> = 0xABABABABABABABAB / -6076574518398440533 / -2.5301707e-98
    2 <32bit> = 0x00000200 / 512 / 7.17465e-43
    3 <chunk> = message(1 <varint> = 1, 2 <varint> = 0)
    4 <chunk> = message:
        2 <chunk> = message:
            1 <chunk> = "registry"
            2 <varint> = 1
            3 <varint> = 0
*/
#define REGISTRY_INIT_PROTO_LEN 0x31
uint8_t pbuf_registry_init[REGISTRY_INIT_PROTO_LEN] = {
	0x0a, 0x12, 0x09, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x11, 0xab, 0xab, 0xab,
	0xab, 0xab, 0xab, 0xab, 0xab, 0x15, 0x00, 0x02, 0x00, 0x00, 0x1a, 0x04, 0x08, 0x01, 0x10,
	0x00, 0x22, 0x10, 0x12, 0x0e, 0x0a, 0x08, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x79,
	0x10, 0x01, 0x18, 0x00,
};

volatile sig_atomic_t terminate = 0;
int sns_service_port = 0;
// Transaction ID is used to identify which request a particular
// reply was for, we include it in our requests and the reponse
// for that particular request should have the same one.
// indication messages from the modem will use their own txn id
// which starts at 1(?)
int txn_id = 0x5;
struct list_head pending_packets;

// replace with a proper state machine
static bool init_pending = true;

void term(int signum)
{
	terminate = 1;
}

// Send a QMI packet to the sensor service
int sns_send(int fd, void *data, size_t sz)
{
	struct sns_msg *msg;
	const struct qmi_header *qmi;
	int rc;

	if (!sns_service_port) {
		fprintf(stderr, "[QRTR] invalid port!\n");
		return -1;
	}

	qmi = (const struct qmi_header*)data;

	msg = calloc(1, sizeof(struct sns_msg));
	msg->txn_id = txn_id;
	msg->msg_id = qmi->msg_id;
	msg->service = SNS_CLIENT_QMI_SERVICE;
	msg->port = sns_service_port;
	list_init(&msg->li);
	txn_id++;

	print_hex_dump("QRTR TX", data, sz);

	// The node represents which DSP we're sending to
	// the modem is always node 0, the SLPI is node 9
	rc = qrtr_sendto(fd, 9, sns_service_port, data, sz);
	if (rc == 0)
		list_append(&pending_packets, &msg->li);
	else {
		fprintf(stderr, "Failed to send! (%d)\n", rc);
		free(msg);
	}
	
	return rc;
}

int sns_handle_resp(int fd, struct qrtr_packet *pkt)
{
	unsigned txn;
	struct sns_sensor_client_resp *resp;
	struct sns_qmi_result *res;
	struct sns_msg *msg;
	uint64_t client_id;
	uint32_t r;
	
	resp = sns_sensor_client_resp_parse(pkt->data, pkt->data_len, &txn);
	qmi_tlv_dump((struct qmi_tlv*)resp);

	msg = sns_msg_get_by_txn(&pending_packets, txn);
	list_remove(&msg->li);
	free(msg);
	res = sns_sensor_client_resp_get_result(resp);

	printf("Result: %u, error: %u\n", res->result, res->error);
	// Assuming non-zero result means an error, not sure
	// this is always true
	if (res->result != 0)
		return -1;

	sns_sensor_client_resp_get_client_id(resp, &client_id);
	sns_sensor_client_resp_get_res(resp, &r);

	printf("RESPONSE { txn = 0x%2x, client_id = 0x%8lx, res = 0x%4x }\n", txn, client_id, r);

	return 0;
}

int sns_handle_report(int fd, struct qrtr_packet *pkt)
{
	unsigned txn;
	struct sns_sensor_client_ind *ind;
	uint64_t client_id;
	struct sns_payload *payload;

	ind = sns_sensor_client_ind_parse(pkt->data, pkt->data_len, &txn);
	if (!ind) {
		fprintf(stderr, "Couldn't parse message!\n");
		return -1;
	}

	qmi_tlv_dump((struct qmi_tlv*)ind);

	sns_sensor_client_ind_get_client_id(ind, &client_id);
	payload = sns_sensor_client_ind_get_data(ind);

	printf("INDICATION { txn = 0x%2x, client_id = 0x%8lx, proto = 0x%4x }\n", txn,
		client_id, payload->data_n);

	return 0;
}

int sns_handle_data(int fd, struct qrtr_packet *pkt, int msg_id)
{
	switch(msg_id) {
	case SNS_CLIENT_RESP:
		sns_handle_resp(fd, pkt);
		break;
	case SNS_CLIENT_REPORT:
		sns_handle_report(fd, pkt);
		break;
	default:
		fprintf(stderr, "Unknown message 0x%x\n", msg_id);
		break;
	}
	return 0;
}

int sns_send_init(int fd)
{
	struct sns_payload payload;
	struct sns_sensor_client_req *req;
	int rc;
	void *buf;
	size_t sz;

	req = sns_sensor_client_req_alloc(txn_id);

	payload.data_n = REGISTRY_INIT_PROTO_LEN;
	payload.data = pbuf_registry_init;

	rc = sns_sensor_client_req_set_data(req, &payload);
	if (rc < 0) {
		fprintf(stderr, "failed to set payload: %d\n", rc);
		return rc;
	}

	rc = sns_sensor_client_req_set_some_val(req, 1);
	if (rc < 0) {
		fprintf(stderr, "failed to set some_val: %d\n", rc);
		return rc;
	}

	buf = sns_sensor_client_req_encode(req, &sz);
	if (!buf) {
		fprintf(stderr, "Failed to encode request\n");
		return -1;
	}

	rc = sns_send(fd, buf, sz);
	sns_sensor_client_req_free(req);
	
	init_pending = false;

	return rc;
}

int main(int argc, char **argv)
{
	int fd, ret;
	unsigned char* buf;
	int len;
	struct sigaction action;
	struct qrtr_packet pkt;
	struct sns_msg *msg;
	struct sockaddr_qrtr sq;
	socklen_t sl = sizeof(sq);
	const struct qmi_header *qmi;

	buf = malloc(0x1000);
	list_init(&pending_packets);

	memset(&action, 0, sizeof(action));
	action.sa_handler = term;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);

	// For standard QMI you must allocate a client ID and hold it
	// for QRTR, this file descriptor is our ID, closing it will
	// cause the remote end to close down whatever they were doing
	fd = qrtr_open(0);
	if (fd < 0) {
		fprintf(stderr, "Failed to create qrtr socket\n");
		return fd;
	}
	printf("qrtr_open(fd=%d)\n", fd);

	// Sends a QRTR lookup packet to discover the sensor service
	ret = qrtr_new_lookup(fd, SNS_CLIENT_QMI_SERVICE, 0, 0);
	if (fd < 0) {
		fprintf(stderr, "Failed to lookup service\n");
		return fd;
	}

	while (!terminate) {
		// will poll indefinitely, should multithread
		// or use a small timeout and a state machine
		ret = qrtr_poll(fd, -1);
		printf("\n");

		memset(&sq, 0, sizeof(sq));

		len = recvfrom(fd, buf, 0x1000, 0, (void*)&sq, &sl);
		if (len < 0) {
			fprintf(stderr, "Failed to recv: %d\n", len);
			break;
		}

		ret = qrtr_decode(&pkt, buf, len, &sq);
		if (ret < 0) {
			fprintf(stderr, "Failed to qrtr_decode: %d\n", ret);
			free(buf);
			return ret;
		}
		switch (pkt.type) {
		// This should only be the sensor service
		// we need to know the port so that we can send
		// messages to it
		case QRTR_TYPE_NEW_SERVER:
			if (!pkt.service && !pkt.instance && !pkt.node && !pkt.port)
				break;
			printf("Found service! type: %d, node: %d, port: %d, service: %d, version: %d, instance: %d, data_len: %lu\n",
				pkt.type, pkt.node, pkt.port, pkt.service, pkt.version,
				pkt.instance, pkt.data_len);
			if (pkt.service == SNS_CLIENT_QMI_SERVICE)
				sns_service_port = pkt.port;
			break;
		// Regular QMI data packets, the pkt->data
		// buffer is the actual QMI data
		case QRTR_TYPE_DATA:
			qmi = qmi_get_header(&pkt);
			if (!qmi) {
				fprintf(stderr, "Failed to decode QMI header for pkt!");
				continue;
			}
			printf("[QRTR] data packet from port %d, msg_id: 0x%2x\n",
				sq.sq_port, qmi->msg_id);
			
			print_hex_dump("QRTR RX", pkt.data, pkt.data_len);
			//print_hex_dump("QRTR RX", (void*)qmi, sizeof(struct qmi_header));

			if (sq.sq_port == sns_service_port) {
				sns_handle_data(fd, &pkt, qmi->msg_id);
			}
			break;
		default:
			fprintf(stderr, "Failed to handle pkt type %d\n", pkt.type);
			break;
		}

		if (init_pending && sns_service_port) {
			ret = sns_send_init(fd);
			if (ret < 0) {
				fprintf(stderr, "Failed to init: %d\n", ret);
				break;
			}
		}
	}

	fprintf(stderr, "Exiting...\n");
	fprintf(stderr, "Pending responses:\n");
	list_for_each_entry(msg, &pending_packets, li) {
		fprintf(stderr, "\t{ txn_id = 0x%2x, msg_id = 0x%2x }\n",
			msg->txn_id, msg->msg_id);
	}

	free(buf);
	return 0;
}
