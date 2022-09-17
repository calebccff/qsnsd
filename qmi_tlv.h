#ifndef __QMI_TLV_H__
#define __QMI_TLV_H__

#include <stdint.h>
#include <stdlib.h>

struct qmi_tlv {
	void *allocated;
	void *buf;
	size_t size;
	int error;
};

struct qmi_tlv_item {
	uint8_t key;
	uint16_t len;
	uint8_t data[];
} __attribute__((__packed__));

struct qmi_tlv_msg_name {
	int msg_id;
	const char *msg_name;
};

struct qmi_tlv *qmi_tlv_init(uint16_t txn, uint32_t msg_id, uint32_t msg_type);
void *qmi_tlv_encode(struct qmi_tlv *tlv, size_t *len);
struct qmi_tlv *qmi_tlv_decode(void *buf, size_t len);
void qmi_tlv_free(struct qmi_tlv *tlv);
void *qmi_tlv_get(struct qmi_tlv *tlv, uint8_t id, size_t *len);
void *qmi_tlv_get_array(struct qmi_tlv *tlv, uint8_t id, size_t len_size,
			size_t *len, size_t *size);
int qmi_tlv_set(struct qmi_tlv *tlv, uint8_t id, void *buf, size_t len);
int qmi_tlv_set_array(struct qmi_tlv *tlv, uint8_t id, size_t len_size,
		      void *buf, size_t len, size_t size);
struct qmi_response_type_v01 *qmi_tlv_get_result(struct qmi_tlv *tlv);

#endif
