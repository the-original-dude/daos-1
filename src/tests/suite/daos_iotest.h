/**
 * (C) Copyright 2016-2018 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
 * The Government's rights to use, modify, reproduce, release, perform, display,
 * or disclose this software are subject to the terms of the Apache License as
 * provided in Contract No. B609815.
 * Any reproduction of computer software, computer software documentation, or
 * portions thereof marked with this legend must also reproduce the markings.
 */
/**
 * This file is part of daos
 *
 * tests/suite/daos_iotest.h
 */
#ifndef __DAOS_IOTEST_H_
#define __DAOS_IOTEST_H_

#include "daos_test.h"
#include <sys/stat.h>
#include <fcntl.h>

extern int dts_obj_class;
extern int dts_obj_replica_cnt;

#define UPDATE_CSUM_SIZE	32
#define IOREQ_IOD_NR	5
#define IOREQ_SG_NR	5
#define IOREQ_SG_IOD_NR	5

struct ioreq {
	daos_handle_t		oh;
	test_arg_t		*arg;
	daos_event_t		ev;
	daos_key_t		dkey;
	daos_key_t		akey;
	d_iov_t		val_iov[IOREQ_SG_IOD_NR][IOREQ_SG_NR];
	d_sg_list_t		sgl[IOREQ_SG_IOD_NR];
	daos_csum_buf_t		csum;
	char			csum_buf[UPDATE_CSUM_SIZE];
	daos_recx_t		rex[IOREQ_SG_IOD_NR][IOREQ_IOD_NR];
	daos_epoch_range_t	erange[IOREQ_SG_IOD_NR][IOREQ_IOD_NR];
	daos_iod_t		iod[IOREQ_SG_IOD_NR];
	daos_iod_type_t		iod_type;
	uint64_t		fail_loc;
};

#define SEGMENT_SIZE (10 * 1048576) /* 10MB */

void
ioreq_init(struct ioreq *req, daos_handle_t coh, daos_obj_id_t oid,
	   daos_iod_type_t iod_type, test_arg_t *arg);

void
ioreq_fini(struct ioreq *req);

void
insert_single(const char *dkey, const char *akey, uint64_t idx, void *value,
	      daos_size_t iod_size, daos_handle_t th, struct ioreq *req);

void
insert_single_with_rxnr(const char *dkey, const char *akey, uint64_t idx,
			void *value, daos_size_t iod_size, int rx_nr,
			daos_handle_t th, struct ioreq *req);

void
lookup_single(const char *dkey, const char *akey, uint64_t idx,
	      void *val, daos_size_t data_size, daos_handle_t th,
	      struct ioreq *req);

void
lookup_single_with_rxnr(const char *dkey, const char *akey, uint64_t idx,
			void *val, daos_size_t iod_size, daos_size_t data_size,
			daos_handle_t th, struct ioreq *req);

void
lookup_empty_single(const char *dkey, const char *akey, uint64_t idx,
		    void *val, daos_size_t data_size, daos_handle_t th,
		    struct ioreq *req);

int
enumerate_dkey(daos_handle_t th, uint32_t *number, daos_key_desc_t *kds,
	       daos_anchor_t *anchor, void *buf, daos_size_t len,
	       struct ioreq *req);

void
insert(const char *dkey, int nr, const char **akey, daos_size_t *iod_size,
	int *rx_nr, uint64_t *idx, void **val, daos_handle_t th,
	struct ioreq *req);

void
insert_recxs(const char *dkey, const char *akey, daos_size_t iod_size,
	     daos_handle_t th, daos_recx_t *recxs, int nr, void *data,
	     daos_size_t data_size, struct ioreq *req);

void
lookup(const char *dkey, int nr, const char **akey, uint64_t *idx,
	daos_size_t *iod_size, void **val, daos_size_t *data_size,
	daos_handle_t th, struct ioreq *req, bool empty);

void
punch_obj(daos_handle_t th, struct ioreq *req);

void
punch_dkey(const char *dkey, daos_handle_t th, struct ioreq *req);

void
punch_akey(const char *dkey, const char *akey, daos_handle_t th,
	   struct ioreq *req);
void
punch_recxs(const char *dkey, const char *akey, daos_recx_t *recxs,
	    int nr, daos_handle_t th, struct ioreq *req);
void
punch_single(const char *dkey, const char *akey, uint64_t idx,
	     daos_handle_t th, struct ioreq *req);

void
lookup_recxs(const char *dkey, const char *akey, daos_size_t iod_size,
	     daos_handle_t th, daos_recx_t *recxs, int nr, void *data,
	     daos_size_t data_size, struct ioreq *req);

int
obj_setup(void **state);

int
obj_teardown(void **state);

int io_conf_run(test_arg_t *arg, const char *io_conf);

/* below list the structure defined for epoch io testing */

enum test_level {
	TEST_LVL_DAOS		= 0,
	TEST_LVL_VOS		= 1,
	/* fake/file IO to simulate/replay, use it for verification */
	TEST_LVL_FIO		= 2,
	TEST_LVLS		= 3,
};

enum test_op_type {
	TEST_OP_MIN		= 0,
	TEST_OP_UPDATE		= 0,
	TEST_OP_PUNCH		= 1,
	TEST_OP_EPOCH_DISCARD	= 2,
	/* above are modification OP, below are read-only OP */
	TEST_OP_FETCH		= 3,
	TEST_OP_ENUMERATE	= 4,
	TEST_OP_ADD		= 5,
	TEST_OP_EXCLUDE		= 6,
	TEST_OP_POOL_QUERY	= 7,
	TEST_OP_MAX		= 7,
};

static inline bool
test_op_is_modify(int op)
{
	return (op == TEST_OP_UPDATE	||
		op == TEST_OP_PUNCH	||
		op == TEST_OP_EPOCH_DISCARD);
}

struct test_op_record;
typedef int (*test_op_cb)(test_arg_t *arg, struct test_op_record *op,
			  char **buf, daos_size_t *buf_size);

struct test_op_dict {
	enum test_op_type	 op_type;
	char			*op_str;
	test_op_cb		 op_cb[TEST_LVLS];
};

struct test_key_record {
	/* link to epoch_io_args::op_list */
	d_list_t		 or_list;
	char			*or_dkey;
	char			*or_akey;
	int			 or_fd_array;
	int			 or_fd_single;
	daos_size_t		 or_iod_size;
	/* the epoch last replayed */
	daos_epoch_t		 or_replayed_epoch;
	/* modification OP queue on this key, ordered by tid */
	d_list_t		 or_queue;
	/* # OP in the queue */
	uint32_t		 or_op_num;
};

struct test_update_fetch_arg {
	daos_recx_t		*ua_recxs;
	int			*ua_values;
	int			 ua_recx_num;
	int			 ua_single_value;
	int			 ua_array:1, /* false for single */
				 ua_verify:1;
};

struct test_add_exclude_arg {
	d_rank_t	ua_rank;
	int		ua_tgt;
};

struct test_punch_arg {
	daos_recx_t	*pa_recxs;
	int		 pa_recxs_num;
};

/* one OP record per cmd line in the ioconf file */
struct test_op_record {
	/* link to test_key_record::or_queue */
	d_list_t		 or_queue_link;
	struct test_key_record	*or_key_rec; /* back pointer */
	daos_epoch_t		 or_epoch;
	enum test_op_type	 or_op;
	union {
		struct test_update_fetch_arg	uf_arg;
		struct test_punch_arg		pu_arg;
		struct test_add_exclude_arg	ae_arg;
	};
};

#endif
