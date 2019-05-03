/**
 * (C) Copyright 2016-2019 Intel Corporation.
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
 * ds_cont: Epoch Operations
 */
#define D_LOGFAC	DD_FAC(container)

#include <daos_srv/pool.h>
#include <daos_srv/rdb.h>
#include "rpc.h"
#include "srv_internal.h"
#include "srv_layout.h"

static int
epoch_aggregate_bcast(crt_context_t ctx, struct cont *cont,
		      daos_epoch_range_t *epr, size_t count)
{
	struct cont_tgt_epoch_aggregate_in	*in;
	struct cont_tgt_epoch_aggregate_out	*out;
	crt_rpc_t				*rpc;
	int					rc;

	D_DEBUG(DF_DSMS, DF_CONT" bcast epr: "DF_U64"->"DF_U64 "\n",
		DP_CONT(cont->c_svc->cs_pool_uuid, cont->c_uuid),
		epr->epr_lo, epr->epr_hi);

	rc = ds_cont_bcast_create(ctx, cont->c_svc, CONT_TGT_EPOCH_AGGREGATE,
				  &rpc);
	if (rc != 0)
		D_GOTO(out, rc);

	in = crt_req_get(rpc);
	in->tai_epr_list.ca_arrays = epr;
	in->tai_epr_list.ca_count = count;
	uuid_copy(in->tai_pool_uuid, cont->c_svc->cs_pool_uuid);
	uuid_copy(in->tai_cont_uuid, cont->c_uuid);

	rc = dss_rpc_send(rpc);
	if (rc != 0)
		D_GOTO(out_rpc, rc);

	out = crt_reply_get(rpc);
	rc = out->tao_rc;

	if (rc != 0) {
		D_ERROR(DF_CONT",agg-bcast,e:"DF_U64"->"DF_U64":%d(targets)\n",
			DP_CONT(cont->c_svc->cs_pool_uuid, cont->c_uuid),
			epr->epr_lo, epr->epr_hi, rc);
		rc = -DER_IO;
	}

out_rpc:
	crt_req_decref(rpc);
out:
	D_DEBUG(DF_DSMS, DF_CONT": bcasted: %d\n",
		DP_CONT(cont->c_svc->cs_pool_uuid, cont->c_uuid), rc);
	return rc;
}

struct snap_list_iter_args {
	int		 sla_index;
	int		 sla_count;
	int		 sla_max_count;
	daos_epoch_t	*sla_buf;
};

static int
snap_list_iter_cb(daos_handle_t ih, d_iov_t *key, d_iov_t *val,
		  void *arg)
{
	struct snap_list_iter_args *i_args = arg;

	D_ASSERTF(key->iov_len == sizeof(daos_epoch_t),
		  DF_U64"\n", key->iov_len);

	if (i_args->sla_count > 0) {
		/* Check if we've reached capacity */
		if (i_args->sla_index == i_args->sla_count)  {
			/* Increase capacity exponentially */
			i_args->sla_count *= 2;
			/* If max_count < 0, there is no upper limit */
			if (i_args->sla_max_count > 0 &&
			    i_args->sla_max_count < i_args->sla_count)
				i_args->sla_count = i_args->sla_max_count;

			/* Re-allocate only if count actually increased */
			if (i_args->sla_index < i_args->sla_count) {
				void *ptr;

				D_REALLOC(ptr, i_args->sla_buf,
					  i_args->sla_count *
					  sizeof(daos_epoch_t));
				if (ptr == NULL)
					return -DER_NOMEM;
				i_args->sla_buf = ptr;
			}
		}

		if (i_args->sla_index < i_args->sla_count)
			memcpy(&i_args->sla_buf[i_args->sla_index],
			       key->iov_buf, sizeof(daos_epoch_t));
	}
	++i_args->sla_index;
	return 0;
}

static int
read_snap_list(struct rdb_tx *tx, struct cont *cont,
	       daos_epoch_t **buf, int *count)
{
	struct snap_list_iter_args iter_args;
	int rc;

	iter_args.sla_index = 0;
	iter_args.sla_max_count = *count;
	if (*count != 0) {
		/* start with initial size then grow the buffer */
		iter_args.sla_count = *count > 0 && *count < 64 ? *count : 64;
		D_ALLOC_ARRAY(iter_args.sla_buf, iter_args.sla_count);
		if (iter_args.sla_buf == NULL)
			return -DER_NOMEM;
	} else {
		iter_args.sla_count = 0;
		iter_args.sla_buf = NULL;
	}
	rc = rdb_tx_iterate(tx, &cont->c_snaps, false /* !backward */,
			    snap_list_iter_cb, &iter_args);
	if (rc != 0) {
		D_FREE(iter_args.sla_buf);
		return rc;
	}
	*count = iter_args.sla_index;
	*buf   = iter_args.sla_buf;
	return 0;
}

static int
trigger_aggregation(struct rdb_tx *tx, struct cont *cont, daos_epoch_t epoch_lo,
		    daos_epoch_t epoch_hi, crt_context_t ctx)
{
	daos_epoch_t		*snapshots;
	int			 snap_count;
	daos_epoch_range_t	*ranges;
	int			 range_count;
	int			 start;
	int			 i;
	int			 rc = 0;

	if (epoch_hi <= epoch_lo)
		goto out;
	D_DEBUG(DF_DSMS, DF_CONT": Aggregating { "DF_U64" => "DF_U64" }\n",
			 DP_CONT(cont->c_svc->cs_pool_uuid, cont->c_uuid),
			 epoch_lo, epoch_hi);

	/* Aggregate between all snapshots */
	snap_count = -1; /* No upper limit */
	rc = read_snap_list(tx, cont, &snapshots, &snap_count);
	if (rc != 0)
		goto out;
	/* Start from highest snapshot less than lower bound */
	for (i = 0; i < snap_count && snapshots[i] < epoch_lo; ++i)
		;
	start = i - 1;

	/* range_count will be at least `1` and at most `snap_count + 1` */
	for (range_count = 1; i < snap_count &&
	     snapshots[i] < epoch_hi; ++range_count, ++i)
	     ;

	D_DEBUG(DF_DSMS, DF_CONT": snap_count=%d range_count=%d start=%d\n",
			 DP_CONT(cont->c_svc->cs_pool_uuid, cont->c_uuid),
			 snap_count, range_count, start);

	D_ALLOC_ARRAY(ranges, range_count);
	if (ranges == NULL) {
		rc = -DER_NOMEM;
		goto out_snap;
	}

	/* If start == -1, lower bound is less than lowest snapshot */
	ranges[0].epr_lo = start < 0 ? 0UL : snapshots[start];
	for (i = 1; i < range_count; ++i) {
		ranges[i - 1].epr_hi = snapshots[start + i];
		ranges[i].epr_lo = snapshots[start + i] + 1;
	}
	ranges[range_count - 1].epr_hi = epoch_hi;
	rc = epoch_aggregate_bcast(ctx, cont, ranges, range_count);
	D_FREE(ranges);
out_snap:
	D_FREE(snapshots);
out:
	return rc;
}

static int
read_ghce(struct rdb_tx *tx, struct cont *cont, daos_epoch_t *ghce)
{
	d_iov_t		value;
	int		rc;

	d_iov_set(&value, ghce, sizeof(*ghce));
	rc = rdb_tx_lookup(tx, &cont->c_prop, &ds_cont_prop_ghce, &value);
	if (rc != 0)
		D_ERROR(DF_CONT": failed to lookup GHCE: %d\n",
			DP_CONT(cont->c_svc->cs_pool_uuid, cont->c_uuid), rc);
	return rc;
}

static int
update_ghce(struct rdb_tx *tx, struct cont *cont, daos_epoch_t ghce)
{
	d_iov_t		value;
	int		rc;

	d_iov_set(&value, &ghce, sizeof(ghce));
	rc = rdb_tx_update(tx, &cont->c_prop, &ds_cont_prop_ghce, &value);
	if (rc != 0)
		D_ERROR(DF_CONT": failed to update ghce: %d\n",
			DP_CONT(cont->c_svc->cs_pool_uuid, cont->c_uuid), rc);
	return rc;
}

int
ds_cont_epoch_init_hdl(struct rdb_tx *tx, struct cont *cont, uuid_t c_hdl,
		       struct container_hdl *hdl)
{
	return 0;
}

int
ds_cont_epoch_fini_hdl(struct rdb_tx *tx, struct cont *cont,
		       crt_context_t ctx, struct container_hdl *hdl)
{
	return 0;
}

int
ds_cont_epoch_aggregate(struct rdb_tx *tx, struct ds_pool_hdl *pool_hdl,
			struct cont *cont, struct container_hdl *hdl,
			crt_rpc_t *rpc)
{
	struct cont_epoch_op_in	*in = crt_req_get(rpc);
	daos_epoch_t		 epoch = in->cei_epoch;
	int			 rc;

	D_DEBUG(DF_DSMS, DF_CONT": processing rpc %p: epoch="DF_U64"\n",
		DP_CONT(pool_hdl->sph_pool->sp_uuid, in->cei_op.ci_uuid), rpc,
		in->cei_epoch);

	if (epoch >= DAOS_EPOCH_MAX)
		return -DER_INVAL;
	else if (in->cei_epoch == 0)
		epoch = daos_ts2epoch();

	rc = trigger_aggregation(tx, cont, 0UL, epoch, rpc->cr_ctx);

	D_DEBUG(DF_DSMS, DF_CONT": replying rpc %p: epoch="DF_U64", %d\n",
		DP_CONT(pool_hdl->sph_pool->sp_uuid, in->cei_op.ci_uuid), rpc,
		epoch, rc);
	return rc;
}

static int
cont_epoch_discard_bcast(crt_context_t ctx, struct cont *cont,
			 const uuid_t hdl_uuid, daos_epoch_t epoch)
{
	struct cont_tgt_epoch_discard_in       *in;
	struct cont_tgt_epoch_discard_out      *out;
	crt_rpc_t			       *rpc;
	int					rc;

	D_DEBUG(DF_DSMS, DF_CONT": bcasting\n",
		DP_CONT(cont->c_svc->cs_pool_uuid, cont->c_uuid));

	rc = ds_cont_bcast_create(ctx, cont->c_svc, CONT_TGT_EPOCH_DISCARD,
				  &rpc);
	if (rc != 0)
		D_GOTO(out, rc);

	in = crt_req_get(rpc);
	uuid_copy(in->tii_hdl, hdl_uuid);
	in->tii_epoch = epoch;

	rc = dss_rpc_send(rpc);
	if (rc != 0)
		D_GOTO(out_rpc, rc);

	out = crt_reply_get(rpc);
	rc = out->tio_rc;
	if (rc != 0) {
		D_ERROR(DF_CONT": failed to discard epoch "DF_U64" for handle "
			DF_UUID" on %d targets\n",
			DP_CONT(cont->c_svc->cs_pool_uuid, cont->c_uuid), epoch,
			DP_UUID(hdl_uuid), rc);
		rc = -DER_IO;
	}

out_rpc:
	crt_req_decref(rpc);
out:
	D_DEBUG(DF_DSMS, DF_CONT": bcasted: %d\n",
		DP_CONT(cont->c_svc->cs_pool_uuid, cont->c_uuid), rc);
	return rc;
}

int
ds_cont_epoch_discard(struct rdb_tx *tx, struct ds_pool_hdl *pool_hdl,
		      struct cont *cont, struct container_hdl *hdl,
		      crt_rpc_t *rpc)
{
	struct cont_epoch_op_in	       *in = crt_req_get(rpc);
	int				rc;

	D_DEBUG(DF_DSMS, DF_CONT": processing rpc %p: hdl="DF_UUID" epoch="
		DF_U64"\n",
		DP_CONT(pool_hdl->sph_pool->sp_uuid, in->cei_op.ci_uuid), rpc,
		DP_UUID(in->cei_op.ci_hdl), in->cei_epoch);

	/* Verify the container handle capabilities. */
	if (!(hdl->ch_capas & DAOS_COO_RW))
		D_GOTO(out, rc = -DER_NO_PERM);

	if (in->cei_epoch >= DAOS_EPOCH_MAX)
		D_GOTO(out, rc = -DER_OVERFLOW);

	rc = cont_epoch_discard_bcast(rpc->cr_ctx, cont, in->cei_op.ci_hdl,
				      in->cei_epoch);
out:
	D_DEBUG(DF_DSMS, DF_CONT": replying rpc %p: %d\n",
		DP_CONT(pool_hdl->sph_pool->sp_uuid, in->cei_op.ci_uuid), rpc,
		rc);
	return rc;
}

int
ds_cont_epoch_commit(struct rdb_tx *tx, struct ds_pool_hdl *pool_hdl,
		     struct cont *cont, struct container_hdl *hdl,
		     crt_rpc_t *rpc, bool snapshot)
{
	struct cont_epoch_op_in	       *in = crt_req_get(rpc);
	daos_epoch_t			ghce;
	d_iov_t				key;
	d_iov_t				value;
	int				rc;

	D_DEBUG(DF_DSMS, DF_CONT": processing rpc %p: epoch="DF_U64"\n",
		DP_CONT(pool_hdl->sph_pool->sp_uuid, in->cei_op.ci_uuid), rpc,
		in->cei_epoch);

	/* Verify the container handle capabilities. */
	if (!(hdl->ch_capas & DAOS_COO_RW)) {
		rc = -DER_NO_PERM;
		goto out;
	}

	if (in->cei_epoch >= DAOS_EPOCH_MAX) {
		rc = -DER_OVERFLOW;
		goto out;
	}

	rc = read_ghce(tx, cont, &ghce);
	if (rc != 0)
		goto out;

	/* Committing an already committed epoch is okay and a no-op. */
	if (in->cei_epoch < ghce)
		goto out;
	else if (in->cei_epoch == ghce)
		goto out_snap;

	rc = update_ghce(tx, cont, in->cei_epoch);
	if (rc != 0)
		goto out;
	ghce = in->cei_epoch;

out_snap:
	if (snapshot) {
		char		zero = 0;

		d_iov_set(&key, &in->cei_epoch, sizeof(in->cei_epoch));
		d_iov_set(&value, &zero, sizeof(zero));
		rc = rdb_tx_update(tx, &cont->c_snaps, &key, &value);
		if (rc != 0) {
			D_ERROR(DF_CONT": failed to create snapshot: %d\n",
				DP_CONT(cont->c_svc->cs_pool_uuid,
					cont->c_uuid), rc);
			goto out;
		}
	}

	rc = trigger_aggregation(tx, cont, 0UL, ghce, rpc->cr_ctx);
	if (rc != 0)
		D_ERROR("Trigger aggregation from commit failed %d\n", rc);
out:
	D_DEBUG(DF_DSMS, DF_CONT": replying rpc %p: %d\n",
		DP_CONT(pool_hdl->sph_pool->sp_uuid, in->cei_op.ci_uuid), rpc,
		rc);
	return rc;
}

struct snap_destroy_iter_args {
	daos_epoch_t		sda_find;
	daos_epoch_t		sda_prev;
	daos_epoch_range_t	sda_range;
};

static int
snap_destroy_iter_cb(daos_handle_t ih, d_iov_t *key, d_iov_t *val,
		     void *arg)
{
	struct snap_destroy_iter_args *i_args = arg;
	daos_epoch_t *curr = key->iov_buf;

	D_ASSERTF(key->iov_len == sizeof(daos_epoch_t),
		  DF_U64"\n", key->iov_len);
	if (*curr == i_args->sda_find)
		i_args->sda_range.epr_lo = i_args->sda_prev + 1;
	else if (i_args->sda_find == i_args->sda_prev) {
		if (i_args->sda_range.epr_hi > *curr)
			i_args->sda_range.epr_hi = *curr;
		return 1;
	}
	i_args->sda_prev = *curr;
	return 0;
}

int
ds_cont_snap_destroy(struct rdb_tx *tx, struct ds_pool_hdl *pool_hdl,
		    struct cont *cont, struct container_hdl *hdl,
		    crt_rpc_t *rpc)
{
	struct cont_epoch_op_in		*in = crt_req_get(rpc);
	struct snap_destroy_iter_args	 iter_args;
	d_iov_t				 key;
	daos_epoch_t			 ghce;
	int				 rc;

	D_DEBUG(DF_DSMS, DF_CONT": processing rpc %p: epoch="DF_U64"\n",
		DP_CONT(pool_hdl->sph_pool->sp_uuid, in->cei_op.ci_uuid),
		rpc, in->cei_epoch);

	d_iov_set(&key, &in->cei_epoch, sizeof(daos_epoch_t));
	rc = rdb_tx_delete(tx, &cont->c_snaps, &key);
	if (rc != 0) {
		rc = 0;
		goto out;
	}
	rc = read_ghce(tx, cont, &ghce);
	if (rc != 0)
		goto out;

	iter_args.sda_find = in->cei_epoch;
	iter_args.sda_prev = 0UL;
	iter_args.sda_range.epr_lo = 0UL;
	iter_args.sda_range.epr_hi = ghce;
	rc = rdb_tx_iterate(tx, &cont->c_snaps, false /* !backward */,
			    snap_destroy_iter_cb, &iter_args);
	if (rc != 0)
		goto out;

	D_DEBUG(DF_DSMS, "deleted="DF_U64" prev="DF_U64" next="DF_U64"\n",
		in->cei_epoch, iter_args.sda_range.epr_lo,
		iter_args.sda_range.epr_hi);
	rc = epoch_aggregate_bcast(rpc->cr_ctx, cont, &iter_args.sda_range, 1);
out:
	return rc;
}

static int
bulk_cb(const struct crt_bulk_cb_info *cb_info)
{
	ABT_eventual *eventual = cb_info->bci_arg;

	ABT_eventual_set(*eventual, (void *)&cb_info->bci_rc,
			 sizeof(cb_info->bci_rc));
	return 0;
}

int
ds_cont_snap_list(struct rdb_tx *tx, struct ds_pool_hdl *pool_hdl,
		  struct cont *cont, struct container_hdl *hdl, crt_rpc_t *rpc)
{
	struct cont_snap_list_in	*in		= crt_req_get(rpc);
	struct cont_snap_list_out	*out		= crt_reply_get(rpc);
	daos_size_t			 bulk_size;
	daos_epoch_t			*snapshots;
	int				 snap_count;
	int				 xfer_size;
	int				 rc;

	D_DEBUG(DF_DSMS, DF_CONT": processing rpc %p: hdl="DF_UUID"\n",
		DP_CONT(pool_hdl->sph_pool->sp_uuid, in->sli_op.ci_uuid),
		rpc, DP_UUID(in->sli_op.ci_hdl));
	/*
	 * If remote bulk handle does not exist, only aggregate size is sent.
	 */
	if (in->sli_bulk) {
		rc = crt_bulk_get_len(in->sli_bulk, &bulk_size);
		if (rc != 0)
			goto out;
		D_DEBUG(DF_DSMS, DF_CONT": bulk_size=%lu\n",
			DP_CONT(pool_hdl->sph_pool->sp_uuid,
				in->sli_op.ci_uuid), bulk_size);
		snap_count = (int)(bulk_size / sizeof(daos_epoch_t));
	} else {
		bulk_size = 0;
		snap_count = 0;
	}
	rc = read_snap_list(tx, cont, &snapshots, &snap_count);
	if (rc != 0)
		goto out;
	out->slo_count = snap_count;
	xfer_size = snap_count * sizeof(daos_epoch_t);
	xfer_size = MIN(xfer_size, bulk_size);

	if (xfer_size > 0) {
		ABT_eventual	 eventual;
		int		*status;
		d_iov_t	 iov = {
			.iov_buf	= snapshots,
			.iov_len	= xfer_size,
			.iov_buf_len	= xfer_size
		};
		d_sg_list_t	 sgl = {
			.sg_nr_out = 1,
			.sg_nr	   = 1,
			.sg_iovs   = &iov
		};
		struct crt_bulk_desc bulk_desc = {
			.bd_rpc		= rpc,
			.bd_bulk_op	= CRT_BULK_PUT,
			.bd_local_off	= 0,
			.bd_remote_hdl	= in->sli_bulk,
			.bd_remote_off	= 0,
			.bd_len		= xfer_size
		};

		rc = ABT_eventual_create(sizeof(*status), &eventual);
		if (rc != ABT_SUCCESS) {
			rc = dss_abterr2der(rc);
			goto out_mem;
		}

		rc = crt_bulk_create(rpc->cr_ctx, &sgl, CRT_BULK_RW,
				     &bulk_desc.bd_local_hdl);
		if (rc != 0)
			goto out_eventual;
		rc = crt_bulk_transfer(&bulk_desc, bulk_cb, &eventual, NULL);
		if (rc != 0)
			goto out_bulk;
		rc = ABT_eventual_wait(eventual, (void **)&status);
		if (rc != ABT_SUCCESS)
			rc = dss_abterr2der(rc);
		else
			rc = *status;

out_bulk:
		crt_bulk_free(bulk_desc.bd_local_hdl);
out_eventual:
		ABT_eventual_free(&eventual);
	}

out_mem:
	D_FREE(snapshots);
out:
	return rc;
}

int
ds_cont_get_snapshots(uuid_t pool_uuid, uuid_t cont_uuid,
		      daos_epoch_t **snapshots, int *snap_count)
{
	struct cont_svc	*svc;
	struct rdb_tx	tx;
	struct cont	*cont = NULL;
	int		rc;

	D_ASSERT(dss_get_module_info()->dmi_xs_id == 0);
	rc = cont_svc_lookup_leader(pool_uuid, 0, &svc, NULL);
	if (rc != 0)
		return rc;

	rc = rdb_tx_begin(svc->cs_rsvc->s_db, svc->cs_rsvc->s_term, &tx);
	if (rc != 0)
		D_GOTO(out_put, rc);

	ABT_rwlock_rdlock(svc->cs_lock);
	rc = cont_lookup(&tx, svc, cont_uuid, &cont);
	if (rc != 0)
		D_GOTO(out_lock, rc);

	rc = read_snap_list(&tx, cont, snapshots, snap_count);
	if (rc != 0)
		D_GOTO(out_lock, rc);

out_lock:
	ABT_rwlock_unlock(svc->cs_lock);
	rdb_tx_end(&tx);
out_put:
	cont_svc_put_leader(svc);

	return rc;
}
