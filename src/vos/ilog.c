#define D_LOGFAC DD_FAC(vos)
#include <daos/common.h>
#include <daos_srv/vos.h>
#include <daos/btree.h>
#include "vos_internal.h"
#include "vos_layout.h"
#include "ilog.h"

#define ILOG_TREE_ORDER 11

enum {
	ILOG_ITER_NONE,
	ILOG_ITER_INIT,
	ILOG_ITER_READY,
	ILOG_ITER_FINI,
};

/** The ilog is split into two parts.   If there is one entry, the ilog
 *  is embedded into the root df struct.   If not, a b+tree is used.
 *  The tree is used more like a set where only the key is used.
 */

struct ilog_tree {
	umem_off_t	it_root;
	uint64_t	it_embedded;
};

struct ilog_root {
	union {
		struct ilog_id		lr_id;
		struct ilog_tree	lr_tree;
	};
	bool				lr_punch;
	uint32_t			lr_magic;
};

#define DF_ID		"epoch:"DF_U64" dtx:0x"DF_X64
#define DP_ID(id)	(id).id_epoch, (id).id_dtx
#define DF_VAL		"punch:%s"
#define DP_VAL(punch)	punch ? " true" : "false"


D_CASSERT(sizeof(struct ilog_id) == sizeof(struct ilog_tree));
D_CASSERT(sizeof(struct ilog_root) == sizeof(struct ilog_df));
/** We hijack the value offset to store the actual value inline */
D_CASSERT(sizeof(bool) <= sizeof(((struct btr_record *)0)->rec_off));

/**
 * Customized functions for btree.
 */

/** size of hashed-key */
static int
ilog_hkey_size(void)
{
	return sizeof(struct ilog_id);
}

static int
ilog_rec_msize(int alloc_overhead)
{
	/** No extra allocation for ilog entries */
	return 0;
}

/** generate hkey */
static void
ilog_hkey_gen(struct btr_instance *tins, d_iov_t *key_iov, void *hkey)
{
	D_ASSERT(key_iov->iov_len == sizeof(struct ilog_id));
	memcpy(hkey, key_iov->iov_buf, sizeof(struct ilog_id));
}

/** compare the hashed key */
static int
ilog_hkey_cmp(struct btr_instance *tins, struct btr_record *rec, void *hkey)
{
	struct ilog_id	*k1 = (struct ilog_id *)&rec->rec_hkey[0];
	struct ilog_id	*k2 = (struct ilog_id *)hkey;

	if (k1->id_epoch < k2->id_epoch)
		return BTR_CMP_LT;

	if (k1->id_epoch > k2->id_epoch)
		return BTR_CMP_GT;

	return BTR_CMP_EQ;
}

/** create a new key-record, or install an externally allocated key-record */
static int
ilog_rec_alloc(struct btr_instance *tins, d_iov_t *key_iov,
	      d_iov_t *val_iov, struct btr_record *rec)
{
	D_ASSERT(val_iov->iov_len == sizeof(bool));
	/** Note the D_CASSERT above ensures that rec_off is large enough
	 *  to fit the value without allocating new memory.
	 */
	memcpy(&rec->rec_off, val_iov->iov_buf, val_iov->iov_len);

	return 0;
}

static int
ilog_rec_free(struct btr_instance *tins, struct btr_record *rec, void *args)
{
	return 0;
}

static int
ilog_rec_fetch(struct btr_instance *tins, struct btr_record *rec,
	      d_iov_t *key_iov, d_iov_t *val_iov)
{
	struct ilog_id	*key = (struct ilog_id *)&rec->rec_hkey[0];
	bool		*punch = (bool *)&rec->rec_off;

	if (key_iov != NULL) {
		if (key_iov->iov_buf == NULL) {
			d_iov_set(key_iov, key, sizeof(*key));
		} else {
			D_ASSERT(sizeof(*key) <= key_iov->iov_buf_len);
			memcpy(key_iov->iov_buf, key, sizeof(*key));
			key_iov->iov_len = sizeof(*key);
		}
	}
	if (val_iov != NULL) {
		if (val_iov->iov_buf == NULL) {
			d_iov_set(val_iov, punch, sizeof(*punch));
		} else {
			D_ASSERT(sizeof(*punch) <= val_iov->iov_buf_len);
			memcpy(val_iov->iov_buf, punch, sizeof(*punch));
			val_iov->iov_len = sizeof(*punch);
		}
	}
	return 0;
}

static int
ilog_rec_update(struct btr_instance *tins, struct btr_record *rec,
	       d_iov_t *key_iov, d_iov_t *val_iov)
{
	bool	*new_punch = val_iov->iov_buf;
	bool	*old_punch = (bool *)&rec->rec_off;
	int			 rc = 0;

	if (*new_punch <= *old_punch)
		return 0;

	/* The new one is a punch so promote the in-tree entry */
	rc = umem_tx_add_ptr(&tins->ti_umm, old_punch, sizeof(*old_punch));
	if (rc != 0)
		goto done;

	*old_punch = true;
done:
	return rc;
}

static btr_ops_t ilog_btr_ops = {
	.to_rec_msize		= ilog_rec_msize,
	.to_hkey_size		= ilog_hkey_size,
	.to_hkey_gen		= ilog_hkey_gen,
	.to_hkey_cmp		= ilog_hkey_cmp,
	.to_rec_alloc		= ilog_rec_alloc,
	.to_rec_free		= ilog_rec_free,
	.to_rec_fetch		= ilog_rec_fetch,
	.to_rec_update		= ilog_rec_update,
};

int
ilog_init(void)
{
	int	rc;

	rc = dbtree_class_register(VOS_BTR_ILOG, 0, &ilog_btr_ops);
	if (rc != 0)
		D_ERROR("Failed to register incarnation log btree class: %s\n",
			d_errstr(rc));

	return rc;
}

struct ilog_context {
	/** Root pointer */
	struct ilog_root		*ic_root;
	/** umem instance */
	struct umem_instance		*ic_umm;
	/** ref count for iterator */
	uint32_t			 ic_ref;
	/** padding */
	uint32_t			 ic_pad;
};

static inline bool
ilog_empty(struct ilog_root *root)
{
	return !root->lr_tree.it_embedded &&
		root->lr_tree.it_root == UMOFF_NULL;
}

#define ilog_tx_add_ptr(umm, ptr, len)	\
	umem_tx_add_ptr(umm, ptr, len)

#define ILOG_MAGIC 0xdeadbaad

static void
ilog_addref(struct ilog_context *lctx)
{
	lctx->ic_ref++;
}

static void
ilog_decref(struct ilog_context *lctx)
{
	lctx->ic_ref--;
	if (lctx->ic_ref == 0)
		D_FREE(lctx);
}

static int
ilog_ctx_create(struct umem_instance *umm, struct ilog_root *root,
		    struct ilog_context **lctxp)
{
	D_ALLOC_PTR(*lctxp);
	if (*lctxp == NULL) {
		D_ERROR("Could not allocate memory for open incarnation log\n");
		return -DER_NOMEM;
	}

	(*lctxp)->ic_root = root;
	(*lctxp)->ic_umm = umm;
	ilog_addref(*lctxp);
	return 0;
}

static daos_handle_t
ilog_lctx2hdl(struct ilog_context *lctx)
{
	daos_handle_t	hdl;

	hdl.cookie = (uint64_t)lctx;

	return hdl;
}

static struct ilog_context *
ilog_hdl2lctx(daos_handle_t hdl)
{
	struct ilog_context	*lctx;

	if (daos_handle_is_inval(hdl))
		return NULL;

	lctx = (struct ilog_context *)hdl.cookie;

	if (lctx->ic_root->lr_magic != ILOG_MAGIC)
		return NULL;

	return lctx;
}

static int
ilog_ptr_set_full(struct umem_instance *umm, void *dest, const void *src,
		  size_t len)
{
	int	rc = 0;

	D_ASSERT(umm != NULL);

	rc = vos_tx_begin(umm);
	if (rc != 0) {
		D_ERROR("Failed to start PMDK transaction: rc = %s\n",
			d_errstr(rc));
		goto done;
	}

	rc = ilog_tx_add_ptr(umm, dest, len);
	if (rc != 0) {
		D_ERROR("Failed to add to undo log\n");
		goto end;
	}

	memcpy(dest, src, len);
end:
	rc = vos_tx_end(umm, rc);
done:
	return rc;
}

#define ilog_ptr_set(umm, dest, src)	\
	ilog_ptr_set_full(umm, dest, src, sizeof(*(src)))

int
ilog_create(struct umem_instance *umm, struct ilog_df *root, daos_handle_t *loh)
{
	struct ilog_context	*lctx;
	struct ilog_root	 tmp = {0};
	int			 rc = 0;

	tmp.lr_magic = ILOG_MAGIC;
	rc = ilog_ptr_set(umm, root, &tmp);
	if (rc != 0)
		goto done;

	rc = ilog_ctx_create(umm, (struct ilog_root *)root, &lctx);
	if (rc != 0)
		goto done;

	*loh = ilog_lctx2hdl(lctx);
done:
	return rc;
}

int
ilog_open(struct umem_instance *umm, struct ilog_df *root,
	      daos_handle_t *loh)
{
	struct ilog_context	*lctx;
	int			 rc;

	if (((struct ilog_root *)root)->lr_magic != ILOG_MAGIC) {
		D_ERROR("Could not open uninitialized incarnation log\n");
		return -DER_INVAL;
	}

	rc = ilog_ctx_create(umm, (struct ilog_root *)root, &lctx);
	if (rc != 0)
		return rc;

	*loh = ilog_lctx2hdl(lctx);

	return 0;
}

int
ilog_close(daos_handle_t loh)
{
	struct ilog_context *lctx = ilog_hdl2lctx(loh);

	D_ASSERTF(lctx != NULL,
		  "Trying to close invalid incarnation log handle\n");
	if (lctx == NULL)
		return -DER_INVAL;

	ilog_decref(lctx);

	return 0;
}

int
ilog_destroy(daos_handle_t loh)
{
	struct ilog_context	*lctx = ilog_hdl2lctx(loh);
	struct ilog_root	*root;
	struct umem_attr	 uma;
	uint64_t		 tmp = 0;
	int			 rc = 0;
	daos_handle_t		 toh;

	D_ASSERTF(lctx != NULL, "Cannot destroy incarnation log\n");
	if (lctx == NULL)
		return -DER_INVAL;

	root = lctx->ic_root;
	if (!ilog_empty(root) && !root->lr_tree.it_embedded) {
		umem_attr_get(lctx->ic_umm, &uma);
		rc = dbtree_open(root->lr_tree.it_root, &uma, &toh);
		if (rc != 0) {
			D_ERROR("Could not open incarnation log tree:"
				" rc = %s\n", d_errstr(rc));
			goto fail;
		}
		rc = dbtree_destroy(toh);
		if (rc != 0) {
			D_ERROR("Failed to destroy incarnation log tree:"
				" rc = %s\n", d_errstr(rc));
			goto fail;
		}
	}

	rc = ilog_ptr_set(lctx->ic_umm, &root->lr_magic, &tmp);

	if (rc != 0)
		D_ERROR("Failed to destroy incarnation log: rc = %s\n",
			d_errstr(rc));
fail:
	ilog_decref(lctx);
	return rc;
}

static int
ilog_root_migrate(struct ilog_context *lctx, const struct ilog_id *id,
		  bool new_punch)
{
	struct ilog_root	*root;
	struct ilog_root	 tmp = {0};
	d_iov_t			 key_iov;
	d_iov_t			 val_iov;
	struct ilog_id		 key;
	umem_off_t		 tree_root;
	daos_handle_t		 toh = DAOS_HDL_INVAL;
	struct umem_attr	 uma;
	bool			 punch;
	int			 rc = 0;

	root = lctx->ic_root;

	rc = vos_tx_begin(lctx->ic_umm);
	if (rc != 0) {
		D_ERROR("Failed to start PMDK transaction: rc = %s\n",
			d_errstr(rc));
		goto done;
	}

	umem_attr_get(lctx->ic_umm, &uma);
	rc = dbtree_create(VOS_BTR_ILOG, 0, ILOG_TREE_ORDER,
			   &uma, &tree_root, &toh);
	if (rc != 0) {
		D_ERROR("Failed to create an incarnation log tree: rc = %s\n",
			d_errstr(rc));
		goto end;
	}

	d_iov_set(&key_iov, &key, sizeof(key));
	d_iov_set(&val_iov, &punch, sizeof(punch));

	key = root->lr_id;
	punch = root->lr_punch;

	rc = dbtree_update(toh, &key_iov, &val_iov);
	if (rc != 0) {
		D_ERROR("Failed to add entry to incarnation log: %s\n",
			d_errstr(rc));
		goto end;
	}

	key = *id;
	punch = new_punch;

	rc = dbtree_update(toh, &key_iov, &val_iov);
	if (rc != 0) {
		D_ERROR("Failed to add entry to incarnation log: %s\n",
			d_errstr(rc));
		goto end;
	}

	tmp.lr_tree.it_root = tree_root;
	tmp.lr_tree.it_embedded = 0;
	tmp.lr_magic = ILOG_MAGIC;

	rc = ilog_ptr_set(lctx->ic_umm, root, &tmp);
end:
	rc = vos_tx_end(lctx->ic_umm, rc);
done:
	if (!daos_handle_is_inval(toh))
		dbtree_close(toh);

	return rc;
}

#define id_dtx_cmp(id1, id2)				\
({							\
	umem_off_t	__off1;				\
	umem_off_t	__off2;				\
							\
	__off1 = umem_off2offset((id1).id_dtx);		\
	__off2 = umem_off2offset((id2).id_dtx);		\
							\
	__off1 < __off2 ? -1 : __off1 > __off2 ? 1 : 0;	\
})

static int
update_inplace(struct ilog_context *lctx, enum ilog_op opc,
	       struct ilog_id *id_out, bool *punch_out,
	       const struct ilog_id *id_in, bool punch_in,
	       bool *is_equal)
{
	umem_off_t		null_off = UMOFF_NULL;
	int			cmp;

	*is_equal = true;

	if (id_in->id_epoch != id_out->id_epoch) {
		*is_equal = false;
		return 0;
	}

	cmp = id_dtx_cmp(*id_in, *id_out);
	if (cmp != 0) {
		*is_equal = false;
		D_ASSERT(opc != ILOG_OP_PERSIST);
		if (opc != ILOG_OP_UPDATE) {
			D_DEBUG(DB_IO, "No entry found, done\n");
			return 0;
		}
		D_DEBUG(DB_IO, "Access of incarnation log from multiple DTX"
			" at same time is not allowed: rc=DER_AGAIN\n");
		return -DER_AGAIN;
	}

	if (opc == ILOG_OP_PERSIST) {
		D_DEBUG(DB_IO, "Updating persistence\n");
		return ilog_ptr_set(lctx->ic_umm, &id_out->id_dtx, &null_off);
	} else if (opc != ILOG_OP_UPDATE) {
		/** Will remove in handler */
		return 0;
	}

	if (*punch_out || !punch_in)
		return 0;

	/* New operation in old DTX is a punch.  Update the old entry
	 * accordingly.
	 */
	D_DEBUG(DB_IO, "Updating old entry to a punch\n");
	return ilog_ptr_set(lctx->ic_umm, punch_out, &punch_in);
}

static int
collapse_tree(struct ilog_context *lctx, daos_handle_t *toh, daos_handle_t *ih)
{
	struct ilog_root	*root = lctx->ic_root;
	int			 rc;
	struct ilog_root	 tmp = {0};
	struct ilog_id		 key;
	d_iov_t			 key_iov;
	d_iov_t			 val_iov;
	bool			 punch;

	rc = dbtree_iter_probe(*ih, BTR_PROBE_FIRST, DAOS_INTENT_DEFAULT, NULL,
			       NULL);
	if (rc == -DER_NONEXIST) {
		rc = 0;
		key.id_epoch = 0;
		key.id_dtx = 0;
		punch = 0;
		goto set;
	}

	if (rc != 0) {
		D_ERROR("Could not probe iterator: rc = %s\n", d_errstr(rc));
		goto fail;
	}

	d_iov_set(&val_iov, &punch, sizeof(punch));
	d_iov_set(&key_iov, &key, sizeof(key));

	rc = dbtree_iter_fetch(*ih, &key_iov, &val_iov, NULL);
	if (rc != 0) {
		D_ERROR("Could not fetch from iterator: rc = %s\n",
			d_errstr(rc));
		goto fail;
	}
set:
	rc = dbtree_iter_finish(*ih);
	if (rc != 0) {
		D_ERROR("Could not finalize iterator: rc = %s\n", d_errstr(rc));
		goto done;
	}
	*ih = DAOS_HDL_INVAL;

	rc = dbtree_destroy(*toh);
	if (rc != 0) {
		D_ERROR("Could not destroy table: rc = %s\n", d_errstr(rc));
		goto done;
	}
	*toh = DAOS_HDL_INVAL;

	tmp.lr_magic = ILOG_MAGIC;
	tmp.lr_id = key;
	tmp.lr_punch = punch;
	rc = ilog_ptr_set(lctx->ic_umm, root, &tmp);
done:
	return rc;
fail:
	dbtree_iter_finish(*ih);
	return rc;
}

static int
consolidate_tree(struct ilog_context *lctx, const daos_epoch_range_t *epr,
		 daos_handle_t *toh, daos_handle_t *ih, enum ilog_op opc,
		 const struct ilog_id *id, bool is_punch)
{
	struct ilog_id		key = {0};
	struct btr_attr		attr;
	d_iov_t			key_iov;
	d_iov_t			val_iov;
	int			rc = 0;
	int			probe_opc = BTR_PROBE_GT;
	bool			punch = 0;

	D_ASSERT(opc != ILOG_OP_UPDATE);

	if (opc >= ILOG_OP_ABORT) {
		rc = dbtree_iter_delete(*ih, NULL);
		if (rc != 0)
			goto collapse;

		if (opc == ILOG_OP_ABORT)
			goto collapse;

		probe_opc = BTR_PROBE_LT;
	} else if (is_punch) {
		goto collapse;
	}

	for (;;) {
		d_iov_set(&key_iov, (struct ilog_id *)id, sizeof(*id));
		rc = dbtree_iter_probe(*ih, probe_opc, DAOS_INTENT_DEFAULT,
				       &key_iov, NULL);
		if (rc == -DER_NONEXIST)
			break;
		if (rc != 0) {
			D_ERROR("Problem with probing incarnation log:"
				" rc=%s\n", d_errstr(rc));
			goto done;
		}

		d_iov_set(&key_iov, &key, sizeof(key));
		d_iov_set(&val_iov, &punch, sizeof(punch));
		rc = dbtree_iter_fetch(*ih, &key_iov, &val_iov, NULL);
		if (rc != 0) {
			D_ERROR("Problem with fetching incarnation log:"
				" rc=%s\n", d_errstr(rc));
			goto done;
		}

		if (punch && opc == ILOG_OP_PERSIST)
			break;

		if (epr != NULL && (epr->epr_hi < key.id_epoch
				    || epr->epr_lo > key.id_epoch))
			break;

		D_DEBUG(DB_IO, "Removing entry "DF_ID" from incarnation log\n",
			DP_ID(key));
		rc = dbtree_iter_delete(*ih, NULL);
		if (rc != 0) {
			D_ERROR("Problem deleting entry in incarnation log:"
				" rc=%s\n", d_errstr(rc));
			goto done;
		}
	}
collapse:
	rc = dbtree_query(*toh, &attr, NULL);
	if (attr.ba_count > 1)
		goto done;

	rc = collapse_tree(lctx, toh, ih);
done:
	return rc;

}

static int
ilog_tree_update(struct ilog_context *lctx, const daos_epoch_range_t *epr,
		 enum ilog_op opc, const struct ilog_id *id,
		 bool punch, ilog_available_cb cb, void *cb_arg)
{
	struct ilog_root	*root;
	bool			*punchp;
	struct ilog_id		*keyp;
	struct ilog_id		 key;
	daos_handle_t		 toh = DAOS_HDL_INVAL;
	daos_handle_t		 ih = DAOS_HDL_INVAL;
	d_iov_t			 key_iov;
	d_iov_t			 val_iov;
	int			 visibility;
	struct umem_attr	 uma;
	int			 rc;

	root = lctx->ic_root;

	umem_attr_get(lctx->ic_umm, &uma);
	rc = dbtree_open(root->lr_tree.it_root, &uma, &toh);
	if (rc != 0) {
		D_ERROR("Failed to open incarnation log tree: rc = %s\n",
			d_errstr(rc));
		goto done;
	}

	rc = dbtree_iter_prepare(toh, BTR_ITER_EMBEDDED, &ih);
	if (rc != 0) {
		D_ERROR("Could not prepare iterator: rc = %s\n", d_errstr(rc));
		return rc;
	}

	for (;;) {
		bool	is_equal;

		d_iov_set(&key_iov, (struct ilog_id *)id, sizeof(*id));

		rc = dbtree_iter_probe(ih, BTR_PROBE_LE, DAOS_INTENT_DEFAULT,
				       &key_iov, NULL);
		if (rc == -DER_NONEXIST)
			break; /* Skip to handler */
		if (rc != 0) {
			D_ERROR("Could not probe iterator: rc = %s\n",
				d_errstr(rc));
			goto done;
		}

		d_iov_set(&key_iov, NULL, 0);
		d_iov_set(&val_iov, NULL, 0);

		rc = dbtree_iter_fetch(ih, &key_iov, &val_iov, NULL);
		if (rc != 0) {
			D_ERROR("Could not fetch from iterator: rc = %s\n",
				d_errstr(rc));
			goto done;
		}

		punchp = (bool *)val_iov.iov_buf;
		keyp = (struct ilog_id *)key_iov.iov_buf;

		visibility = cb(keyp, cb_arg);

		if (visibility == ILOG_REMOVED) {
			D_DEBUG(DB_IO, "Removing aborted entry "DF_ID"\n",
				DP_ID(*keyp));
			/* workaround until synchronous abort */
			rc = dbtree_iter_delete(toh, NULL);
			if (rc != 0) {
				D_ERROR("Failure to remove aborted entry:"
					" rc=%s\n", d_errstr(rc));
				goto done;
			}
			continue;
		}

		rc = update_inplace(lctx, opc, keyp, punchp, id, punch,
				    &is_equal);
		if (rc != 0)
			goto done;

		if (is_equal) {
			if (opc == ILOG_OP_UPDATE)
				goto done;

			if (opc == ILOG_OP_REMOVE && !*punchp) {
				D_ERROR("Remove operation no supported"
					" for non-punch:"
					" rc=DER_NO_PERM\n");
				rc = -DER_NO_PERM;
				goto done;
			}

			rc = consolidate_tree(lctx, epr, &toh, &ih, opc, id,
					      *punchp);

			goto done;
		}

		if (opc != ILOG_OP_UPDATE) {
			D_DEBUG(DB_IO, "No entry found, done\n");
			goto done;
		}

		if (punch || visibility == ILOG_INVISIBLE || *punchp)
			break; /* handle entry */
		/* the new update is "covered" by a previous one */
		goto done;
	}
	d_iov_set(&key_iov, &key, sizeof(key));
	d_iov_set(&val_iov, &punch, sizeof(punch));
	key = *id;
	rc = dbtree_upsert(toh, BTR_PROBE_EQ, DAOS_INTENT_UPDATE, &key_iov,
			   &val_iov);
	if (rc) {
		D_ERROR("Failed to update incarnation log: rc = %s\n",
			d_errstr(rc));
		goto done;
	}
done:
	if (!daos_handle_is_inval(ih))
		dbtree_iter_finish(ih);
	if (!daos_handle_is_inval(toh))
		dbtree_close(toh);

	return 0;
}

int
ilog_update(daos_handle_t loh, const daos_epoch_range_t *epr, enum ilog_op opc,
	    const struct ilog_id *id, bool punch, ilog_available_cb cb,
	    void *cb_arg)
{
	struct ilog_context	*lctx;
	struct ilog_root	*root;
	struct ilog_root	 tmp = {0};
	int			 rc = 0;
	int			 visibility = ILOG_INVISIBLE;

	D_ASSERT(id != NULL);
	if (D_LOG_ENABLED(DB_IO)) {
		if (opc == ILOG_OP_UPDATE) {
			D_DEBUG(DB_IO, "Updating incarnation log: op:%d "
				DF_ID" "DF_VAL"\n", opc, DP_ID(*id),
				DP_VAL(punch));
		} else {
			D_DEBUG(DB_IO, "Updating incarnation log: op:%d "
				DF_ID"\n", opc, DP_ID(*id));
		}
	}
	lctx = ilog_hdl2lctx(loh);
	if (lctx == NULL) {
		D_ERROR("Invalid log handle\n");
		return -DER_INVAL;
	}

	root = lctx->ic_root;

	if (root->lr_tree.it_embedded)
		visibility = cb(&root->lr_id, cb_arg);

	if (visibility == ILOG_REMOVED || ilog_empty(root)) {
		switch (opc) {
		case ILOG_OP_UPDATE:
			tmp.lr_magic = ILOG_MAGIC;
			tmp.lr_id = *id;
			tmp.lr_punch = punch;
			rc = ilog_ptr_set(lctx->ic_umm, root, &tmp);
			D_DEBUG(DB_IO, "Inserting at incarnation log root\n");
			break;
		default:
			if (visibility == ILOG_REMOVED) {
				tmp.lr_magic = ILOG_MAGIC;
				D_DEBUG(DB_IO, "Removing aborted "DF_ID"\n",
					DP_ID(root->lr_id));
				rc = ilog_ptr_set(lctx->ic_umm, root, &tmp);
			}
			D_DEBUG(DB_IO, "No entry found, done\n");
		}
	} else if (root->lr_tree.it_embedded) {
		bool	is_equal;

		rc = update_inplace(lctx, opc, &root->lr_id, &root->lr_punch,
				    id, punch, &is_equal);
		if (rc != 0)
			goto done;

		if (is_equal) {
			if (opc >= ILOG_OP_ABORT) {
				tmp.lr_magic = ILOG_MAGIC;
				rc = ilog_ptr_set(lctx->ic_umm, root, &tmp);
				D_DEBUG(DB_IO, "Resetting root\n");
			}
			goto done;
		}

		if (opc != ILOG_OP_UPDATE) {
			D_DEBUG(DB_IO, "No entry found, done\n");
			goto done;
		}

		if (!punch && !root->lr_punch &&
		    id->id_epoch > root->lr_id.id_epoch &&
		    visibility == ILOG_VISIBLE) {
			D_DEBUG(DB_IO, "No update needed\n");
			goto done;
		}
		/* Either this entry is earlier or prior entry is uncommitted
		 * or either entry is a punch
		 */
		rc = ilog_root_migrate(lctx, id, punch);
	} else {
		/** Ok, we have a tree.  Do the operation in the tree */
		rc = ilog_tree_update(lctx, epr, opc, id, punch, cb, cb_arg);
	}
done:
	D_DEBUG(DB_IO, "Update incarnation log "DF_ID" status: rc=%s\n",
		DP_ID(*id), d_errstr(rc));
	return rc;
}

void
ilog_fetch_init(struct ilog_entries *entries)
{
	D_ASSERT(entries != NULL);
	memset(entries, 0, sizeof(*entries));
	entries->ie_entries = &entries->ie_embedded[0];
	entries->ie_ih = DAOS_HDL_INVAL;
}

static void
ilog_fetch_reset(struct ilog_entries *entries)
{
	D_ASSERT(entries->ie_entries != NULL);
	D_ASSERT(entries->ie_alloc_size != 0 ||
		 entries->ie_entries == &entries->ie_embedded[0]);
	entries->ie_num_entries = 0;
}

static int
open_tree_iterator(struct ilog_context *lctx, daos_handle_t *ih)
{
	struct ilog_root	*root;
	struct umem_attr	 uma;
	int			 rc;
	daos_handle_t		 toh;

	if (!daos_handle_is_inval(*ih)) {
		/* NB: We can probably optimize this by validating that
		 * the ih has a valid tree but for now, this is simplest.
		 * The issue is the tree can potentially be reallocated
		 * in a different place between calls.
		 */
		dbtree_iter_finish(*ih);
		*ih = DAOS_HDL_INVAL;
	}

	root = lctx->ic_root;

	umem_attr_get(lctx->ic_umm, &uma);
	rc = dbtree_open(root->lr_tree.it_root, &uma, &toh);
	if (rc != 0) {
		D_ERROR("Failed to open ilog tree: rc = %s\n", d_errstr(rc));
		return rc;
	}

	rc = dbtree_iter_prepare(toh, BTR_ITER_EMBEDDED, ih);
	if (rc != 0)
		D_ERROR("Failed to open ilog iterator: rc = %s\n",
			d_errstr(rc));

	dbtree_close(toh);

	return rc;
}

static struct ilog_entry *
alloc_entry(struct ilog_entries *entries)
{
	struct ilog_entry	*new_data;
	struct ilog_entry	*item;
	bool			 dealloc;
	size_t			 old_count;
	size_t			 new_count;

	if (entries->ie_num_entries < ILOG_NUM_EMBEDDED)
		goto out;

	if (entries->ie_num_entries < entries->ie_alloc_size)
		goto out;

	if (entries->ie_alloc_size) {
		old_count = entries->ie_alloc_size;
		dealloc = true;
	} else {
		old_count = ILOG_NUM_EMBEDDED;
		dealloc = false;
	}
	new_count = old_count * 2;

	D_ALLOC_ARRAY(new_data, new_count);
	if (new_data == NULL) {
		D_ERROR("No memory available for iterating ilog\n");
		return NULL;
	}

	memcpy(new_data, entries->ie_entries,
	       sizeof(*new_data) * old_count);
	if (dealloc)
		D_FREE(entries->ie_entries);

	entries->ie_entries = new_data;
	entries->ie_alloc_size = new_count;
out:
	item = &entries->ie_entries[entries->ie_num_entries++];

	return item;
}

static int
set_entry(struct ilog_entries *entries, const struct ilog_id *id,
	  bool punch)
{
	struct ilog_entry *entry;

	entry = alloc_entry(entries);
	if (entry == NULL)
		return -DER_NOMEM;

	entry->ie_id = *id;
	entry->ie_punch = punch;

	return 0;
}

int
ilog_fetch(daos_handle_t loh, const daos_epoch_range_t *epr,
	   struct ilog_entries *entries)
{
	struct ilog_context	*lctx;
	struct ilog_root	*root;
	struct ilog_id		*id_out;
	struct ilog_id		 id = {0};
	daos_epoch_range_t	 range = {0, DAOS_EPOCH_MAX};
	d_iov_t			 id_iov;
	d_iov_t			 val_iov;
	int			 rc;

	if (epr) {
		range.epr_lo = epr->epr_lo;
		range.epr_hi = epr->epr_hi;
	}

	ilog_fetch_reset(entries);

	lctx = ilog_hdl2lctx(loh);
	if (lctx == NULL) {
		D_ERROR("Invalid log handle\n");
		return -DER_INVAL;
	}

	root = lctx->ic_root;

	if (ilog_empty(root))
		return -DER_NONEXIST;

	if (root->lr_tree.it_embedded) {
		entries->ie_entries[0].ie_id = root->lr_id;
		entries->ie_entries[0].ie_punch = root->lr_punch;
		entries->ie_num_entries = 1;
		return 0;
	}

	rc = open_tree_iterator(lctx, &entries->ie_ih);
	if (rc != 0)
		return rc;

	d_iov_set(&id_iov, &id, sizeof(id));
	id.id_epoch = range.epr_lo;

	rc = dbtree_iter_probe(entries->ie_ih, BTR_PROBE_GE,
			       DAOS_INTENT_DEFAULT, &id_iov, NULL);
	if (rc == -DER_NONEXIST)
		return rc;

	if (rc != 0) {
		D_ERROR("Error probing ilog: rc = %s\n", d_errstr(rc));
		return rc;
	}

	for (;;) {
		d_iov_set(&id_iov, NULL, 0);
		d_iov_set(&val_iov, NULL, 0);
		rc = dbtree_iter_fetch(entries->ie_ih, &id_iov, &val_iov, NULL);
		if (rc != 0) {
			D_ERROR("Error fetching ilog entry from tree:"
				" rc = %s\n", d_errstr(rc));
			return rc;
		}

		id_out = (struct ilog_id *)id_iov.iov_buf;
		if (id_out->id_epoch > range.epr_hi)
			break;

		rc = set_entry(entries, id_out,
			       *(bool *)val_iov.iov_buf);
		if (rc != 0)
			return rc;

		rc = dbtree_iter_next(entries->ie_ih);
		if (rc == -DER_NONEXIST)
			break;

	}

	if (entries->ie_num_entries == 0)
		return -DER_NONEXIST;

	return 0;
}

void
ilog_fetch_finish(struct ilog_entries *entries)
{
	D_ASSERT(entries != NULL);
	if (entries->ie_alloc_size)
		D_FREE(entries->ie_entries);

	if (!daos_handle_is_inval(entries->ie_ih))
		dbtree_iter_finish(entries->ie_ih);
}
