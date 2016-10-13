/*
 * Copyright (c) 2013 Mellanox Technologies®. All rights reserved.
 *
 * This software is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU General Public
 * License (GPL) Version 2, available from the file COPYING in the main
 * directory of this source tree, or the Mellanox Technologies® BSD license
 * below:
 *
 *      - Redistribution and use in source and binary forms, with or without
 *        modification, are permitted provided that the following conditions
 *        are met:
 *
 *      - Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 *      - Neither the name of the Mellanox Technologies® nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef XIO_TRANSPORT_H
#define XIO_TRANSPORT_H

#include <infiniband/verbs.h>
#include "xio_hash.h"
#include "xio_task.h"
#include "xio_ev_data.h"
#include "xio_workqueue_priv.h"
#include <sys/hashtable.h>

#define NUM_CONN_SETUP_TASKS		2 /* one posted for req rx,
					   * one for reply tx
					   */
#define CONN_SETUP_BUF_SIZE		4096

#define NUM_START_PRIMARY_POOL_TASKS	312  /* must be enough to send few +
					      *	fully post_recv buffers
					      */
#define NUM_ALLOC_PRIMARY_POOL_TASKS	512

#define VALIDATE_SZ(sz)        do {                    \
               if (optlen != (sz)) {           \
                       xio_set_error(EINVAL);  \
                       return -1;              \
               }                               \
       } while (0)

#define xio_prefetch(p)            __builtin_prefetch(p)

/*---------------------------------------------------------------------------*/
/* enums								     */
/*---------------------------------------------------------------------------*/
enum xio_transport_state {
	XIO_TRANSPORT_STATE_INIT,
	XIO_TRANSPORT_STATE_LISTEN,
	XIO_TRANSPORT_STATE_CONNECTING,
	XIO_TRANSPORT_STATE_CONNECTED,
	XIO_TRANSPORT_STATE_DISCONNECTED,
	XIO_TRANSPORT_STATE_RECONNECT,
	XIO_TRANSPORT_STATE_CLOSED,
	XIO_TRANSPORT_STATE_DESTROYED,
	XIO_TRANSPORT_STATE_ERROR
};

enum xio_transport_event {
	XIO_TRANSPORT_EVENT_NEW_CONNECTION,
	XIO_TRANSPORT_EVENT_ESTABLISHED,
	XIO_TRANSPORT_EVENT_DISCONNECTED,
	XIO_TRANSPORT_EVENT_CLOSED,
	XIO_TRANSPORT_EVENT_REFUSED,
	XIO_TRANSPORT_EVENT_NEW_MESSAGE,
	XIO_TRANSPORT_EVENT_SEND_COMPLETION,
	XIO_TRANSPORT_EVENT_ASSIGN_IN_BUF,
	XIO_TRANSPORT_EVENT_CANCEL_REQUEST,
	XIO_TRANSPORT_EVENT_CANCEL_RESPONSE,
	XIO_TRANSPORT_EVENT_MESSAGE_ERROR,
	XIO_TRANSPORT_EVENT_ERROR,
	XIO_TRANSPORT_EVENT_DIRECT_RDMA_COMPLETION
};

enum xio_transport_opt {
	XIO_TRANSPORT_OPT_MSG_ATTR,
};

enum xio_transport_attr_mask {
	XIO_TRANSPORT_ATTR_TOS			= 1 << 0,
};

/*---------------------------------------------------------------------------*/
/* unions and structs	                                                     */
/*---------------------------------------------------------------------------*/
union xio_transport_event_data {
	struct {
		struct xio_task		*task;
		enum xio_wc_op		op;
		int			pad;
	} msg;
	struct {
		struct xio_task		*task;
		int			is_assigned;
		int			pad;
	} assign_in_buf;
	struct {
		void			*ulp_msg;
		size_t			ulp_msg_sz;
		struct xio_task		*task;
		enum xio_status		result;
		int			pad;
	} cancel;
	struct {
		struct xio_transport_handle	*child_trans_hndl;
	} new_connection;
	struct {
		uint32_t	cid;
	} established;
	struct {
		struct xio_task		*task;
		enum xio_status		reason;
		enum xio_msg_direction	direction;
	} msg_error;
	struct {
		enum xio_status	reason;
	} error;
};

struct xio_tasks_pool_cls {
	void		*pool;
	struct xio_task * (*task_get)(void *pool, void *context);
	void		  (*task_put)(struct xio_task *task);

	struct xio_task	* (*task_lookup)(void *pool, int task_id);
};

/* LIANGPAN */
struct __attribute__((__packed__)) xio_rdma_setup_msg {
	uint16_t		credits;	/* peer send credits	*/
	uint16_t		sq_depth;
	uint16_t		rq_depth;
	uint16_t		rkey_tbl_size;
	uint64_t		buffer_sz;
	uint32_t		max_in_iovsz;
	uint32_t		max_out_iovsz;
	uint32_t                max_header_len;
	uint32_t		pad;
};

struct xio_work_req {
	union {
		struct ibv_send_wr	send_wr;
		struct ibv_recv_wr	recv_wr;
	};
	struct ibv_sge			*sge;
};
/* LIANGPAN */

struct xio_transport_attr {
	uint8_t			tos;		/**< type of service RFC 2474 */
	uint8_t			pad[3];		/**< padding		     */
};

struct xio_transport_init_attr {
	uint8_t			tos;		/**< type of service RFC 2474 */
	uint8_t			pad[3];		/**< padding		     */
};

struct xio_transport_handle {
	struct xio_observable		observable;
	uint32_t			is_client;  /* client or server */
	int				pad;
	char				*portal_uri;
	struct sockaddr_storage		peer_addr;
	struct sockaddr_storage		local_addr;
	enum   xio_proto		proto;
	struct kref			kref;
	struct xio_context		*ctx;
	struct xio_cq			*tcq;
	struct ibv_qp			*qp;
	struct xio_mempool		*rdma_mempool;
	struct xio_tasks_pool		*phantom_tasks_pool;

	struct list_head		trans_list_entry;

	/*  tasks queues */
	struct list_head		tx_ready_list;
	struct list_head		tx_comp_list;
	struct list_head		in_flight_list;
	struct list_head		rx_list;
	struct list_head		io_list;
	struct list_head		rdma_rd_req_list;
	struct list_head		rdma_rd_req_in_flight_list;
	struct list_head		rdma_rd_rsp_list;
	struct list_head		rdma_rd_rsp_in_flight_list;

		/* rx parameters */
	int				rq_depth;	 /* max rcv per qp
							    allowed */
	int				rqe_avail;	 /* recv queue elements
							    avail */
	uint16_t			sim_peer_credits;  /* simulates the peer
							    * credits management
							    * to control nop
							    * sends
							    */
	uint16_t			credits;	  /* the ack this
							     peer sends */
	uint16_t			peer_credits;

	uint16_t			pad1;
	uint32_t                        peer_max_header;

	/* fast path params */
	int				rdma_rd_req_in_flight;
	int				rdma_rd_rsp_in_flight;
	int				sqe_avail;
	enum xio_transport_state	state;

	/* tx parameters */
	int				kick_rdma_rd_req;
	int				kick_rdma_rd_rsp;
	int				reqs_in_flight_nr;
	int				rsps_in_flight_nr;
	int				tx_ready_tasks_num;
	int				max_tx_ready_tasks_num;
	int				max_inline_data;
	size_t				max_inline_buf_sz;
	int				max_sge;
	uint16_t			req_sig_cnt;
	uint16_t			rsp_sig_cnt;
	/* sender window parameters */
	uint16_t			sn;	   /* serial number */
	uint16_t			ack_sn;	   /* serial number */

	uint16_t			max_sn;	   /* upper edge of
						      sender's window + 1 */

	/* receiver window parameters */
	uint16_t			exp_sn;	   /* lower edge of
						      receiver's window */

	uint16_t			max_exp_sn; /* upper edge of
						       receiver's window + 1 */

	uint16_t			pad2;

	/* control path params */
	int				sq_depth;     /* max snd allowed  */
	uint16_t			client_initiator_depth;
	uint16_t			client_responder_resources;

	uint32_t			peer_max_in_iovsz;
	uint32_t			peer_max_out_iovsz;
	int32_t				handler_nesting;
	/* connection's flow control */
	size_t				membuf_sz;

	struct xio_cm_channel		*cm_channel;
	struct rdma_cm_id		*cm_id;
	struct xio_tasks_pool_cls	initial_pool_cls;
	struct xio_tasks_pool_cls	primary_pool_cls;

	struct xio_rdma_setup_msg	setup_rsp;

	/* for reconnect */
	struct xio_device		*dev;
	struct xio_rkey_tbl		*rkey_tbl;
	struct xio_rkey_tbl		*peer_rkey_tbl;

	/* for reconnect */
	uint16_t			rkey_tbl_size;
	uint16_t			peer_rkey_tbl_size;

	uint32_t			ignore_timewait:1;
	uint32_t			timewait_nr:1; /* flag */
	uint32_t			ignore_disconnect:1;
	uint32_t			disconnect_nr:1; /* flag */
	uint32_t                        beacon_sent:1;
	uint32_t			reserved:27;

	/* too big to be on stack - use as temporaries */
	union {
		struct xio_msg		dummy_msg;
		struct xio_work_req	dummy_wr;
	};
	struct xio_ev_data		close_event;
	struct xio_ev_data		timewait_exit_event;
	xio_delayed_work_handle_t	timewait_timeout_work;
	xio_delayed_work_handle_t	disconnect_timeout_work;
	struct ibv_send_wr		beacon;
	struct xio_task			beacon_task;
	uint32_t			trans_attr_mask;
	struct xio_transport_attr	trans_attr;
	struct xio_srq			*xio_srq;
	HT_ENTRY(rdma_hndl, xio_key_int32) rdma_hndl_htbl;
};

struct xio_tasks_pool_ops {
	void	(*pool_get_params)(struct xio_transport_handle *transport_hndl,
				   int *start_nr,
				   int *max_nr,
				   int *alloc_nr,
				   int *pool_dd_size,
				   int *slab_dd_size,
				   int *task_dd_size);

	int	(*slab_pre_create)(struct xio_transport_handle *trans_hndl,
				   int alloc_nr,
				   void *pool_dd_data, void *slab_dd_data);
	int	(*slab_destroy)(struct xio_transport_handle *trans_hndl,
				void *pool_dd_data, void *slab_dd_data);
	int	(*slab_init_task)(struct xio_transport_handle *trans_hndl,
				  void *pool_dd_data, void *slab_dd_data,
				  int tid, struct xio_task *task);
	int	(*slab_uninit_task)(struct xio_transport_handle *trans_hndl,
				    void *pool_dd_data, void *slab_dd_data,
				    struct xio_task *task);
	int	(*slab_remap_task)(struct xio_transport_handle *old_th,
				   struct xio_transport_handle *new_th,
				   void *pool_dd_data, void *slab_dd_data,
				   struct xio_task *task);
	int	(*slab_post_create)(struct xio_transport_handle *trans_hndl,
				    void *pool_dd_data, void *slab_dd_data);
	int	(*pool_pre_create)(struct xio_transport_handle *trans_hndl,
				   void *pool, void *pool_dd_data);
	int	(*pool_post_create)(struct xio_transport_handle *trans_hndl,
				    void *pool, void *pool_dd_data);
	int	(*pool_destroy)(struct xio_transport_handle *trans_hndl,
				void *pool, void *pool_dd_data);
	int	(*task_pre_put)(struct xio_transport_handle *trans_hndl,
				struct xio_task *task);
	int	(*task_post_get)(struct xio_transport_handle *trans_hndl,
				 struct xio_task *task);
};

char *xio_transport_state_str(enum xio_transport_state state);

struct xio_mempool *xio_transport_mempool_get(
		struct xio_context *ctx,
		int reg_mr);

/*---------------------------------------------------------------------------*/
/* xio_transport_reg_observer	                                             */
/*---------------------------------------------------------------------------*/
static inline void xio_transport_reg_observer(
		struct xio_transport_handle *trans_hndl,
		struct xio_observer *observer)
{
	xio_observable_reg_observer(&trans_hndl->observable, observer);
}

/*---------------------------------------------------------------------------*/
/* xio_transport_unreg_observer						     */
/*---------------------------------------------------------------------------*/
static inline void xio_transport_unreg_observer(
		struct xio_transport_handle *trans_hndl,
		struct xio_observer *observer)
{
	xio_observable_unreg_observer(&trans_hndl->observable, observer);
}

/*---------------------------------------------------------------------------*/
/* xio_transport_unreg_observer						     */
/*---------------------------------------------------------------------------*/
static inline void xio_transport_notify_observer(
		struct xio_transport_handle *trans_hndl,
		int event, void *event_data)
{
	xio_observable_notify_all_observers(&trans_hndl->observable,
					    event, event_data);
}

/*---------------------------------------------------------------------------*/
/* xio_transport_notify_observer_error					     */
/*---------------------------------------------------------------------------*/
static inline void xio_transport_notify_observer_error(
				struct xio_transport_handle *trans_hndl,
				int reason)
{
	union xio_transport_event_data ev_data = {};

	ev_data.error.reason = (enum xio_status)reason;

	xio_observable_notify_all_observers(&trans_hndl->observable,
					    XIO_TRANSPORT_EVENT_ERROR,
					    &ev_data);
}

/*---------------------------------------------------------------------------*/
/* xio_transport_notify_message_error					     */
/*---------------------------------------------------------------------------*/
static inline void xio_transport_notify_message_error(
				struct xio_transport_handle *trans_hndl,
				struct xio_task *task,
				enum xio_status reason)
{
	union xio_transport_event_data ev_data;

	ev_data.msg_error.task		= task;
	ev_data.msg_error.reason	= reason;

	xio_observable_notify_all_observers(&trans_hndl->observable,
					    XIO_TRANSPORT_EVENT_MESSAGE_ERROR,
					    &ev_data);
}

int xio_transport_flush_task_list(struct list_head *list);

int xio_transport_assign_in_buf(struct xio_transport_handle *trans_hndl,
				struct xio_task *task,
				int *is_assigned);

int xio_rdma_cancel_req(struct xio_transport_handle *transport,
			struct xio_msg *req, uint64_t stag,
			void *ulp_msg, size_t ulp_msg_sz);

int xio_rdma_cancel_rsp(struct xio_transport_handle *transport,
			struct xio_task *task, enum xio_status result,
			void *ulp_msg, size_t ulp_msg_sz);

/*---------------------------------------------------------------------------*/
/* rdma transport functions							     */
/*---------------------------------------------------------------------------*/
void xio_rdma_transport_constructor(void);
void xio_rdma_transport_destructor(void);
int xio_rdma_transport_init();
void xio_rdma_transport_release();
int xio_rdma_context_shutdown(struct xio_transport_handle *trans_hndl,
			struct xio_context *ctx);
int xio_rdma_connect(struct xio_transport_handle *trans_hndl,
			const char *portal_uri, const char *out_if_addr);
int xio_rdma_listen(struct xio_transport_handle *transport_hndl,
			const char *portal_uri,
			uint16_t *src_port, int backlog);
int xio_rdma_accept(struct xio_transport_handle *transport_hndl);
int xio_rdma_reject(struct xio_transport_handle *transport);
void xio_rdma_close(struct xio_transport_handle *transport);
int xio_rdma_dup2(struct xio_transport_handle *old_trans_hndl,
			struct xio_transport_handle **new_trans_hndl);
int xio_rdma_update_task(struct xio_transport_handle *transport_hndl,
			struct xio_task *task);
int xio_rdma_update_rkey(struct xio_transport_handle *transport_hndl,
			uint32_t *rkey);
int xio_rdma_send(struct xio_transport_handle *transport,
			struct xio_task *task);
int xio_rdma_set_opt(void *xio_obj,
			int optname, const void *optval, int optlen);
int xio_rdma_get_opt(void  *xio_obj,
			int optname, void *optval, int *optlen);
int xio_rdma_cancel_req(struct xio_transport_handle *transport,
			struct xio_msg *req, uint64_t stag,
			void *ulp_msg, size_t ulp_msg_sz);
int xio_rdma_cancel_rsp(struct xio_transport_handle *transport,
			struct xio_task *task, enum xio_status result,
			void *ulp_msg, size_t ulp_msg_sz);
void xio_rdma_set_pools_cls(
			struct xio_transport_handle *transport_hndl,
			struct xio_tasks_pool_cls *initial_pool_cls,
			struct xio_tasks_pool_cls *primary_pool_cls);
int xio_rdma_transport_modify(struct xio_transport_handle *transport_hndl,
			struct xio_transport_attr *attr,
			int attr_mask);
int xio_rdma_transport_query(struct xio_transport_handle *transport_hndl,
			struct xio_transport_attr *attr,
			int attr_mask);
int xio_rdma_is_valid_in_req(struct xio_msg *msg);
int xio_rdma_is_valid_out_msg(struct xio_msg *msg);

struct xio_transport_handle *xio_rdma_open(
	struct xio_context	*ctx,
	struct xio_observer	*observer,
	uint32_t		trans_attr_mask,
	struct xio_transport_init_attr *attr);

void xio_rdma_get_pools_ops(
	struct xio_transport_handle *trans_hndl,
	struct xio_tasks_pool_ops **initial_pool_ops,
	struct xio_tasks_pool_ops **primary_pool_ops);
#endif /*XIO_TRANSPORT_H */
