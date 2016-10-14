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
#include "libxio.h"
#include <xio_os.h>
#include "xio_log.h"
#include "xio_common.h"
#include "xio_mbuf.h"
#include "xio_task.h"
#include "xio_observer.h"
#include "xio_transport.h"
#include "xio_context.h"
#include "xio_mempool.h"

/*---------------------------------------------------------------------------*/
/* xio_transport_flush_task_list					     */
/*---------------------------------------------------------------------------*/
int xio_transport_flush_task_list(struct list_head *list)
{
	struct xio_task *ptask, *next_ptask;

	list_for_each_entry_safe(ptask, next_ptask, list,
				 tasks_list_entry) {
		/*
		TRACE_LOG("flushing task %p type 0x%x\n",
			  ptask, ptask->tlv_type);
		*/
		if (ptask->sender_task) {
			xio_tasks_pool_put(ptask->sender_task);
			ptask->sender_task = NULL;
		}
		xio_tasks_pool_put(ptask);
	}

	return 0;
}
EXPORT_SYMBOL(xio_transport_flush_task_list);

/*---------------------------------------------------------------------------*/
/* xio_transport_assign_in_buf						     */
/*---------------------------------------------------------------------------*/
int xio_transport_assign_in_buf(struct xio_transport_handle *trans_hndl,
				struct xio_task *task, int *is_assigned)
{
	union xio_transport_event_data event_data = {};

	event_data.assign_in_buf.task = task;

	xio_transport_notify_observer(trans_hndl,
				      XIO_TRANSPORT_EVENT_ASSIGN_IN_BUF,
				      &event_data);

	*is_assigned = event_data.assign_in_buf.is_assigned;
	return 0;
}
EXPORT_SYMBOL(xio_transport_assign_in_buf);

/*---------------------------------------------------------------------------*/
/* xio_transport_mempool_get						     */
/*---------------------------------------------------------------------------*/
struct xio_mempool *xio_transport_mempool_get(
		struct xio_context *ctx, int reg_mr)
{
	if (ctx->mempool)
		return (struct xio_mempool *)ctx->mempool;

        /* user asked to force registration and rdma exist on machine*/
	xio_rdma_transport_init();
        if (ctx->register_internal_mempool)
                reg_mr = 1;

	ctx->mempool = xio_mempool_create_prv(
			ctx->nodeid,
			(reg_mr ? XIO_MEMPOOL_FLAG_REG_MR : 0) |
			XIO_MEMPOOL_FLAG_HUGE_PAGES_ALLOC);

	if (!ctx->mempool) {
		ERROR_LOG("xio_mempool_create failed (errno=%d %m)\n", errno);
		return NULL;
	}
	return (struct xio_mempool *)ctx->mempool;
}

/*---------------------------------------------------------------------------*/
/* xio_transport_state_str						     */
/*---------------------------------------------------------------------------*/
char *xio_transport_state_str(enum xio_transport_state state)
{
	switch (state) {
	case XIO_TRANSPORT_STATE_INIT:
		return "INIT";
	case XIO_TRANSPORT_STATE_LISTEN:
		return "LISTEN";
	case XIO_TRANSPORT_STATE_CONNECTING:
		return "CONNECTING";
	case XIO_TRANSPORT_STATE_CONNECTED:
		return "CONNECTED";
	case XIO_TRANSPORT_STATE_DISCONNECTED:
		return "DISCONNECTED";
	case XIO_TRANSPORT_STATE_RECONNECT:
		return "RECONNECT";
	case XIO_TRANSPORT_STATE_CLOSED:
		return "CLOSED";
	case XIO_TRANSPORT_STATE_DESTROYED:
		return "DESTROYED";
	case XIO_TRANSPORT_STATE_ERROR:
		return "ERROR";
	default:
		return "UNKNOWN";
	}

	return NULL;
};
