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
#ifndef XIO_COMMON_TRANSPORT_H
#define XIO_COMMON_TRANSPORT_H

#include "xio_transport.h"

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
struct xio_mr {
	void				*addr;  /* for new devices */
	size_t				length; /* for new devices */
	int				access; /* for new devices */
	int				addr_alloced;	/* address was
							   allocated by xio */
	struct list_head		dm_list;
	struct list_head		mr_list_entry;
};

struct xio_mempool *xio_transport_mempool_get(
		struct xio_context *ctx,
		int reg_mr);

char *xio_transport_state_str(enum xio_transport_state state);

#endif  /* XIO_COMMON_TRANSPORT_H */
