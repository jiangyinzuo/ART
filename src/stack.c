// Copyright (c) 2021, Jiang Yinzuo. All rights reserved.

// art_stack refers to Redis's raxStack

/* Rax -- A radix tree implementation.
 *
 * Version 1.2 -- 7 February 2019
 *
 * Copyright (c) 2017-2019, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
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

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "art/stack.h"

/* ------------------------- art_stack functions --------------------------
 * The art_stack is a simple stack of pointers that is capable of switching
 * from using a stack-allocated array to dynamic heap once a given number of
 * items are reached. It is used in order to retain the list of parent nodes
 * while walking the radix tree in order to implement certain operations that
 * need to navigate the tree upward.
 * ------------------------------------------------------------------------- */

/* Initialize the stack. */
void art_stack_init(art_stack *ts) {
    ts->stack = ts->static_items;
    ts->items = 0;
    ts->maxitems = ART_STACK_STATIC_ITEMS;
    ts->oom = false;
}

/* Push an item into the stack, returns 1 on success, 0 on out of memory. */
bool art_stack_push(art_stack *ts, art_stack_elem ptr) {
    if (ts->items == ts->maxitems) {
        if (ts->stack == ts->static_items) {
            ts->stack = malloc(sizeof(art_stack_elem) * ts->maxitems * 2);
            if (ts->stack == NULL) {
                ts->stack = ts->static_items;
                ts->oom = true;
                errno = ENOMEM;
                return false;
            }
            memcpy(ts->stack, ts->static_items,
                   sizeof(art_stack_elem) * ts->maxitems);
        } else {
            art_stack_elem *newalloc =
                realloc(ts->stack, sizeof(art_stack_elem) * ts->maxitems * 2);
            if (newalloc == NULL) {
                ts->oom = true;
                errno = ENOMEM;
                return false;
            }
            ts->stack = newalloc;
        }
        ts->maxitems *= 2;
    }
    ts->stack[ts->items] = ptr;
    ts->items++;
    return true;
}

bool art_stack_append(art_stack *ts, const art_stack_elem *elems, size_t len) {
    if (ts->items + len > ts->maxitems) {
        ts->maxitems = (ts->items + len) * 2;
        if (ts->stack == ts->static_items) {
            ts->stack = malloc(sizeof(art_stack_elem) * ts->maxitems);
            if (ts->stack == NULL) {
                ts->stack = ts->static_items;
                ts->oom = true;
                errno = ENOMEM;
                return false;
            }
            memcpy(ts->stack, ts->static_items,
                   sizeof(art_stack_elem) * ts->items);
        } else {
            art_stack_elem *newalloc =
                realloc(ts->stack, sizeof(art_stack_elem) * ts->maxitems);
            if (newalloc == NULL) {
                ts->oom = true;
                errno = ENOMEM;
                return false;
            }
            ts->stack = newalloc;
        }
    }
    memcpy(ts->stack + ts->items, elems, sizeof(art_stack_elem) * len);
    ts->items += len;
    return true;
}

/* Pop an item from the stack, the function returns NULL if there are no
 * items to pop. */
art_stack_elem art_stack_pop(art_stack *ts) {
    if (ts->items == 0)
        return 0;
    ts->items--;
    return ts->stack[ts->items];
}

void art_stack_popn(art_stack *ts, size_t n) {
    assert(ts->items >= n);
    ts->items -= n;
}

/* Return the stack item at the top of the stack without actually consuming
 * it. */
art_stack_elem art_stack_peek(art_stack *ts) {
    if (ts->items == 0)
        return 0;
    return ts->stack[ts->items - 1];
}

/* Free the stack in case we used heap allocation. */
void art_stack_free(art_stack *ts) {
    if (ts->stack != ts->static_items)
        free(ts->stack);
}
