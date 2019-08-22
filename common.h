#pragma once


#define _GNU_SOURCE 1
#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>

#include <stdlib.h>

#ifndef _cleanup_
#define _cleanup_(x) __attribute__((__cleanup__(x)))
#endif


static inline void free_ptr(void **pptr) {
        free (*pptr);
}

#define _cleanup_free_ _cleanup_(free_ptr)

#define steal_ptr(ptr) ({ typeof(ptr) tmp__ = (ptr); (ptr) = NULL;  tmp__; })


CK_FUNCTION_LIST **  p11_load_module(const char *path, int flags);


typedef struct P11Ctx {
        CK_FUNCTION_LIST *module;
        CK_SLOT_ID slot;

        /* */
        CK_TOKEN_INFO token;

        /* */
        CK_SESSION_HANDLE session;
} P11Ctx;

int   p11ctx_find_token(CK_FUNCTION_LIST **modules,
                        P11Ctx *ctx,
                        P11KitUri *uri);

int   p11ctx_open_session(P11Ctx *ctx, int rw);

int   p11ctx_login(P11Ctx *ctx, CK_USER_TYPE utype, const char *pin);
