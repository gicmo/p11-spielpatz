#include <common.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


CK_FUNCTION_LIST **
p11_load_module(const char *path, int flags)
{
        CK_FUNCTION_LIST **modules;
        CK_RV rv;

        modules = malloc(sizeof(CK_FUNCTION_LIST) * 2);
        memset(modules, 0, sizeof(CK_FUNCTION_LIST) * 2);

        modules[0] = p11_kit_module_load(path, flags);
        if (modules[0] == NULL)
                return modules;

        rv = p11_kit_module_initialize(modules[0]);
        if (rv != CKR_OK) {
                p11_kit_module_release(modules[0]);
                modules[0] = NULL;
        }

        return modules;
}

int
p11ctx_find_token(CK_FUNCTION_LIST **modules,
                  P11Ctx *ctx,
                  P11KitUri *uri)
{
        assert(modules != NULL);
        assert(ctx != NULL);
        assert(uri != NULL);

         for (CK_FUNCTION_LIST **l = modules; *l; l++) {
                 CK_FUNCTION_LIST *m = *l;
                 CK_SLOT_ID slotids[256];
                 CK_ULONG count = sizeof(slotids) / sizeof(CK_SLOT_ID);
                 CK_INFO info;
                 CK_RV rv;
                 int r;

                 r = p11_kit_uri_match_module_info(uri, &info);
                 if (r == 0)
                         continue;

                  rv = m->C_GetSlotList(0, slotids, &count);
                  if (rv != CKR_OK) {
                          fprintf(stderr, "GetSlotList failed\n");
                          continue;
                  }

                  ctx->module = m;

                  for (CK_ULONG i = 0; i < count; i++) {
                          CK_SLOT_INFO slot;
                          CK_TOKEN_INFO token;

                          rv = m->C_GetSlotInfo(slotids[i], &slot);
                          if (rv != CKR_OK) {
                                  fprintf(stderr, "GetSlotInfo failed\n");
                                  continue;
                          }

                          r = p11_kit_uri_match_slot_info(uri, &slot);
                          if (r == 0)
                                  continue;

                          ctx->slot = slotids[i];

                          rv = m->C_GetTokenInfo(slotids[i], &token);

                          if (rv != CKR_OK) {
                                  fprintf(stderr, "GetTokenInfo failed\n");
                                  continue;
                          }

                          r = p11_kit_uri_match_token_info(uri, &token);
                          if (r == 1) {
                                  /* we have a full match! */
                                  memcpy(&ctx->token, &token, sizeof(token));
                                  return 0;
                          }
                  }
         }

         return -ENOENT;
}

int
p11ctx_open_session(P11Ctx *ctx, int rw)
{
        CK_RV rv;
        CK_FLAGS flags;

        flags = CKF_SERIAL_SESSION;

        if (rw)
                flags |= CKF_RW_SESSION;

        rv = ctx->module->C_OpenSession(ctx->slot, flags, NULL, NULL, &ctx->session);

        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
                return -EIO;
        }

        return 0;
}

int
p11ctx_login(P11Ctx *ctx, CK_USER_TYPE utype, const char *pin)
{
        char *tmp = NULL;
        CK_RV rv;
        CK_ULONG len;

        if (pin == NULL) {
                tmp = getpass("PIN: ");
                pin = tmp;
        }

        if (pin == NULL)
                return CKR_CANCEL;

        len = strlen(pin);
        fprintf(stderr, "Login [pinlen: %lu]\n", len);

        rv = ctx->module->C_Login(ctx->session, utype, (unsigned char *) pin, len);
        free(tmp);

        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
                return -EIO;

        return 0;
}
