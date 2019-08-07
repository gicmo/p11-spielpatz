#define _GNU_SOURCE 1
#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef _cleanup_
#define _cleanup_(x) __attribute__((__cleanup__(x ## __cleanup)))
#endif

#define steal_ptr(ptr) ({ typeof(ptr) tmp__ = (ptr); (ptr) = NULL;  tmp__; })


typedef struct P11Ctx {
        CK_FUNCTION_LIST *module;
        CK_SLOT_ID slot;

        /* */
        CK_TOKEN_INFO token;

        /* */
        CK_SESSION_HANDLE session;
} P11Ctx;

static int
p11ctx_find_token (CK_FUNCTION_LIST **modules,
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
p11ctx_login(P11Ctx *ctx, const char *pin)
{
        char *tmp = NULL;
        CK_RV rv;

        if (pin == NULL) {
                tmp = getpass("PIN: ");
                pin = tmp;
        }

        if (pin == NULL)
                return CKR_CANCEL;

        rv = ctx->module->C_Login(ctx->session, CKU_USER, (unsigned char *) pin, strlen(pin));
        free(tmp);

        if (rv != CKR_OK)
                return -EIO;

        return 0;
}

int
p11ctx_import_keypair (RSA *key)
{
        CK_OBJECT_CLASS oklass = CKO_PUBLIC_KEY;
        CK_KEY_TYPE ktype = CKK_RSA;
        CK_UTF8CHAR *app = NULL;
        CK_UTF8CHAR *label = NULL;
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_BYTE *subject = NULL;
        CK_BYTE *keyid = NULL;
        CK_BYTE *modulus = NULL;
        CK_BYTE *pubexp = NULL;
        CK_BYTE *privexp = NULL;
        CK_BYTE *prime1 = NULL;
        CK_BYTE *prime2 = NULL;
        CK_BYTE *exp1 = NULL;
        CK_BYTE *exp2 = NULL;
        CK_BYTE *coeff = NULL;
        CK_ATTRIBUTE attrs[] = {
                {CKA_CLASS,            &oklass, sizeof(oklass)},
                {CKA_TOKEN,            &yes,    sizeof(yes)},
                {CKA_LABEL,            label,   0},
                {CKA_LABEL,            app,     0},
                {CKA_KEY_TYPE,         &ktype,  sizeof(ktype)},
                {CKA_ID,               keyid,   0},
                {CKA_SUBJECT,          subject, 0},
                {CKA_SENSITIVE,        &yes,    sizeof(yes)},
                {CKA_WRAP,             &yes,    sizeof(yes)},
                {CKA_ENCRYPT,          &yes,    sizeof(yes)},
                {CKA_DECRYPT,          &no,     sizeof(no)},
                {CKA_SIGN,             &no,     sizeof(no)},
                {CKA_MODULUS,          modulus, 0},
                {CKA_PUBLIC_EXPONENT,  pubexp,  0},
                /* End of public fields (N = 13)*/
                {CKA_PRIVATE_EXPONENT, privexp, 0},
                {CKA_PRIME_1,          prime1,  0},
                {CKA_PRIME_2,          prime2,  0},
                {CKA_EXPONENT_1,       exp1,    0},
                {CKA_EXPONENT_2,       exp2,    0},
                {CKA_COEFFICIENT,      coeff,   0},
        };

        return 0;
}

static EVP_PKEY *
generate_key()
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    int size = 2048;
    int r;

    if(!pkey || !rsa || !e)
            return NULL;

    BN_set_word(e, RSA_F4);

    r = RSA_generate_key_ex(rsa, size, e, NULL);
    if (r != 1) {
            return NULL;
    }

    BN_free(e);

    r = EVP_PKEY_set1_RSA(pkey, rsa);
    if (r != 1) {
            return NULL;
    }

    RSA_free(rsa);

    return pkey;
}

/* Generates a self-signed x509 certificate. */
static X509 *
generate_x509(EVP_PKEY * pkey)
{
    X509 *x509 = X509_new();
    X509_NAME *name;

    if(!x509)
            return NULL;

    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    //    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    X509_set_pubkey(x509, pkey);

    name = X509_get_subject_name(x509);

    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"CA",        -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"GNOME.org", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"SSH Key",   -1, -1, 0);

    X509_set_issuer_name(x509, name);

    if(!X509_sign(x509, pkey, EVP_sha1())) {
        X509_free(x509);
        return NULL;
    }

    return x509;
}

static int
write_pubkey(RSA *key, const char *path)
{
        BIO *f = NULL;
        int r;

        f = BIO_new_file(path, "w+");
        r = PEM_write_bio_RSAPublicKey(f, key);

        BIO_free_all (f);

        return r != 1 ? -EIO : 0;
}

static int
write_privkey(RSA *key, const char *path)
{
        BIO *f = NULL;
        int r;

        f = BIO_new_file(path, "w+");
        r = PEM_write_bio_RSAPrivateKey(f, key, NULL, NULL, 0, NULL, NULL);

        BIO_free_all (f);

        return r != 1 ? -EIO : 0;
}

static int
write_x509(X509 *cert, const char *path)
{
        FILE *f = NULL;
        int r;

        f = fopen(path, "w+");
        if (f == NULL)
                return -errno;

        r = PEM_write_X509(f, cert);

        if (r == 1)
                r = fclose(f);
        else
                (void) fclose(f);

        return r != 1 ? -EIO : 0;
}

int
main(int argc, char **argv)
{
        CK_FUNCTION_LIST **modules;
        P11Ctx ctx;
        P11KitUri *uri;
        EVP_PKEY *pair;
        X509 *cert;
        RSA *key;
        int r;

        if (argc < 2) {
                fprintf(stderr, "usage: %s URI\n", argv[0]);
                return EXIT_FAILURE;
        }

        uri = p11_kit_uri_new();
        r = p11_kit_uri_parse(argv[1], P11_KIT_URI_FOR_ANY, uri);
        if (r != P11_KIT_URI_OK) {
                fprintf(stderr, "Could not parse URI: %s: %s\n",
                        argv[1], p11_kit_uri_message(r));
                return EXIT_FAILURE;
        }

        modules = p11_kit_modules_load_and_initialize(0);

        r = p11ctx_find_token(modules, &ctx, uri);
        if (r != 0) {
                fprintf(stderr, "Could not find token for uri\n");
                return EXIT_SUCCESS;
        }

        r = p11ctx_open_session(&ctx, 1);
        if (r != 0) {
                fprintf(stderr, "Could not open pkcs11 session\n");
                return EXIT_SUCCESS;
        }

        printf("Found token\n");
        if (ctx.token.flags & CKF_LOGIN_REQUIRED) {
                printf("Token needs login\n");
                r = p11ctx_login(&ctx, NULL);
                if (r != 0) {
                        fprintf(stderr, "Could not login\n");
                        return EXIT_SUCCESS;
                }
        }

        return EXIT_SUCCESS;

        printf("Generating key pair\n");
        pair = generate_key();
        if (pair == NULL)
                return EXIT_FAILURE;

        printf("Generating certificate\n");
        cert = generate_x509(pair);
        if (cert == NULL)
                return EXIT_FAILURE;

        key = EVP_PKEY_get1_RSA(pair);
        r = write_pubkey(key, "public.pem");
        if (r)
                return EXIT_FAILURE;

        r = write_privkey(key, "private.pem");
        if (r)
                return EXIT_FAILURE;

        r = write_x509(cert, "cert.pem");
        if (r)
                return EXIT_FAILURE;





        return EXIT_SUCCESS;
}
