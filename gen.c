#define _GNU_SOURCE 1
#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef _cleanup_
#define _cleanup_(x) __attribute__((__cleanup__(x)))
#endif


static inline void free_ptr(void **pptr) {
        free (*pptr);
}

#define _cleanup_free_ _cleanup_(free_ptr)

#define steal_ptr(ptr) ({ typeof(ptr) tmp__ = (ptr); (ptr) = NULL;  tmp__; })


typedef struct P11Ctx {
        CK_FUNCTION_LIST *module;
        CK_SLOT_ID slot;

        /* */
        CK_TOKEN_INFO token;

        /* */
        CK_SESSION_HANDLE session;
} P11Ctx;

typedef struct MemPool {

        struct MemItem {
                void  *data;
                size_t len;
                int    flags;
        } *items;

        size_t count;
        size_t size;
} MemPool;

static void
mempool_init (MemPool *pool, size_t reserve)
{
        assert(pool != NULL);
        memset(pool, 0, sizeof(MemPool));

        pool->items = malloc(reserve * sizeof(struct MemItem));
        pool->size = reserve;

        fprintf(stderr, "pool[%p] init (%lu)\n", (void *) pool, reserve);
}

static void *
mempool_alloc(MemPool *pool, size_t size, int erase)
{
        size_t idx;
        void *data;

        assert(pool);

        if (pool->count == pool->size) {
                return NULL;
        }

        data = malloc(size);
        if (data == NULL)
                return NULL;

        idx = pool->count++;
        pool->items[idx].data = data;
        pool->items[idx].len = size;
        pool->items[idx].flags = erase;

        fprintf(stderr, "pool[%p] @ %lu alloc (%lu)\n", (void *) pool, idx, size);

        return data;
}

static void
mempool_cleanup(MemPool *pool)
{
        fprintf(stderr, "pool[%p] cleanup (%lu)\n", (void *) pool, pool->count);

        for (size_t i = 0; i < pool->count; i++) {
                struct MemItem *item = pool->items + i;
                if (item->flags)
                        explicit_bzero(item->data, item->len);
                free(item->data);
        }
        free(pool->items);
        pool->items = NULL;
        pool->size = pool->count = 0;
}

#define _cleanup_pool_ _cleanup_(mempool_cleanup)

static char *
mempool_vprintf(MemPool *pool, size_t *len, int erase, const char *fmt, va_list ap)
{
        void *buf = NULL;
        size_t n, k;

        va_list lst;
        va_copy(lst, ap);

        n = vsnprintf(buf, 0, fmt, ap);

        n++; //null byte
        buf = mempool_alloc(pool, n, erase);
        k = vsnprintf(buf, n, fmt, lst);

        assert (k < n);

        va_end(lst);

        if (len)
                *len = k;

        return buf;
}

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

static int
bignum_to_attr(const BIGNUM *num, CK_ATTRIBUTE *attr, MemPool *pool)
{
        int n, r;

        n = BN_num_bytes(num);

        attr->ulValueLen = n;
        attr->pValue = mempool_alloc(pool, n, 1);

        if (attr->pValue == NULL)
                return -ENOMEM;

        r = BN_bn2bin(num, attr->pValue);
        assert(r == n);

        return 0;
}

static int
attr_find( CK_ATTRIBUTE_TYPE type,
           CK_ATTRIBUTE *attrs,
           size_t n_attrs,
           CK_ATTRIBUTE **result)
{
        int count;

        if (n_attrs > INT_MAX)
                return -EOVERFLOW;

        count = (int) n_attrs;

        for (int i = 0; i < count; i++) {
                if (attrs[i].type == type) {
                        if (result)
                                *result = &attrs[i];
                        fprintf(stderr, "Found %i for %lx\n", i, (unsigned long) type);
                        return i;
                }
        }

        if (result)
                *result = NULL;

        return -ENOENT;
}

static int
bignum_to_attr_find(const BIGNUM *num,
                    CK_ATTRIBUTE_TYPE type,
                    CK_ATTRIBUTE *attrs,
                    size_t n_attrs,
                    MemPool *pool)
{
        CK_ATTRIBUTE *attr;
        int idx;

        idx = attr_find(type, attrs, n_attrs, &attr);
        if (idx < 0)
                return idx;

        return bignum_to_attr(num, attr, pool);
}

static int
attr_set_bool(CK_ATTRIBUTE_TYPE type,
              CK_BBOOL b,
              CK_ATTRIBUTE *attrs,
              size_t n_attrs)
{
        static CK_BBOOL yes = CK_TRUE;
        static CK_BBOOL no = CK_FALSE;
        CK_ATTRIBUTE *attr;
        int idx;

        idx = attr_find(type, attrs, n_attrs, &attr);
        if (idx < 0)
                return idx;

        attr->pValue = b ? &yes : &no;
        attr->ulValueLen = sizeof(CK_BBOOL);

        return 0;
}

static char *
attr_printf(CK_ATTRIBUTE *attr, MemPool *pool, const char *fmt, ...)
{
        void *buf = NULL;
        size_t len;

        if (attr == NULL)
                return NULL;

        va_list ap;
        va_start(ap, fmt);
        attr->pValue = mempool_vprintf(pool, &len, 0, fmt, ap);
        va_end(ap);

        if (attr->pValue == NULL)
                return NULL;

        attr->ulValueLen = (unsigned long) len;

        return buf;
}

int
p11ctx_import_keypair(P11Ctx *ctx, RSA *key, int id)
{
        _cleanup_pool_ MemPool pool = {NULL, 0, 0};
        CK_OBJECT_CLASS oklass = CKO_PRIVATE_KEY;
        CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
        CK_KEY_TYPE ktype = CKK_RSA;
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_BYTE keyid[2] = {0, };
        CK_ATTRIBUTE attrs[] = {
                {CKA_CLASS,            &oklass, sizeof(oklass)},
                {CKA_KEY_TYPE,         &ktype,  sizeof(ktype)},
                {CKA_TOKEN,            &yes,    sizeof(yes)},
                //{CKA_APPLICATION,      NULL,    0},
                {CKA_LABEL,            NULL,    0},
                {CKA_ID,               keyid,   sizeof(keyid)},
                //{CKA_SUBJECT,          NULL,    0},
                //{CKA_SENSITIVE,        &yes,    sizeof(yes)},
                //{CKA_PRIVATE,          &yes,    sizeof(yes)},
                //{CKA_EXTRACTABLE,      &no,     sizeof(no)},
                //{CKA_WRAP,             &no,     sizeof(no)},
                //{CKA_UNWRAP,           &yes,    sizeof(yes)},
                //{CKA_ENCRYPT,          &no,     sizeof(no)},
                //{CKA_VERIFY,           &no,     sizeof(no)},
                //{CKA_DECRYPT,          &yes,    sizeof(yes)},
                //{CKA_SIGN,             &yes,    sizeof(yes)},
                //{CKA_MODULUS,          NULL,    0},
                {CKA_PUBLIC_EXPONENT,  NULL,    0},
                /* End of public fields (N = 13)*/
                //{CKA_PRIVATE_EXPONENT, NULL,    0},
                {CKA_PRIME_1,          NULL,    0},
                {CKA_PRIME_2,          NULL,    0},
                {CKA_EXPONENT_1,       NULL,    0},
                {CKA_EXPONENT_2,       NULL,    0},
                {CKA_COEFFICIENT,      NULL,    0},
        };
        size_t nattr = sizeof(attrs)/sizeof(CK_ATTRIBUTE);
        CK_ATTRIBUTE *attr;
        const BIGNUM *n;
        const BIGNUM *e;
        const BIGNUM *d;
        const BIGNUM *p;
        const BIGNUM *q;
        const BIGNUM *dmp1;
        const BIGNUM *dmq1;
        const BIGNUM *iqmp;
        CK_RV rv;

        keyid[0] = (id >> 8) & 0xFF;
        keyid[1] = id & 0xFF;

        mempool_init(&pool, nattr);

        attr_find(CKA_APPLICATION, attrs, nattr, &attr);
        attr_printf(attr, &pool, "GNOME.org");

        attr_find(CKA_LABEL, attrs, nattr, &attr);
        attr_printf(attr, &pool, "TheKey");

        RSA_get0_key(key, &n, &e, &d);
        RSA_get0_factors(key, &p, &q);
        RSA_get0_crt_params(key, &dmp1, &dmq1, &iqmp);

        //bignum_to_attr_find(n, CKA_MODULUS, attrs, nattr, &pool);
        bignum_to_attr_find(e, CKA_PUBLIC_EXPONENT, attrs, nattr, &pool);

        //bignum_to_attr_find(d, CKA_PRIVATE_EXPONENT, attrs, nattr, &pool);

        bignum_to_attr_find(p, CKA_PRIME_1, attrs, nattr, &pool);
        bignum_to_attr_find(q, CKA_PRIME_2, attrs, nattr, &pool);

        bignum_to_attr_find(dmp1, CKA_EXPONENT_1, attrs, nattr, &pool);
        bignum_to_attr_find(dmq1, CKA_EXPONENT_2, attrs, nattr, &pool);
        bignum_to_attr_find(iqmp, CKA_COEFFICIENT, attrs, nattr, &pool);

        for (size_t i = 0; i < nattr; i++) {
                fprintf(stderr, "%lu: %lu %lu %p\n", i, attrs[i].type, attrs[i].ulValueLen, attrs[i].pValue);
        }

        /* Private Key */
        rv = ctx->module->C_CreateObject(ctx->session, attrs, nattr, &priv);
        if (rv != CKR_OK) {
                fprintf(stderr, "Failed to create private key [0x%lx]\n", rv);
                return -EIO;
        }

#if 0 /* Yubikey only supports importing private key */
        /* public key field adjustments */
        oklass = CKO_PUBLIC_KEY;
        attr_set_bool(CKA_SENSITIVE,   CK_FALSE, attrs, nattr);
        attr_set_bool(CKA_PRIVATE,     CK_FALSE, attrs, nattr);
        attr_set_bool(CKA_EXTRACTABLE, CK_TRUE,  attrs, nattr);
        attr_set_bool(CKA_WRAP,        CK_TRUE,  attrs, nattr);
        attr_set_bool(CKA_UNWRAP,      CK_FALSE, attrs, nattr);
        attr_set_bool(CKA_ENCRYPT,     CK_TRUE,  attrs, nattr);
        attr_set_bool(CKA_VERIFY,      CK_TRUE,  attrs, nattr);
        attr_set_bool(CKA_DECRYPT,     CK_FALSE, attrs, nattr);
        attr_set_bool(CKA_SIGN,        CK_FALSE, attrs, nattr);

        rv = ctx->module->C_CreateObject(ctx->session, attrs, nattr - 6, &pub);
        if (rv != CKR_OK) {
                fprintf(stderr, "Failed to create public key [0x%lx]\n", rv);
                (void) ctx->module->C_DestroyObject(ctx->session, priv);
                return -EIO;
        }
#endif

        return 0;
}

int
p11ctx_import_cert(P11Ctx *ctx, X509 *cert, int id)
{
        CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
        CK_OBJECT_CLASS oklass = CKO_CERTIFICATE;
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
        CK_BYTE keyid[2] = {0, };
        CK_ATTRIBUTE *attr;
        CK_ATTRIBUTE attrs[] = {
                {CKA_CLASS,            &oklass, sizeof(oklass)},
                {CKA_TOKEN,            &yes,    sizeof(yes)},
                {CKA_LABEL,            NULL,    0},
                {CKA_ID,               keyid,   sizeof(keyid)},
                {CKA_SUBJECT,          NULL,    0},
                {CKA_PRIVATE,          &yes,    sizeof(yes)},
                {CKA_VALUE,            NULL,    0}
        };
        size_t nattr = sizeof(attrs)/sizeof(CK_ATTRIBUTE);
        CK_RV rv;
        CK_BYTE *p = NULL;
        CK_BYTE *buf = NULL;
        int len;

        keyid[0] = (id >> 8) & 0xFF;
        keyid[1] = id & 0xFF;

        attr_find(CKA_VALUE, attrs, nattr, &attr);

        len = i2d_X509(cert, NULL);
        if (len < 0)
                return -EIO;

        buf = OPENSSL_malloc(len);
        p = buf;
        len = i2d_X509(cert, &p);

        fprintf(stderr, "cert size: %i %p %p\n", len, (void *) buf, (void *) p);

        attr->ulValueLen = len;
        attr->pValue = (void *) buf;

        for (size_t i = 0; i < nattr; i++) {
                fprintf(stderr, "%lu: %lu %lu %p\n", i, attrs[i].type, attrs[i].ulValueLen, attrs[i].pValue);
        }

        /* Private Key */
        rv = ctx->module->C_CreateObject(ctx->session, attrs, nattr, &h);
        OPENSSL_free(buf);

        if (rv != CKR_OK) {
                fprintf(stderr, "Failed to import cert [0x%lx]\n", rv);
                return -EIO;
        }

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

    r = EVP_PKEY_assign_RSA(pkey, rsa);
    if (r != 1) {
            return NULL;
    }

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

        if (r == 1) {
                r = fclose(f);
                if (r != 0)
                        r = -errno;
        } else {
                (void) fclose(f);
                r = -EIO;
        }

        return r;
}

static CK_FUNCTION_LIST **
load_module(const char *path, int flags)
{
        CK_FUNCTION_LIST **modules;
        CK_RV rv;

        modules = malloc(sizeof(CK_FUNCTION_LIST) * 2);
        memset(modules, 0, sizeof(CK_FUNCTION_LIST) * 2);

        modules[0] = p11_kit_module_load (path, flags);
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

        p11_kit_be_loud();

        modules = load_module("/home/gicmo/Code/src/p11-spielpatz/libykcs11.so", 0);

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
                r = p11ctx_login(&ctx, CKU_SO, "010203040506070801020304050607080102030405060708");
                if (r != 0) {
                        fprintf(stderr, "Could not login\n");
                        return EXIT_SUCCESS;
                }
        }

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

        printf("Importing keys\n");
        r = p11ctx_import_keypair(&ctx, key, 1);
        if (r)
                return EXIT_FAILURE;

        printf("Importing cert\n");
        r = p11ctx_import_cert(&ctx, cert, 1);

        if (r)
                return EXIT_FAILURE;

        ctx.module->C_CloseSession(ctx.session);
        p11_kit_modules_finalize_and_release(modules);

        return EXIT_SUCCESS;
}
