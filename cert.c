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
generate_x509(EVP_PKEY *pkey)
{
    X509 *x509 = X509_new();
    X509_NAME *name;
    int r;

    if(!x509)
            return NULL;

    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    r = X509_set_pubkey(x509, pkey);
    if (!r) {
            X509_free(x509);
            return NULL;
    }

    name = X509_NAME_new();
    //name = X509_get_subject_name(x509);

    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"CA",        -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"GNOME.org", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"SSH Key",   -1, -1, 0);

    X509_set_issuer_name(x509, name);
    X509_set_subject_name(x509, name);

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
write_privkey(EVP_PKEY *pkey, const char *path)
{
        FILE *f;
        int r;

        f = fopen(path, "wb+");
        r = PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);

        if (r == 1) {
                r = fclose(f);
                if (r != 0)
                        r = -errno;
        } else {
                (void) fclose(f);
                r = -EIO;
        }

        return 0;
}

static int
write_x509(X509 *cert, const char *path)
{
        FILE *f = NULL;
        int r;

        f = fopen(path, "wb+");
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

int
main(int argc, char **argv)
{
        EVP_PKEY *pair;
        X509 *cert;
        RSA *key;
        int r;

        printf("Generating key pair\n");
        pair = generate_key();
        if (pair == NULL)
                return EXIT_FAILURE;

        printf("Generating certificate\n");
        cert = generate_x509(pair);
        if (cert == NULL)
                return EXIT_FAILURE;

        key = EVP_PKEY_get1_RSA(pair);

        r = write_privkey(pair, "private.pem");
        if (r)
                return EXIT_FAILURE;

        r = write_x509(cert, "cert.pem");
        if (r)
                return EXIT_FAILURE;

        return EXIT_SUCCESS;
}
