#define _GNU_SOURCE 1
#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>

#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *
cleanup_str(const unsigned char *s, size_t l, char *buf, size_t n)
{
        while (l > 0 && isspace(buf[l - 1]))
                l--;

        if (n < l)
                l = n;

        memcpy(buf, s, l - 1);
        buf[l] = '\0';

        return buf;
}
#define get_str(field, buf) (cleanup_str((field), sizeof(field), (buf), sizeof(buf)))

static inline void
dump_version (CK_VERSION *version)
{
        printf("%hhu.%hhu", version->major, version->minor);
}

#define yesno(x) ((!!(x)) ? "yes" : "no")

static void
dump_slot_info (CK_SLOT_INFO *slot)
{

        printf("%.*s\n", (int) sizeof(slot->slotDescription), slot->slotDescription);
        printf(" Manufacturer: %.*s\n", (int) sizeof(slot->manufacturerID), slot->manufacturerID);
        printf(" Flags: 0x%lX\n", slot->flags);
        printf("   Removable: ");
                if (slot->flags & CKF_REMOVABLE_DEVICE) {
                        printf("yes, present: %s\n", yesno(slot->flags & CKF_TOKEN_PRESENT));
                } else {
                        printf("no\n");
                }
        printf("   HW Slot: %s\n", yesno(slot->flags & CKF_HW_SLOT));
        printf(" Hardware version: ");
        dump_version(&slot->hardwareVersion);
        printf("\n");
        printf(" Firmware version: ");
        dump_version(&slot->firmwareVersion);
        printf("\n");
}

static inline int
token_requires_login(CK_TOKEN_INFO *token)
{
        return token->flags & CKF_LOGIN_REQUIRED;
}

static void
dump_token_info (CK_TOKEN_INFO *token, const char *prefix)
{
        char buf[128];

        printf("%s Name: %s\n", prefix, get_str (token->label, buf));
        printf("%s Manufacturer: %s\n", prefix, get_str (token->manufacturerID, buf));
        printf("%s Model: %s\n", prefix, get_str (token->model, buf));
        printf("%s Serial: %s\n", prefix, get_str (token->serialNumber, buf));
        printf("%s Flags: 0x%lX\n", prefix, token->flags);
        printf("%s   Login Required: %s\n", prefix, yesno(token->flags & CKF_LOGIN_REQUIRED));
        printf("%s Hardware version: ", prefix);
        dump_version(&token->hardwareVersion);
        printf("\n");
        printf("%s Firmware version: ", prefix);
        dump_version(&token->firmwareVersion);
        printf("\n");
        printf("%s UTC Time: %s\n", prefix, get_str (token->utcTime, buf));
}

static CK_RV
report_error(CK_RV rv, const char *function)
{
        if (rv == CKR_OK)
                return CKR_OK;

        fprintf(stderr, "%s error: %s", function,
                p11_kit_strerror (rv));

        return rv;
}

static const char *
object_class_to_str(CK_OBJECT_CLASS klass)
{
        switch (klass) {
        case CKO_DATA:
                return "data";
        case CKO_CERTIFICATE:
                return "certificate";
        case CKO_PUBLIC_KEY:
                return "public key";
        case CKO_PRIVATE_KEY:
                return "private key";
        case CKO_SECRET_KEY:
                return "secret key";
        case CKO_HW_FEATURE:
                return "hw feature";
        case CKO_DOMAIN_PARAMETERS:
                return "domain parameters";
        case CKO_MECHANISM:
                return "mechanism";
        case CKO_OTP_KEY:
                return "opt key";
        case CKO_VENDOR_DEFINED:
                return "vendor defined";
        }

        return "unknown";
}

static const char *
cert_type_to_str(CK_CERTIFICATE_TYPE ct)
{
        switch (ct) {
        case CKC_X_509:
                return "X.509";
        case CKC_X_509_ATTR_CERT:
                return "X.509 attribute";
        case CKC_WTLS:
                return "WTLS";
        case CKC_OPENPGP:
                return "OpenPGP";
        }

        if (ct & CKC_VENDOR_DEFINED)
                return "vendor defined";

        return "unknown";
}

static void
dump_attributes (CK_ATTRIBUTE *attrs, size_t nattrs, const char *prefix)
{
        for (size_t i = 0; i < nattrs; i++) {
                CK_ATTRIBUTE *attr = attrs + i;

                if (attr->ulValueLen == CK_UNAVAILABLE_INFORMATION)
                        continue;

                switch (attr->type) {
                case CKA_CLASS: {
                        CK_OBJECT_CLASS klass;
                        memcpy(&klass, attr->pValue, sizeof(klass));
                        printf("%s Class: %s [0x%lX]\n", prefix, object_class_to_str(klass), klass);
                        break;
                }

                case CKA_TOKEN: {
                        CK_BBOOL is_token = CK_FALSE;
                        memcpy(&is_token, attr->pValue, sizeof(is_token));
                        printf("%s Token: %s\n", prefix, yesno(is_token));
                        break;
                }

                case CKA_LABEL: {
                        CK_UTF8CHAR *label = (CK_UTF8CHAR *) attr->pValue;
                        printf("%s Label: %s\n", prefix, label);
                        break;
                }

                case CKA_APPLICATION: {
                        CK_UTF8CHAR *str = (CK_UTF8CHAR *) attr->pValue;
                        printf("%s Application: %s\n", prefix, str);
                        break;
                }

                case CKA_CERTIFICATE_TYPE: {
                        CK_CERTIFICATE_TYPE certtype = 0;
                        memcpy(&certtype, attr->pValue, sizeof(certtype));
                        printf("%s Certificate: %s\n", prefix, cert_type_to_str(certtype));
                        break;
                }

                case CKA_URL: {
                        CK_UTF8CHAR *str = (CK_UTF8CHAR *) attr->pValue;
                        printf("%s URL: %s\n", prefix, str);
                        break;
                }

                case CKA_SIGN: {
                        CK_BBOOL yn = CK_FALSE;
                        memcpy(&yn, attr->pValue, sizeof(yn));
                        printf("%s Sign: %s\n", prefix, yesno(yn));
                        break;
                }

                case CKA_ENCRYPT: {
                        CK_BBOOL yn = CK_FALSE;
                        memcpy(&yn, attr->pValue, sizeof(yn));
                        printf("%s Encrypt: %s\n", prefix, yesno(yn));
                        break;
                }

                case CKA_DECRYPT: {
                        CK_BBOOL yn = CK_FALSE;
                        memcpy(&yn, attr->pValue, sizeof(yn));
                        printf("%s Decrypt: %s\n", prefix, yesno(yn));
                        break;
                }

                case CKA_VERIFY: {
                        CK_BBOOL yn = CK_FALSE;
                        memcpy(&yn, attr->pValue, sizeof(yn));
                        printf("%s Verify: %s\n", prefix, yesno(yn));
                        break;
                }

                }
        }
}

static void
dump_objects(CK_FUNCTION_LIST *m,
             CK_SESSION_HANDLE session,
             const char *prefix)
{
        CK_RV rv;

        rv = m->C_FindObjectsInit(session, NULL, 0);
        if (rv != CKR_OK) {
                report_error(rv, "FindObjectsInit");
                return;
        }

        while (rv == CKR_OK) {
                CK_OBJECT_HANDLE objs[256];
                CK_ULONG count = sizeof (objs) / sizeof (CK_OBJECT_HANDLE);
                rv = m->C_FindObjects(session, objs, count, &count);
                if (rv != CKR_OK) {
                        report_error(rv, "FindObjects");
                        break;
                }

                if (count == 0)
                        break;

                for (CK_ULONG i = 0; i < count; i++) {
                        CK_OBJECT_CLASS klass = CK_UNAVAILABLE_INFORMATION;
                        CK_BBOOL is_token = CK_FALSE;
                        CK_UTF8CHAR label[256] = {0, };
                        CK_UTF8CHAR app[256] = {0, };
                        CK_CERTIFICATE_TYPE certtype = 0;
                        CK_BBOOL can_sign = CK_FALSE;
                        CK_BBOOL can_encrypt = CK_FALSE;
                        CK_BBOOL can_decrypt = CK_FALSE;
                        CK_BBOOL can_verify = CK_FALSE;
                        CK_UTF8CHAR url[256] = {0, };
                        CK_ATTRIBUTE attrs[] =
                                {
                                 {CKA_CLASS, &klass, sizeof(klass)},
                                 {CKA_TOKEN, &is_token, sizeof(is_token)},
                                 {CKA_LABEL, label, sizeof(label)-1},
                                 {CKA_APPLICATION, app, sizeof(app)-1},
                                 {CKA_CERTIFICATE_TYPE, &certtype, sizeof(certtype)},
                                 {CKA_URL, url, sizeof(url)-1},
                                 {CKA_SIGN, &can_sign, sizeof(can_sign)},
                                 {CKA_ENCRYPT, &can_encrypt, sizeof(can_encrypt)},
                                 {CKA_DECRYPT, &can_decrypt, sizeof(can_decrypt)},
                                 {CKA_VERIFY, &can_verify, sizeof(can_verify)},
                        };

                        CK_ULONG nattr = sizeof(attrs) / sizeof(CK_ATTRIBUTE);
                        rv = m->C_GetAttributeValue(session, objs[i], attrs, nattr);
                        if (rv == CKR_ATTRIBUTE_SENSITIVE) {
                                fprintf(stderr, "sensitive information hidden\n");
                        }

                        /* NB: pre item return value */
                        printf("%s Object #%lu [%lu]\n", prefix, i, objs[i]);
                        dump_attributes(attrs, nattr, "    ");
                }
        }

        rv = m->C_FindObjectsFinal(session);
        if (rv != CKR_OK) {
                report_error(rv, "FindObjectsFinal");
        }
}

static void
print_uri(P11KitUri *uri, P11KitUriType how, const char *pre, const char *post)
{
        const char *str = NULL;
        char *tmp = NULL;
        int r;

        r = p11_kit_uri_format(uri, how, &tmp);

        if (r == P11_KIT_URI_OK) {
                str = tmp;
        } else {
                str = p11_kit_uri_message(r);
        }

        printf("%s'%s'%s", pre, str, post);
        free(tmp);
}

CK_RV
token_login(CK_FUNCTION_LIST *m, CK_SESSION_HANDLE session, const char *pin)
{
        char *tmp = NULL;
        if (pin == NULL) {
                tmp = getpass("PIN: ");
                pin = tmp;
        }

        if (pin == NULL)
                return CKR_CANCEL;

        CK_RV rv = m->C_Login(session, CKU_USER, (unsigned char *) pin, strlen(pin));
        free(tmp);
        return report_error(rv, "Login");
}

int
main(int argc, char **argv)
{
        CK_FUNCTION_LIST **modules;
        P11KitUri *uri;
        CK_RV rv;
        int c;
        int no_login = 0;

        while (1) {
                int optidx = 0;
                static struct option opts[] =
                        {
                         {"no-login",  no_argument,       0, 'N'},
                         {NULL,        0,                 0,  0 }
                        };

                c = getopt_long(argc, argv, "N", opts, &optidx);
                if (c == -1)
                        break;

                switch (c) {
                case 'N':
                        no_login = 1;
                        break;

                case '?':
                        break;

                default:
                        fprintf(stderr, "invalid option: 0%o\n", c);
                }
        }

        uri = p11_kit_uri_new();

        modules = p11_kit_modules_load_and_initialize(0);

        for (CK_FUNCTION_LIST **l = modules; *l; l++) {
                CK_FUNCTION_LIST *m = *l;
                CK_INFO info;
                char *name;

                name = p11_kit_module_get_name (m);
                printf("Module: %s\n", name ? name : "unnamed");
                free (name);

                rv = m->C_GetInfo(&info);
                if (rv != CKR_OK) {
                        report_error(rv, "GetSlotList");
                        continue;
                }

                memcpy(p11_kit_uri_get_module_info(uri), &info, sizeof(info));
                print_uri(uri, P11_KIT_URI_FOR_MODULE, " URI: ", "\n");

                printf(" Version: ");
                dump_version(&info.cryptokiVersion);
                printf("\n");
                printf(" Manufacturer: %.*s\n", (int) sizeof (info.manufacturerID), info.manufacturerID);

                CK_SLOT_ID slotids[256];
                CK_ULONG count = sizeof (slotids) / sizeof (CK_SLOT_ID);

                rv = m->C_GetSlotList (0, slotids, &count);

                if (rv == CKR_BUFFER_TOO_SMALL) {
                        fprintf(stderr, "GetSlotList buffer too small");
                        continue;
                } else if (rv != CKR_OK) {
                        report_error(rv, "GetSlotList");
                        continue;
                }


                for (CK_ULONG i = 0; i < count; i++) {
                        CK_SLOT_INFO slot;
                        CK_TOKEN_INFO token;
                        CK_SESSION_HANDLE session;
                        rv = m->C_GetSlotInfo(slotids[i], &slot);
                        if (rv != CKR_OK) {
                                report_error(rv, "GetSlotInfo");
                                continue;
                        }

                        memcpy(p11_kit_uri_get_slot_info(uri), &slot, sizeof(slot));

                        print_uri(uri, P11_KIT_URI_FOR_SLOT, "Slot-URI: ", "\n");
                        printf("Slot #%lu [%lu]: ", i, slotids[i]);
                        dump_slot_info(&slot);

                        printf("  Token: \n");

                        rv = m->C_GetTokenInfo(slotids[i], &token);
                        if (rv == CKR_TOKEN_NOT_PRESENT) {
                                printf("not present\n");
                                continue;
                        } else if (rv != CKR_OK) {
                                report_error(rv, "GetTokenInfo");
                                continue;
                        }

                        memcpy(p11_kit_uri_get_token_info(uri), &token, sizeof(token));
                        print_uri(uri, P11_KIT_URI_FOR_TOKEN, "   URI: ", "\n");
                        dump_token_info(&token, "  ");

                        rv = m->C_OpenSession(slotids[i], CKF_SERIAL_SESSION, NULL, NULL, &session);

                        if (rv != CKR_OK) {
                                report_error(rv, "OpenSession");
                                continue;
                        }

                        if (token_requires_login(&token) && !no_login)
                                token_login(m, session, NULL);

                        printf("   Objects\n");
                        dump_objects(m, session, "  ");

                        m->C_CloseSession(session);

                }

        }

        p11_kit_uri_free(uri);

        return EXIT_SUCCESS;
}
