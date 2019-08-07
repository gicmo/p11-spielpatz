#define _GNU_SOURCE 1
#include <p11-kit/p11-kit.h>
#include <p11-kit/uri.h>

#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
        CK_FUNCTION_LIST **modules;
        CK_FUNCTION_LIST *osc;
        CK_RV rv;

        modules = p11_kit_modules_load_and_initialize(0);

        osc = p11_kit_module_for_name (modules, "opensc");
        if (osc == NULL) {
                fprintf(stderr, "Failed to locate 'opensc' module\n");
                return -1;
        }

        while (TRUE) {
                CK_SLOT_ID sid = (CK_ULONG) -1;
                CK_SLOT_INFO slot;
                CK_FLAGS flags = 0;
                CK_SLOT_ID slotids[256];
                CK_ULONG count = sizeof (slotids) / sizeof (CK_SLOT_ID);
                CK_BBOOL found = FALSE;

                rv = osc->C_WaitForSlotEvent(flags, &sid, NULL);
                if (rv != CKR_OK)
                        continue;

                fprintf(stderr, "Event in slot id: %lx\n", sid);

                /* directly calling GetSlotInfo often failed, so
                 * we sneak in this GetSlotList call */
                rv = osc->C_GetSlotList(0, slotids, &count);
                if (rv != CKR_OK) {
                        fprintf(stderr, "GetSlotInfo failed: %s\n",
                                p11_kit_strerror (rv));
                        continue;
                }

                for (CK_ULONG i = 0; i < count; i++) {
                        rv = osc->C_GetSlotInfo(slotids[i], &slot);
                        if (rv != CKR_OK) {
                                fprintf(stderr, "GetSlotInfo failed: %s\n",
                                        p11_kit_strerror (rv));
                                continue;
                        }

                        printf(" [%lu] %lx Manufacturer: %.*s\n", i, slotids[i],
                               (int) sizeof(slot.manufacturerID), slot.manufacturerID);
                }

        }

        return EXIT_FAILURE;
}
