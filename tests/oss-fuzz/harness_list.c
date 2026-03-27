#include <xmlsec/list.h>
#include <xmlsec/parser.h>

void ignore(void* ctx, const char* msg, ...) {
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) {
        return 0;
    }

    xmlSetGenericErrorFunc(NULL, &ignore);

    /* Derive item count from first two bytes — allow up to 160 items
     * to reliably exceed the default initial capacity of 64 */
    xmlSecSize num_items = (xmlSecSize)(((unsigned)data[0] << 4) | ((unsigned)data[1] >> 4));
    if (num_items > 160) {
        num_items = 160;
    }

    xmlSecPtrListPtr list = xmlSecPtrListCreate(xmlSecStringListGetKlass());
    if (list == NULL) {
        return 0;
    }

    /* Add items one by one; drives EnsureSize on every iteration */
    for (xmlSecSize i = 0; i < num_items && i < (xmlSecSize)(size - 2); i++) {
        xmlChar* item = xmlStrndup(
            (const xmlChar*)(data + 2 + (i % ((xmlSecSize)(size - 2) > 0 ? (xmlSecSize)(size - 2) : 1))),
            1);
        if (item == NULL) {
            break;
        }
        if (xmlSecPtrListAdd(list, item) < 0) {
            xmlFree(item);
            break;
        }
    }

    xmlSecPtrListDestroy(list);
    return 0;
}
