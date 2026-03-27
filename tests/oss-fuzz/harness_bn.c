#include <xmlsec/bn.h>
#include <xmlsec/parser.h>

void ignore(void* ctx, const char* msg, ...) {
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) {
        return 0;
    }

    xmlSetGenericErrorFunc(NULL, &ignore);

    /* First byte selects base 2–16; remainder is the raw BN value */
    xmlSecSize base    = (xmlSecSize)(2 + (data[0] % 15));
    xmlSecSize bn_size = (xmlSecSize)(size - 1);

    xmlSecBnPtr bn = xmlSecBnCreate(bn_size);
    if (bn == NULL) {
        return 0;
    }

    if (xmlSecBnSetData(bn, (const xmlSecByte*)(data + 1), bn_size) < 0) {
        xmlSecBnDestroy(bn);
        return 0;
    }

    /* Convert to string — exercises the malloc/memset in BnToString */
    xmlChar* str = xmlSecBnToString(bn, base);
    if (str != NULL) {
        /* Roundtrip back to BN to exercise BnFromString */
        xmlSecBnPtr bn2 = xmlSecBnCreate(0);
        if (bn2 != NULL) {
            xmlSecBnFromString(bn2, str, base);
            xmlSecBnDestroy(bn2);
        }
        xmlFree(str);
    }

    xmlSecBnDestroy(bn);
    return 0;
}
