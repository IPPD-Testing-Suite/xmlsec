#include <xmlsec/base64.h>
#include <xmlsec/buffer.h>
#include <xmlsec/parser.h>

void ignore(void* ctx, const char* msg, ...) {
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 1) {
        return 0;
    }

    xmlSetGenericErrorFunc(NULL, &ignore);

    /* Encode raw bytes — exercises GetEncodeSize allocation */
    xmlChar* encoded = xmlSecBase64Encode(
        (const xmlSecByte*)data,
        (xmlSecSize)size,
        0);

    if (encoded != NULL) {
        /* Roundtrip decode into a buffer sized on the encoded string */
        xmlSecBufferPtr buf = xmlSecBufferCreate(xmlSecStrlen(encoded));
        if (buf != NULL) {
            xmlSecSize out_written = 0;
            xmlSecBase64Decode_ex(encoded,
                xmlSecBufferGetData(buf),
                xmlSecBufferGetMaxSize(buf),
                &out_written);
            xmlSecBufferDestroy(buf);
        }
        xmlFree(encoded);
    }

    return 0;
}
