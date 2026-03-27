#include <xmlsec/buffer.h>
#include <xmlsec/parser.h>

void ignore(void* ctx, const char* msg, ...) {
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) {
        return 0;
    }

    xmlSetGenericErrorFunc(NULL, &ignore);

    /* First byte controls remove size; rest is buffer payload */
    xmlSecSize remove_size = (xmlSecSize)data[0];
    xmlSecSize buf_size    = (xmlSecSize)(size - 1);

    xmlSecBufferPtr buf = xmlSecBufferCreate(buf_size);
    if (buf == NULL) {
        return 0;
    }

    if (xmlSecBufferSetData(buf, (const xmlSecByte*)(data + 1), buf_size) < 0) {
        xmlSecBufferDestroy(buf);
        return 0;
    }

    /* Exercise RemoveHead — including the case where remove_size > buf->size */
    xmlSecBufferRemoveHead(buf, remove_size);

    /* Attempt another removal larger than remaining content */
    xmlSecBufferRemoveHead(buf, buf_size + 100);

    /* Destroy triggers Finalize (UAF path) */
    xmlSecBufferDestroy(buf);

    return 0;
}
