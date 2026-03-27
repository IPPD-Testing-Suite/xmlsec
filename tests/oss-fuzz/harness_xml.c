#include <xmlsec/base64.h>
#include <xmlsec/bn.h>
#include <xmlsec/buffer.h>
#include <xmlsec/list.h>
#include <xmlsec/parser.h>

void ignore(void* ctx, const char* msg, ...) {
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 4) {
        return 0;
    }

    xmlSetGenericErrorFunc(NULL, &ignore);

    /* Parse fuzz input as an XML document */
    xmlSecBufferPtr buf = xmlSecBufferCreate((xmlSecSize)size);
    if (buf == NULL) {
        return 0;
    }
    xmlSecBufferSetData(buf, (const xmlSecByte*)data, (xmlSecSize)size);

    xmlDocPtr doc = xmlSecParseMemory(
        xmlSecBufferGetData(buf),
        xmlSecBufferGetSize(buf), 0);

    if (doc != NULL) {
        xmlNodePtr root = xmlDocGetRootElement(doc);
        if (root != NULL) {
            xmlNodePtr child = root->children;
            while (child != NULL) {
                if (child->type == XML_TEXT_NODE && child->content != NULL) {
                    xmlSecSize content_len = (xmlSecSize)xmlStrlen(child->content);

                    /* Exercise buffer ops and RemoveHead on text content */
                    xmlSecBufferPtr tbuf = xmlSecBufferCreate(content_len);
                    if (tbuf != NULL) {
                        xmlSecBufferSetData(tbuf,
                            (const xmlSecByte*)child->content, content_len);
                        if (content_len > 2) {
                            xmlSecBufferRemoveHead(tbuf, content_len / 2);
                        }
                        xmlSecBufferDestroy(tbuf);
                    }

                    /* Exercise base64 encode on content */
                    if (content_len > 0) {
                        xmlChar* enc = xmlSecBase64Encode(
                            (const xmlSecByte*)child->content, content_len, 0);
                        if (enc != NULL) {
                            xmlFree(enc);
                        }
                    }
                }
                child = child->next;
            }
        }
        xmlFreeDoc(doc);
    }

    /* Exercise BN operations on raw bytes */
    if (size >= 8) {
        xmlSecBnPtr bn = xmlSecBnCreate((xmlSecSize)(size / 4));
        if (bn != NULL) {
            xmlSecBnSetData(bn, (const xmlSecByte*)data, (xmlSecSize)(size / 4));
            xmlChar* s = xmlSecBnToString(bn, 16);
            if (s != NULL) {
                xmlFree(s);
            }
            xmlSecBnDestroy(bn);
        }
    }

    xmlSecBufferDestroy(buf);
    return 0;
}
