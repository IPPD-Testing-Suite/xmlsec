#!/bin/bash -eu
#
# OSS-Fuzz build script for xmlsec fuzzing harnesses.
#
# Environment variables provided by the OSS-Fuzz infrastructure:
#   $CC            — C compiler (typically clang)
#   $CFLAGS        — compiler flags (-fsanitize=... -fsanitize=fuzzer-no-link ...)
#   $LIB_FUZZING_ENGINE — fuzzer library to link (-lFuzzer or $LIB_FUZZING_ENGINE path)
#   $OUT           — output directory for built fuzz targets
#   $SRC           — root directory containing checked-out source
#   $WORK          — writable scratch/install directory
#
# To replicate locally without the full oss-fuzz environment:
#   export CC=clang
#   export CFLAGS="-fsanitize=address,fuzzer-no-link -g -O1"
#   export LIB_FUZZING_ENGINE="-fsanitize=fuzzer"
#   export OUT=/tmp/xmlsec-fuzz-out
#   export SRC=$(git rev-parse --show-toplevel)/..
#   export WORK=/tmp/xmlsec-fuzz-work
#   mkdir -p $OUT $WORK
#   bash tests/oss-fuzz/build.sh
#

XMLSEC_SRC="${SRC}/xmlsec"

# ── 1. Build the xmlsec library ────────────────────────────────────────────────
cd "${XMLSEC_SRC}"

./autogen.sh
./configure \
    --prefix="${WORK}" \
    --disable-shared \
    --enable-static \
    --disable-docs \
    --disable-mans \
    CC="${CC}" \
    CFLAGS="${CFLAGS}"

make -j"$(nproc)" install

# Resolve include/lib paths installed by the configure above
XMLSEC_INCLUDES="-I${WORK}/include/xmlsec1 $(xml2-config --cflags)"
XMLSEC_LIBS="-L${WORK}/lib -lxmlsec1-openssl -lxmlsec1 $(xml2-config --libs)"

# ── 2. Build every harness in this directory ───────────────────────────────────
HARNESS_DIR="${XMLSEC_SRC}/tests/oss-fuzz"

for src_file in "${HARNESS_DIR}"/*.c; do
    name="$(basename "${src_file}" .c)"

    "${CC}" ${CFLAGS} \
        ${XMLSEC_INCLUDES} \
        "${src_file}" \
        ${LIB_FUZZING_ENGINE} \
        ${XMLSEC_LIBS} \
        -o "${OUT}/${name}"

    echo "Built: ${OUT}/${name}"
done

# ── 3. Copy seed corpora ────────────────────────────────────────────────────────
for seed_dir in "${HARNESS_DIR}/seeds"/*/; do
    harness_name="harness_$(basename "${seed_dir}")"
    corpus_zip="${OUT}/${harness_name}_seed_corpus.zip"
    if ls "${seed_dir}"* 1>/dev/null 2>&1; then
        zip -j "${corpus_zip}" "${seed_dir}"*
        echo "Packed seeds: ${corpus_zip}"
    fi
done
