package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.structure.fusefilter.Arity3ByteFusePosition;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.crypto.prf.Prf;
import edu.alibaba.mpc4j.common.tool.crypto.prf.PrfFactory;
import edu.alibaba.mpc4j.common.tool.utils.BinaryUtils;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.common.tool.utils.IntUtils;
import edu.alibaba.mpc4j.common.tool.utils.ObjectUtils;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;

/**
 * CAPE_C PIR utilities.
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
class CapeCPirUtils {
    /**
     * compressed-anchor LWE seed byte length.
     */
    static final int SEED_BYTE_LENGTH = 32;
    /**
     * compressed-anchor LWE dimension.
     */
    static final int LWE_DIMENSION = 32;
    /**
     * compressed-anchor LWE modulus.
     */
    static final long LWE_MODULUS = 1L << 32;
    /**
     * message scale for compressed-anchor LWE bits.
     */
    static final long DELTA_BIT = 1L;
    /**
     * serialized LWE b element byte length.
     */
    static final int B_ELEMENT_BYTE_LENGTH = Long.BYTES;
    /**
     * PRG domain.
     */
    private static final byte[] LWE_PRG_DOMAIN = "CAPE_C-LWE-PRG".getBytes(StandardCharsets.UTF_8);

    private CapeCPirUtils() {
        // empty
    }

    static <T> byte[] keywordToByteArray(T keyword) {
        if (keyword instanceof byte[] bytes) {
            return BytesUtils.clone(bytes);
        }
        if (keyword instanceof ByteBuffer byteBuffer) {
            ByteBuffer duplicate = byteBuffer.duplicate();
            byte[] bytes = new byte[duplicate.remaining()];
            duplicate.get(bytes);
            return bytes;
        }
        return ObjectUtils.objectToByteArray(keyword);
    }

    static int[] getHashPositionsFromKeywordBytes(byte[] keywordBytes, int keywordNum, byte[] seed,
                                                  CapeCPirParams params) {
        Arity3ByteFusePosition<ByteBuffer> position = new Arity3ByteFusePosition<>(
            EnvType.STANDARD, keywordNum, params.getPayloadBlockByteLength(), seed
        );
        return position.positions(ByteBuffer.wrap(BytesUtils.clone(keywordBytes)));
    }

    static <T> QueryBloomFilter buildQueryBloomFilter(Collection<T> remainingKeywords, CapeCPirParams params) {
        Set<ByteBuffer> uniqueKeywords = new LinkedHashSet<>();
        remainingKeywords.stream()
            .map(CapeCPirUtils::keywordToByteArray)
            .forEach(keyword -> uniqueKeywords.add(ByteBuffer.wrap(keyword)));
        return QueryBloomFilter.create(uniqueKeywords, params);
    }

    static <T> Map<ByteBuffer, List<T>> buildForwardIndex(Map<T, List<byte[]>> keywordValueMap) {
        Map<ByteBuffer, List<T>> valueKeywordMap = new LinkedHashMap<>();
        keywordValueMap.forEach((keyword, values) -> values.forEach(value ->
            valueKeywordMap.computeIfAbsent(ByteBuffer.wrap(BytesUtils.clone(value)), ignored -> new ArrayList<>())
                .add(keyword)
        ));
        return valueKeywordMap;
    }

    static CapeCCompressedAnchorQuery generateCompressedAnchorQuery(int[] rows, int[] cols, int rowNum, int colNum,
                                                                   int bffHashNum, long[] lweSecretKey) {
        MathPreconditions.checkEqual("rows.length", "bff_hash_num", rows.length, bffHashNum);
        MathPreconditions.checkEqual("cols.length", "bff_hash_num", cols.length, bffHashNum);
        MathPreconditions.checkPositive("row_num", rowNum);
        MathPreconditions.checkPositive("col_num", colNum);
        MathPreconditions.checkPositive("lwe_secret_key.length", lweSecretKey.length);
        int rowBitNum = ceilLog2(rowNum);
        int colBitNum = ceilLog2(colNum);
        int bitNum = bffHashNum * (rowBitNum + colBitNum);
        byte[] seed = generateSeed();
        long[] bValues = new long[bitNum];
        int bitIndex = 0;
        for (int hashIndex = 0; hashIndex < bffHashNum; hashIndex++) {
            MathPreconditions.checkNonNegativeInRange("row", rows[hashIndex], rowNum);
            MathPreconditions.checkNonNegativeInRange("col", cols[hashIndex], colNum);
            for (int rowBitIndex = 0; rowBitIndex < rowBitNum; rowBitIndex++) {
                bValues[bitIndex] = encryptCompressedBit(seed, bitIndex, (rows[hashIndex] >>> rowBitIndex) & 1L,
                    lweSecretKey);
                bitIndex++;
            }
            for (int colBitIndex = 0; colBitIndex < colBitNum; colBitIndex++) {
                bValues[bitIndex] = encryptCompressedBit(seed, bitIndex, (cols[hashIndex] >>> colBitIndex) & 1L,
                    lweSecretKey);
                bitIndex++;
            }
        }
        return new CapeCCompressedAnchorQuery(seed, serializeBArray(bValues), rowBitNum, colBitNum, bffHashNum,
            lweSecretKey.length, LWE_MODULUS, B_ELEMENT_BYTE_LENGTH);
    }

    static List<LweCiphertext> recoverLweBitCiphertexts(CapeCCompressedAnchorQuery query) {
        MathPreconditions.checkEqual("b_element_byte_length", "Long.BYTES", query.getBElementByteLength(), Long.BYTES);
        int bitNum = query.getBffHashNum() * (query.getRowBitNum() + query.getColBitNum());
        long[] bArray = deserializeBArray(query.getBArray());
        MathPreconditions.checkEqual("bArray.length", "bit_num", bArray.length, bitNum);
        List<LweCiphertext> ciphertexts = new ArrayList<>(bitNum);
        for (int bitIndex = 0; bitIndex < bitNum; bitIndex++) {
            long[] a = expandA(query.getSeed(), bitIndex, query.getLweDimension(), query.getLweModulus());
            ciphertexts.add(new LweCiphertext(a, bArray[bitIndex], query.getLweModulus()));
        }
        return ciphertexts;
    }

    static <T> List<byte[]> buildAndPreprocessPackedBloomMatrices(Map<T, List<byte[]>> keywordValueMap,
                                                                  CapeCPirParams params, byte[] seed) {
        List<ByteBuffer> keys = keywordValueMap.keySet().stream()
            .map(keyword -> ByteBuffer.wrap(keywordToByteArray(keyword)))
            .sorted(CapeCPirUtils::compareByteBuffers)
            .toList();
        SameSeedFuseGraph graph = buildSameSeedFuseGraph(keys, params, seed);
        if (graph == null) {
            throw new IllegalStateException("Cannot build same-seed CAPE_C Bloom Binary Fuse Filter");
        }
        IndexedBloomPayloadPlan plan = new IndexedBloomPayloadPlan(canonicalKeywordValueMap(keywordValueMap),
            buildValueBloomFilters(keywordValueMap, params), params.getBloomBitLength(), params.getBloomPerPackedBlock());
        int packedPayloadBlockNum = params.getBloomPackedPayloadBlockNum();
        int coefficientStride = bloomPackedCoefficientStride(params);
        int columnCapacity = bloomPackedMatrixColumnCapacity(params);
        int columnTileNum = ceilDiv(params.getMatrixColNum(), columnCapacity);
        List<byte[]> encodedMatrices = new ArrayList<>(packedPayloadBlockNum * columnTileNum * params.getMatrixRowNum());
        for (int packedBlockIndex = 0; packedBlockIndex < packedPayloadBlockNum; packedBlockIndex++) {
            long[] slotCoefficientValues = assignPackedBloomStorageForBlockFlat(
                graph, plan, packedBlockIndex, coefficientStride, params.getPlainModulus()
            );
            for (int columnTileIndex = 0; columnTileIndex < columnTileNum; columnTileIndex++) {
                int tileStartColumn = columnTileIndex * columnCapacity;
                int tileColumnNum = Math.min(columnCapacity, params.getMatrixColNum() - tileStartColumn);
                long[][][] matrix = matrixizeSinglePackedBloomColumnTile(
                    slotCoefficientValues, graph.filterLength(), params, coefficientStride, tileStartColumn,
                    tileColumnNum
                );
                encodedMatrices.addAll(CapeCPirNativeUtils.preprocessDatabase(params.encryptionParams, matrix));
            }
        }
        return encodedMatrices;
    }

    static <T> SameSeedPreprocessResult buildSameSeedValueAndBloomPreprocess(
        Map<T, List<byte[]>> keywordValueMap, Map<T, long[]> valueOnlyPayloadMap, CapeCPirParams params, byte[] seed
    ) {
        Map<ByteBuffer, List<byte[]>> canonicalKeywordValueMap = canonicalKeywordValueMap(keywordValueMap);
        List<ByteBuffer> keys = new ArrayList<>(canonicalKeywordValueMap.keySet());
        keys.sort(CapeCPirUtils::compareByteBuffers);
        SameSeedFuseGraph graph = buildSameSeedFuseGraph(keys, params, seed);
        if (graph == null) {
            throw new IllegalStateException("Cannot build same-seed CAPE_C Binary Fuse Filter graph");
        }
        Map<ByteBuffer, long[]> canonicalValueOnlyPayloadMap = canonicalValueOnlyPayloadMap(valueOnlyPayloadMap);
        long[][] valueOnlyBffStorage = buildLongBinaryFuseFilters(
            graph, params.getValuePayloadCoeffNum(),
            (keyIndex, blockIndex) -> canonicalValueOnlyPayloadMap.get(keys.get(keyIndex))[blockIndex],
            params.getPlainModulus()
        );
        IndexedBloomPayloadPlan plan = new IndexedBloomPayloadPlan(
            canonicalKeywordValueMap, buildValueBloomFilters(keywordValueMap, params), params.getBloomBitLength(),
            params.getBloomPerPackedBlock()
        );
        List<byte[]> encodedBloomOnlyMatrices = buildAndPreprocessPackedBloomMatrices(graph, plan, params);
        return new SameSeedPreprocessResult(seed, valueOnlyBffStorage, encodedBloomOnlyMatrices);
    }

    private static long[][] buildLongBinaryFuseFilters(SameSeedFuseGraph graph, int payloadBlockNum,
                                                       IndexedLongPayloadBlockProvider payloadProvider,
                                                       long plainModulus) {
        MathPreconditions.checkPositive("payloadBlockNum", payloadBlockNum);
        long[][] storage = new long[payloadBlockNum][];
        for (int blockIndex = 0; blockIndex < payloadBlockNum; blockIndex++) {
            storage[blockIndex] = assignLongStorageForBlockByIndex(graph, payloadProvider, blockIndex, plainModulus);
        }
        return storage;
    }

    private static long[] assignLongStorageForBlockByIndex(SameSeedFuseGraph graph,
                                                           IndexedLongPayloadBlockProvider payloadProvider,
                                                           int blockIndex, long plainModulus) {
        long[] storage = new long[graph.filterLength()];
        for (int peelIndex = graph.peelSize() - 1; peelIndex >= 0; peelIndex--) {
            int keyIndex = graph.peelKeyIndexes()[peelIndex];
            int slot = graph.peelSlots()[peelIndex];
            long share = Math.floorMod(payloadProvider.get(keyIndex, blockIndex), plainModulus);
            for (int pos : graph.keyPositions()[keyIndex]) {
                if (pos != slot) {
                    share = Math.floorMod(share - storage[pos], plainModulus);
                }
            }
            storage[slot] = share;
        }
        return storage;
    }

    private static List<byte[]> buildAndPreprocessPackedBloomMatrices(SameSeedFuseGraph graph,
                                                                      IndexedBloomPayloadPlan plan,
                                                                      CapeCPirParams params) {
        int packedPayloadBlockNum = params.getBloomPackedPayloadBlockNum();
        int coefficientStride = bloomPackedCoefficientStride(params);
        int columnCapacity = bloomPackedMatrixColumnCapacity(params);
        int columnTileNum = ceilDiv(params.getMatrixColNum(), columnCapacity);
        List<byte[]> encodedMatrices = new ArrayList<>(packedPayloadBlockNum * columnTileNum * params.getMatrixRowNum());
        for (int packedBlockIndex = 0; packedBlockIndex < packedPayloadBlockNum; packedBlockIndex++) {
            long[] slotCoefficientValues = assignPackedBloomStorageForBlockFlat(
                graph, plan, packedBlockIndex, coefficientStride, params.getPlainModulus()
            );
            for (int columnTileIndex = 0; columnTileIndex < columnTileNum; columnTileIndex++) {
                int tileStartColumn = columnTileIndex * columnCapacity;
                int tileColumnNum = Math.min(columnCapacity, params.getMatrixColNum() - tileStartColumn);
                long[][][] matrix = matrixizeSinglePackedBloomColumnTile(
                    slotCoefficientValues, graph.filterLength(), params, coefficientStride, tileStartColumn,
                    tileColumnNum
                );
                encodedMatrices.addAll(CapeCPirNativeUtils.preprocessDatabase(params.encryptionParams, matrix));
            }
        }
        return encodedMatrices;
    }

    static int bloomPackedCoefficientStride(CapeCPirParams params) {
        return params.getBloomPerPackedBlock() * params.getBloomBitLength();
    }

    static int bloomPackedMatrixColumnCapacity(CapeCPirParams params) {
        int coefficientStride = bloomPackedCoefficientStride(params);
        MathPreconditions.checkPositive("bloom_packed_coefficient_stride", coefficientStride);
        int columnCapacity = params.getPolyModulusDegree() / coefficientStride;
        MathPreconditions.checkPositive("bloom_packed_matrix_column_capacity", columnCapacity);
        return columnCapacity;
    }

    private static <T> Map<ByteBuffer, List<byte[]>> canonicalKeywordValueMap(Map<T, List<byte[]>> keywordValueMap) {
        Map<ByteBuffer, List<byte[]>> canonicalMap = new LinkedHashMap<>(keywordValueMap.size());
        keywordValueMap.forEach((keyword, values) -> {
            List<byte[]> copiedValues = values.stream().map(BytesUtils::clone).toList();
            canonicalMap.put(ByteBuffer.wrap(keywordToByteArray(keyword)), copiedValues);
        });
        return canonicalMap;
    }

    private static <T> Map<ByteBuffer, long[]> canonicalValueOnlyPayloadMap(Map<T, long[]> valueOnlyPayloadMap) {
        Map<ByteBuffer, long[]> canonicalMap = new LinkedHashMap<>(valueOnlyPayloadMap.size());
        valueOnlyPayloadMap.forEach((keyword, payload) ->
            canonicalMap.put(ByteBuffer.wrap(keywordToByteArray(keyword)), payload.clone())
        );
        return canonicalMap;
    }

    private static <T> Map<ByteBuffer, long[]> buildValueBloomFilters(Map<T, List<byte[]>> keywordValueMap,
                                                                      CapeCPirParams params) {
        Map<ByteBuffer, List<T>> valueKeywordMap = buildForwardIndex(keywordValueMap);
        Map<ByteBuffer, long[]> valueBloomFilters = new LinkedHashMap<>(valueKeywordMap.size());
        valueKeywordMap.forEach((value, keywords) -> {
            List<ByteBuffer> keywordBytes = keywords.stream()
                .map(keyword -> ByteBuffer.wrap(keywordToByteArray(keyword)))
                .toList();
            valueBloomFilters.put(copyByteBuffer(value), QueryBloomFilter.create(keywordBytes, params).toLongBitVector());
        });
        return valueBloomFilters;
    }

    private static SameSeedFuseGraph buildSameSeedFuseGraph(List<ByteBuffer> keys, CapeCPirParams params, byte[] seed) {
        Arity3ByteFusePosition<ByteBuffer> position = new Arity3ByteFusePosition<>(
            EnvType.STANDARD, keys.size(), params.getPayloadBlockByteLength(), seed
        );
        int keyNum = keys.size();
        int filterLength = position.filterLength();
        int[][] keyPositions = new int[keyNum][];
        int[] degrees = new int[filterLength];
        int[] xorKeyIndexes = new int[filterLength];
        for (int keyIndex = 0; keyIndex < keyNum; keyIndex++) {
            keyPositions[keyIndex] = position.positions(keys.get(keyIndex));
            for (int pos : keyPositions[keyIndex]) {
                degrees[pos]++;
                xorKeyIndexes[pos] ^= keyIndex;
            }
        }
        Queue<Integer> queue = new ArrayDeque<>();
        for (int pos = 0; pos < filterLength; pos++) {
            if (degrees[pos] == 1) {
                queue.add(pos);
            }
        }
        boolean[] removed = new boolean[keyNum];
        int[] peelKeyIndexes = new int[keyNum];
        int[] peelSlots = new int[keyNum];
        int peelSize = 0;
        while (!queue.isEmpty()) {
            int slot = queue.remove();
            if (degrees[slot] != 1) {
                continue;
            }
            int keyIndex = xorKeyIndexes[slot];
            if (removed[keyIndex]) {
                continue;
            }
            removed[keyIndex] = true;
            peelKeyIndexes[peelSize] = keyIndex;
            peelSlots[peelSize] = slot;
            peelSize++;
            for (int pos : keyPositions[keyIndex]) {
                degrees[pos]--;
                xorKeyIndexes[pos] ^= keyIndex;
                if (degrees[pos] == 1) {
                    queue.add(pos);
                }
            }
        }
        return peelSize == keyNum
            ? new SameSeedFuseGraph(keys, keyPositions, peelKeyIndexes, peelSlots, peelSize, filterLength)
            : null;
    }

    private static long[] assignPackedBloomStorageForBlockFlat(SameSeedFuseGraph graph,
                                                               IndexedBloomPayloadPlan payloadProvider,
                                                               int packedBlockIndex, int coefficientStride,
                                                               long plainModulus) {
        long[] slotCoefficientValues = new long[graph.filterLength() * coefficientStride];
        for (int peelIndex = graph.peelSize() - 1; peelIndex >= 0; peelIndex--) {
            int keyIndex = graph.peelKeyIndexes()[peelIndex];
            int slot = graph.peelSlots()[peelIndex];
            int[] positions = graph.keyPositions()[keyIndex];
            for (int offset = 0; offset < coefficientStride; offset++) {
                long share = payloadProvider.getPackedCoefficient(keyIndex, packedBlockIndex, offset);
                for (int pos : positions) {
                    if (pos != slot) {
                        share -= slotCoefficientValues[pos * coefficientStride + offset];
                    }
                }
                slotCoefficientValues[slot * coefficientStride + offset] = Math.floorMod(share, plainModulus);
            }
        }
        return slotCoefficientValues;
    }

    private static long[][][] matrixizeSinglePackedBloomColumnTile(long[] slotCoefficientValues, int filterLength,
                                                                   CapeCPirParams params, int coefficientStride,
                                                                   int tileStartColumn, int tileColumnNum) {
        long[][][] matrices = new long[1][params.getMatrixRowNum()][tileColumnNum * coefficientStride];
        MathPreconditions.checkEqual(
            "slotCoefficientValues.length", "filterLength * coefficientStride",
            slotCoefficientValues.length, filterLength * coefficientStride
        );
        for (int slot = 0; slot < filterLength; slot++) {
            int row = slot % params.getMatrixRowNum();
            int col = slot / params.getMatrixRowNum();
            if (col < tileStartColumn || col >= tileStartColumn + tileColumnNum) {
                continue;
            }
            int localCol = col - tileStartColumn;
            for (int offset = 0; offset < coefficientStride; offset++) {
                matrices[0][row][localCol * coefficientStride + offset] =
                    slotCoefficientValues[slot * coefficientStride + offset];
            }
        }
        return matrices;
    }

    static int ceilLog2(int n) {
        int log = 0;
        int pow = 1;
        while (pow < n) {
            pow <<= 1;
            log++;
        }
        return log;
    }

    private static int ceilDiv(int dividend, int divisor) {
        return (dividend + divisor - 1) / divisor;
    }

    private static ByteBuffer copyByteBuffer(ByteBuffer byteBuffer) {
        ByteBuffer duplicate = byteBuffer.asReadOnlyBuffer();
        duplicate.rewind();
        byte[] bytes = new byte[duplicate.remaining()];
        duplicate.get(bytes);
        return ByteBuffer.wrap(bytes);
    }

    private static int compareByteBuffers(ByteBuffer left, ByteBuffer right) {
        return Arrays.compareUnsigned(byteBufferToByteArray(left), byteBufferToByteArray(right));
    }

    private static byte[] byteBufferToByteArray(ByteBuffer byteBuffer) {
        ByteBuffer duplicate = byteBuffer.asReadOnlyBuffer();
        duplicate.rewind();
        byte[] bytes = new byte[duplicate.remaining()];
        duplicate.get(bytes);
        return bytes;
    }

    private static long encryptCompressedBit(byte[] seed, int bitIndex, long bit, long[] lweSecretKey) {
        long[] a = expandA(seed, bitIndex, lweSecretKey.length, LWE_MODULUS);
        return innerProductBinarySecret(a, lweSecretKey) + DELTA_BIT * bit;
    }

    private static byte[] generateSeed() {
        byte[] seed = new byte[SEED_BYTE_LENGTH];
        new SecureRandom().nextBytes(seed);
        return seed;
    }

    private static long[] expandA(byte[] seed, int index, int lweDimension, long modulus) {
        long[] a = new long[lweDimension];
        int generated = 0;
        int counter = 0;
        while (generated < lweDimension) {
            byte[] digest = digest(seed, index, counter);
            ByteBuffer buffer = ByteBuffer.wrap(digest);
            while (buffer.remaining() >= Long.BYTES && generated < lweDimension) {
                a[generated] = Long.remainderUnsigned(buffer.getLong(), modulus);
                generated++;
            }
            counter++;
        }
        return a;
    }

    private static byte[] serializeBArray(long[] bArray) {
        ByteBuffer buffer = ByteBuffer.allocate(bArray.length * Long.BYTES);
        for (long b : bArray) {
            buffer.putLong(b);
        }
        return buffer.array();
    }

    private static long[] deserializeBArray(byte[] bArrayBytes) {
        MathPreconditions.checkEqual("bArrayBytes.length % Long.BYTES", "0", bArrayBytes.length % Long.BYTES, 0);
        ByteBuffer buffer = ByteBuffer.wrap(BytesUtils.clone(bArrayBytes));
        long[] bArray = new long[bArrayBytes.length / Long.BYTES];
        for (int i = 0; i < bArray.length; i++) {
            bArray[i] = buffer.getLong();
        }
        return bArray;
    }

    private static long innerProductBinarySecret(long[] a, long[] secretKey) {
        long value = 0L;
        for (int i = 0; i < a.length; i++) {
            if (secretKey[i] != 0L) {
                value += a[i];
            }
        }
        return value;
    }

    private static byte[] digest(byte[] seed, int index, int counter) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(LWE_PRG_DOMAIN);
            messageDigest.update(seed);
            messageDigest.update(ByteBuffer.allocate(Integer.BYTES).putInt(index).array());
            messageDigest.update(ByteBuffer.allocate(Integer.BYTES).putInt(counter).array());
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /**
     * LWE ciphertext recovered from an CAPE_C compressed anchor query.
     */
    static class LweCiphertext {
        /**
         * LWE a vector.
         */
        private final long[] a;
        /**
         * LWE b value.
         */
        private final long b;
        /**
         * LWE modulus.
         */
        private final long modulus;

        LweCiphertext(long[] a, long b, long modulus) {
            this.a = a.clone();
            this.b = b;
            this.modulus = modulus;
        }

        long[] getA() {
            return a.clone();
        }

        long getB() {
            return b;
        }

        long getModulus() {
            return modulus;
        }
    }

    /**
     * CAPE_C-local query Bloom filter.
     */
    static class QueryBloomFilter {
        /**
         * bit vector.
         */
        private final long[] bitVector;

        private QueryBloomFilter(long[] bitVector) {
            this.bitVector = bitVector.clone();
        }

        static QueryBloomFilter create(Collection<ByteBuffer> keywords, CapeCPirParams params) {
            byte[] storage = new byte[params.getBloomByteLength()];
            Prf hash = PrfFactory.createInstance(EnvType.STANDARD, params.getBloomHashNum() * Integer.BYTES);
            hash.setKey(params.getBloomSeed());
            int offset = storage.length * Byte.SIZE - params.getBloomBitLength();
            for (ByteBuffer keyword : keywords) {
                int[] hashValues = IntUtils.byteArrayToIntArray(hash.getBytes(byteBufferToByteArray(keyword)));
                for (int hashIndex = 0; hashIndex < params.getBloomHashNum(); hashIndex++) {
                    int position = Math.floorMod(hashValues[hashIndex], params.getBloomBitLength());
                    BinaryUtils.setBoolean(storage, offset + position, true);
                }
            }
            long[] bits = new long[params.getBloomBitLength()];
            for (int bitIndex = 0; bitIndex < bits.length; bitIndex++) {
                bits[bitIndex] = BinaryUtils.getBoolean(storage, bitIndex + offset) ? 1L : 0L;
            }
            return new QueryBloomFilter(bits);
        }

        long[] toLongBitVector() {
            return bitVector.clone();
        }

        int countOnes() {
            int count = 0;
            for (long bit : bitVector) {
                count += bit == 0L ? 0 : 1;
            }
            return count;
        }

        private static byte[] byteBufferToByteArray(ByteBuffer byteBuffer) {
            ByteBuffer duplicate = byteBuffer.duplicate();
            byte[] bytes = new byte[duplicate.remaining()];
            duplicate.get(bytes);
            return bytes;
        }
    }

    private record SameSeedFuseGraph(List<ByteBuffer> keys, int[][] keyPositions, int[] peelKeyIndexes,
                                     int[] peelSlots, int peelSize, int filterLength) {
        private SameSeedFuseGraph {
            keys = keys.stream().map(CapeCPirUtils::copyByteBuffer).toList();
            keyPositions = Arrays.stream(keyPositions).map(int[]::clone).toArray(int[][]::new);
            peelKeyIndexes = peelKeyIndexes.clone();
            peelSlots = peelSlots.clone();
        }
    }

    record SameSeedPreprocessResult(byte[] seed, long[][] valueOnlyBffStorage,
                                    List<byte[]> encodedBloomOnlyMatrices) {
        SameSeedPreprocessResult {
            seed = BytesUtils.clone(seed);
            valueOnlyBffStorage = Arrays.stream(valueOnlyBffStorage).map(long[]::clone).toArray(long[][]::new);
            encodedBloomOnlyMatrices = encodedBloomOnlyMatrices.stream().map(BytesUtils::clone).toList();
        }
    }

    @FunctionalInterface
    private interface IndexedLongPayloadBlockProvider {
        long get(int keyIndex, int blockIndex);
    }

    private static class IndexedBloomPayloadPlan {
        /**
         * values attached to each sorted key, represented by Bloom-filter ids.
         */
        private final int[][] keywordValueIds;
        /**
         * value Bloom filters.
         */
        private final long[][] valueBloomFilterArray;
        /**
         * Bloom bit length.
         */
        private final int bloomBitLength;
        /**
         * value Bloom filters per packed block.
         */
        private final int bloomPerPackedBlock;

        IndexedBloomPayloadPlan(Map<ByteBuffer, List<byte[]>> keywordValueMap,
                                Map<ByteBuffer, long[]> valueBloomFilters,
                                int bloomBitLength, int bloomPerPackedBlock) {
            List<ByteBuffer> keys = new ArrayList<>(keywordValueMap.keySet());
            keys.sort(CapeCPirUtils::compareByteBuffers);
            Map<ByteBuffer, Integer> valueIdMap = new LinkedHashMap<>(valueBloomFilters.size());
            valueBloomFilterArray = new long[valueBloomFilters.size()][];
            int valueId = 0;
            for (Map.Entry<ByteBuffer, long[]> entry : valueBloomFilters.entrySet()) {
                valueIdMap.put(copyByteBuffer(entry.getKey()), valueId);
                valueBloomFilterArray[valueId] = entry.getValue().clone();
                valueId++;
            }
            keywordValueIds = new int[keys.size()][];
            for (int keyIndex = 0; keyIndex < keys.size(); keyIndex++) {
                List<byte[]> values = keywordValueMap.get(keys.get(keyIndex));
                int[] valueIds = new int[values.size()];
                for (int valueIndex = 0; valueIndex < values.size(); valueIndex++) {
                    Integer foundValueId = valueIdMap.get(ByteBuffer.wrap(values.get(valueIndex)));
                    if (foundValueId == null) {
                        throw new IllegalArgumentException("Missing value Bloom Filter");
                    }
                    valueIds[valueIndex] = foundValueId;
                }
                keywordValueIds[keyIndex] = valueIds;
            }
            this.bloomBitLength = bloomBitLength;
            this.bloomPerPackedBlock = bloomPerPackedBlock;
        }

        long getPackedCoefficient(int keyIndex, int packedBlockIndex, int coefficientOffset) {
            int localValueIndex = coefficientOffset / bloomBitLength;
            int bloomBitIndex = coefficientOffset % bloomBitLength;
            if (localValueIndex >= bloomPerPackedBlock) {
                return 0L;
            }
            int valueIndex = packedBlockIndex * bloomPerPackedBlock + localValueIndex;
            if (valueIndex >= keywordValueIds[keyIndex].length) {
                return 0L;
            }
            int valueId = keywordValueIds[keyIndex][valueIndex];
            return valueBloomFilterArray[valueId][bloomBitIndex];
        }
    }
}
