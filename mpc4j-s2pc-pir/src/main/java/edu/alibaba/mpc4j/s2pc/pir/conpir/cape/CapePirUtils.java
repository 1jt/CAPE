package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.structure.fusefilter.Arity3ByteFuseFilter;
import edu.alibaba.mpc4j.common.structure.fusefilter.Arity3ByteFusePosition;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.crypto.hash.Hash;
import edu.alibaba.mpc4j.common.tool.crypto.hash.HashFactory;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import edu.alibaba.mpc4j.common.tool.utils.ObjectUtils;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * CAPE PIR utilities.
 *
 * <p>CAPE anchor retrieval payload is
 * {@code fingerprint(anchorKeyword) || item_0 || item_1 || ...}, where each fixed-width item is
 * {@code presentFlag || value || BloomFilter(value)}. The present flag avoids treating a valid all-zero value as
 * padding.</p>
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
class CapePirUtils {
    private CapePirUtils() {
        // empty
    }

    @FunctionalInterface
    interface LongPayloadBlockProvider<T> {
        long get(T key, int blockIndex);
    }

    @FunctionalInterface
    interface IndexedLongPayloadBlockProvider {
        long get(int keyIndex, int blockIndex);
    }

    @FunctionalInterface
    interface IndexedPackedBloomPayloadProvider {
        long get(int keyIndex, int packedBlockIndex, int coefficientOffset);
    }

    @FunctionalInterface
    interface NativePreprocessFunction {
        List<byte[]> preprocess(long[][][] matrices);
    }

    static <T> Map<ByteBuffer, List<T>> buildForwardIndex(Map<T, List<byte[]>> keywordValueMap) {
        Map<ByteBuffer, Set<T>> valueKeywordSetMap = new LinkedHashMap<>();
        keywordValueMap.forEach((keyword, values) -> values.forEach(value ->
            valueKeywordSetMap.computeIfAbsent(ByteBuffer.wrap(BytesUtils.clone(value)), ignored -> new LinkedHashSet<>())
                .add(keyword)
        ));
        Map<ByteBuffer, List<T>> valueKeywordMap = new LinkedHashMap<>(valueKeywordSetMap.size());
        valueKeywordSetMap.forEach((value, keywords) -> valueKeywordMap.put(value, new ArrayList<>(keywords)));
        return valueKeywordMap;
    }

    static <T> Map<ByteBuffer, CapeBloomFilterAdapter> buildValueBloomFilters(Map<ByteBuffer, List<T>> valueToKeywordSet,
                                                                             CapePirParams params) {
        Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters = new LinkedHashMap<>(valueToKeywordSet.size());
        valueToKeywordSet.forEach((value, keywords) -> {
            List<byte[]> keywordBytes = keywords.stream()
                .map(CapePirUtils::keywordToByteArray)
                .collect(Collectors.toList());
            valueBloomFilters.put(ByteBuffer.wrap(byteBufferToByteArray(value)), CapeBloomFilterAdapter.create(
                keywordBytes, params
            ));
        });
        return valueBloomFilters;
    }

    static <T> CapeBloomFilterAdapter buildQueryBloomFilter(Collection<T> remainingKeywords, CapePirParams params) {
        List<byte[]> keywordBytes = remainingKeywords.stream()
            .map(CapePirUtils::keywordToByteArray)
            .collect(Collectors.toList());
        return CapeBloomFilterAdapter.create(keywordBytes, params);
    }

    static byte[] attachBloomFilterToValue(byte[] value, CapeBloomFilterAdapter bloomFilter, CapePirParams params) {
        MathPreconditions.checkEqual("value.length", "value_byte_length", value.length, params.getValueByteLength());
        MathPreconditions.checkEqual(
            "bloom_filter_byte_length", "params.getBloomByteLength()", bloomFilter.getStorage().length,
            params.getBloomByteLength()
        );
        byte[] payload = new byte[params.getPayloadItemByteLength()];
        payload[0] = 1;
        System.arraycopy(value, 0, payload, Byte.BYTES, params.getValueByteLength());
        System.arraycopy(
            bloomFilter.getStorage(), 0, payload, Byte.BYTES + params.getValueByteLength(),
            params.getBloomByteLength()
        );
        return payload;
    }

    static ValueWithBloomFilter parseValueWithBloomFilter(byte[] payload, CapePirParams params) {
        MathPreconditions.checkEqual(
            "payload.length", "payload_item_byte_length", payload.length, params.getPayloadItemByteLength()
        );
        if (payload[0] == 0) {
            return new ValueWithBloomFilter(new byte[params.getValueByteLength()], new byte[params.getBloomByteLength()],
                false);
        }
        if (payload[0] != 1) {
            throw new IllegalArgumentException("invalid CAPE payload item present flag");
        }
        byte[] value = BytesUtils.clone(payload, Byte.BYTES, params.getValueByteLength());
        byte[] bloomFilterBytes = BytesUtils.clone(
            payload, Byte.BYTES + params.getValueByteLength(), params.getBloomByteLength()
        );
        return new ValueWithBloomFilter(value, bloomFilterBytes, true);
    }

    static <T> byte[] buildKeywordPayload(T keyword, List<byte[]> values,
                                          Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters,
                                          CapePirParams params) {
        MathPreconditions.checkLessOrEqual("values.size", values.size(), params.getMaxValueNumPerKeyword());
        byte[] payload = new byte[params.getPayloadByteLength()];
        byte[] fingerprint = fingerprint(keywordToByteArray(keyword), params);
        System.arraycopy(fingerprint, 0, payload, 0, fingerprint.length);
        int offset = params.getFingerprintByteLength();
        for (byte[] value : values) {
            CapeBloomFilterAdapter bloomFilter = valueBloomFilters.get(ByteBuffer.wrap(BytesUtils.clone(value)));
            if (bloomFilter == null) {
                throw new IllegalArgumentException("Missing value Bloom Filter");
            }
            MathPreconditions.checkEqual("value.length", "value_byte_length", value.length,
                params.getValueByteLength());
            byte[] item = attachBloomFilterToValue(value, bloomFilter, params);
            System.arraycopy(item, 0, payload, offset, item.length);
            offset += item.length;
        }
        return payload;
    }

    @Deprecated
    static <T> byte[] buildValueOnlyPayload(T keyword, List<byte[]> values, CapePirParams params) {
        MathPreconditions.checkLessOrEqual("values.size", values.size(), params.getMaxValueNumPerKeyword());
        byte[] payload = new byte[valueOnlyPayloadByteLength(params)];
        byte[] fingerprint = fingerprint(keywordToByteArray(keyword), params);
        System.arraycopy(fingerprint, 0, payload, 0, fingerprint.length);
        int offset = params.getFingerprintByteLength();
        for (byte[] value : values) {
            MathPreconditions.checkEqual("value.length", "value_byte_length", value.length,
                params.getValueByteLength());
            payload[offset] = 1;
            System.arraycopy(value, 0, payload, offset + Byte.BYTES, params.getValueByteLength());
            offset += valueOnlyItemByteLength(params);
        }
        return payload;
    }

    static <T> long[] buildValueOnlyLongPayload(T keyword, List<byte[]> values, CapePirParams params) {
        MathPreconditions.checkLessOrEqual("values.size", values.size(), params.getMaxValueNumPerKeyword());
        long[] payload = new long[valueOnlyPayloadBlockNum(params)];
        byte[] fingerprint = fingerprint(keywordToByteArray(keyword), params);
        for (int coeffIndex = 0; coeffIndex < params.getFingerprintCoeffNum(); coeffIndex++) {
            payload[coeffIndex] = readUnsignedChunk(fingerprint, coeffIndex, params.getValueEncodingChunkBitLength());
        }
        for (int valueIndex = 0; valueIndex < params.getMaxValueNumPerKeyword(); valueIndex++) {
            int base = params.getFingerprintCoeffNum() + valueIndex * params.getValueCoeffNum();
            payload[base] = params.getAbsentValueSentinel();
        }
        for (int valueIndex = 0; valueIndex < values.size(); valueIndex++) {
            byte[] value = values.get(valueIndex);
            MathPreconditions.checkEqual("value.length", "value_byte_length", value.length,
                params.getValueByteLength());
            long[] encodedValue = valueToCoeffArray(value, params);
            int base = params.getFingerprintCoeffNum() + valueIndex * params.getValueCoeffNum();
            for (int coeffIndex = 0; coeffIndex < encodedValue.length; coeffIndex++) {
                payload[base + coeffIndex] = encodedValue[coeffIndex];
            }
        }
        return payload;
    }

    static List<byte[]> decodeValueOnlyPayload(byte[] anchorKeywordBytes, long[] coeffs, CapePirParams params) {
        MathPreconditions.checkGreaterOrEqual("coeffs.length", coeffs.length, valueOnlyPayloadBlockNum(params));
        byte[] expectFingerprint = fingerprint(anchorKeywordBytes, params);
        for (int coeffIndex = 0; coeffIndex < params.getFingerprintCoeffNum(); coeffIndex++) {
            long actual = Math.floorMod(coeffs[coeffIndex], params.getPlainModulus());
            long expected = readUnsignedChunk(expectFingerprint, coeffIndex, params.getValueEncodingChunkBitLength());
            if (actual != expected) {
                return List.of();
            }
        }
        List<byte[]> values = new ArrayList<>(params.getMaxValueNumPerKeyword());
        for (int i = 0; i < params.getMaxValueNumPerKeyword(); i++) {
            int base = params.getFingerprintCoeffNum() + i * params.getValueCoeffNum();
            long firstCoeff = Math.floorMod(coeffs[base], params.getPlainModulus());
            if (firstCoeff == params.getAbsentValueSentinel()) {
                continue;
            }
            long[] valueCoeffs = new long[params.getValueCoeffNum()];
            valueCoeffs[0] = firstCoeff;
            for (int coeffIndex = 1; coeffIndex < valueCoeffs.length; coeffIndex++) {
                valueCoeffs[coeffIndex] = Math.floorMod(coeffs[base + coeffIndex], params.getPlainModulus());
                if (valueCoeffs[coeffIndex] == params.getAbsentValueSentinel()) {
                    return List.of();
                }
            }
            values.add(coeffArrayToValue(valueCoeffs, params));
        }
        return values;
    }

    static byte[] buildBloomOnlyPayload(List<byte[]> values, Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters,
                                        CapePirParams params) {
        MathPreconditions.checkLessOrEqual("values.size", values.size(), params.getMaxValueNumPerKeyword());
        byte[] payload = new byte[bloomOnlyPayloadByteLength(params)];
        int offset = 0;
        for (byte[] value : values) {
            CapeBloomFilterAdapter bloomFilter = valueBloomFilters.get(ByteBuffer.wrap(BytesUtils.clone(value)));
            if (bloomFilter == null) {
                throw new IllegalArgumentException("Missing value Bloom Filter");
            }
            long[] bits = bloomFilter.toLongBitVector();
            for (int i = 0; i < params.getBloomBitLength(); i++) {
                payload[offset + i] = (byte) bits[i];
            }
            offset += params.getBloomBitLength();
        }
        return payload;
    }

    static long[] buildBloomOnlyLongPayload(List<byte[]> values,
                                            Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters,
                                            CapePirParams params) {
        MathPreconditions.checkLessOrEqual("values.size", values.size(), params.getMaxValueNumPerKeyword());
        long[] payload = new long[bloomOnlyPayloadByteLength(params)];
        int offset = 0;
        for (byte[] value : values) {
            CapeBloomFilterAdapter bloomFilter = valueBloomFilters.get(ByteBuffer.wrap(BytesUtils.clone(value)));
            if (bloomFilter == null) {
                throw new IllegalArgumentException("Missing value Bloom Filter");
            }
            long[] bits = bloomFilter.toLongBitVector();
            System.arraycopy(bits, 0, payload, offset, params.getBloomBitLength());
            offset += params.getBloomBitLength();
        }
        return payload;
    }

    static List<ValueWithBloomFilter> parseKeywordPayloadItems(byte[] payload, CapePirParams params) {
        MathPreconditions.checkEqual("payload.length", "payload_byte_length", payload.length,
            params.getPayloadByteLength());
        List<ValueWithBloomFilter> items = new ArrayList<>(params.getMaxValueNumPerKeyword());
        int offset = params.getFingerprintByteLength();
        for (int i = 0; i < params.getMaxValueNumPerKeyword(); i++) {
            byte[] item = BytesUtils.clone(payload, offset, params.getPayloadItemByteLength());
            ValueWithBloomFilter valueWithBloomFilter = parseValueWithBloomFilter(item, params);
            if (valueWithBloomFilter.isPresent()) {
                items.add(valueWithBloomFilter);
            }
            offset += params.getPayloadItemByteLength();
        }
        return items;
    }

    static List<ValueWithBloomFilter> decodeKeywordPayloadItems(byte[] anchorKeywordBytes, long[] coeffs,
                                                                CapePirParams params) {
        MathPreconditions.checkGreaterOrEqual("coeffs.length", coeffs.length, params.getPayloadBlockNum());
        byte[] payload = new byte[params.getPayloadByteLength()];
        int offset = 0;
        for (int blockIndex = 0; blockIndex < params.getPayloadBlockNum(); blockIndex++) {
            byte[] block = longToBlock(coeffs[blockIndex], params);
            int copyByteLength = Math.min(block.length, payload.length - offset);
            if (copyByteLength <= 0) {
                break;
            }
            System.arraycopy(block, 0, payload, offset, copyByteLength);
            offset += copyByteLength;
        }
        byte[] actualFingerprint = BytesUtils.clone(payload, 0, params.getFingerprintByteLength());
        byte[] expectFingerprint = fingerprint(anchorKeywordBytes, params);
        if (!BytesUtils.equals(actualFingerprint, expectFingerprint)) {
            return List.of();
        }
        return parseKeywordPayloadItems(payload, params);
    }

    static byte[][] splitPayloadToBlocks(byte[] payload, CapePirParams params) {
        MathPreconditions.checkLessOrEqual("payload.length", payload.length, params.getPayloadByteLength());
        int blockByteLength = params.getPayloadBlockByteLength();
        int blockNum = (payload.length + blockByteLength - 1) / blockByteLength;
        if (!params.isEnablePayloadSplit()) {
            MathPreconditions.checkEqual("block_num", "1", blockNum, 1);
        }
        byte[][] blocks = new byte[blockNum][blockByteLength];
        for (int blockIndex = 0; blockIndex < blockNum; blockIndex++) {
            int copyByteLength = Math.min(blockByteLength, payload.length - blockIndex * blockByteLength);
            System.arraycopy(payload, blockIndex * blockByteLength, blocks[blockIndex], 0, copyByteLength);
        }
        return blocks;
    }

    static <T> BinaryFuseFilterData buildBinaryFuseFilters(Map<T, byte[]> keywordPayloadMap, CapePirParams params,
                                                           SecureRandom secureRandom) {
        return buildBinaryFuseFilters(keywordPayloadMap, params.getPayloadByteLength(), params, secureRandom, null);
    }

    static <T> BinaryFuseFilterData buildBinaryFuseFilters(Map<T, byte[]> keywordPayloadMap, int payloadByteLength,
                                                           CapePirParams params, SecureRandom secureRandom,
                                                           byte[] fixedSeed) {
        MathPreconditions.checkPositive("keywordPayloadMap.size", keywordPayloadMap.size());
        @SuppressWarnings("unchecked")
        int payloadBlockNum = CommonUtils.getUnitNum(payloadByteLength, params.getPayloadBlockByteLength());
        Map<T, byte[]>[] blockMaps = new Map[payloadBlockNum];
        for (int blockIndex = 0; blockIndex < payloadBlockNum; blockIndex++) {
            blockMaps[blockIndex] = new LinkedHashMap<>(keywordPayloadMap.size());
        }
        for (Map.Entry<T, byte[]> entry : keywordPayloadMap.entrySet()) {
            byte[][] blocks = splitPayloadToBlocks(entry.getValue(), payloadByteLength, params);
            for (int blockIndex = 0; blockIndex < payloadBlockNum; blockIndex++) {
                byte[] block = blockIndex < blocks.length
                    ? blocks[blockIndex]
                    : new byte[params.getPayloadBlockByteLength()];
                blockMaps[blockIndex].put(entry.getKey(), block);
            }
        }
        byte[][][] storage = new byte[payloadBlockNum][][];
        byte[] seed;
        if (payloadBlockNum == 1 && fixedSeed == null) {
            Arity3ByteFuseFilter<T> fuseFilter = new Arity3ByteFuseFilter<>(
                EnvType.STANDARD, blockMaps[0], params.getPayloadBlockByteLength(), secureRandom
            );
            seed = BytesUtils.clone(fuseFilter.seed());
            storage[0] = fuseFilter.storage();
        } else {
            int maxEncodeTries = 1 << 10;
            seed = fixedSeed == null ? new byte[CommonConstants.BLOCK_BYTE_LENGTH] : BytesUtils.clone(fixedSeed);
            boolean encoded = false;
            for (int encodeTry = 0; encodeTry < maxEncodeTries && !encoded; encodeTry++) {
                if (fixedSeed == null) {
                    secureRandom.nextBytes(seed);
                }
                encoded = true;
                for (int blockIndex = 0; blockIndex < payloadBlockNum; blockIndex++) {
                    storage[blockIndex] = buildSameSeedStorage(
                        blockMaps[blockIndex], keywordPayloadMap.size(), params.getPayloadBlockByteLength(), seed
                    );
                    if (storage[blockIndex] == null) {
                        encoded = false;
                        break;
                    }
                }
                if (fixedSeed != null) {
                    break;
                }
            }
            if (!encoded) {
                throw new IllegalStateException("Cannot build same-seed CAPE Binary Fuse Filter");
            }
        }
        return new BinaryFuseFilterData(seed, storage);
    }

    static long[][][] matrixizePackedBff(byte[][][] dPrimes, CapePirParams params) {
        return matrixizePackedBff(dPrimes, params, dPrimes.length, params.getBlocksPerPackedMatrix());
    }

    static long[][][] matrixizePackedBff(byte[][][] dPrimes, CapePirParams params, int payloadBlockNum,
                                         int blocksPerPackedMatrix) {
        MathPreconditions.checkEqual("dPrimes.length", "payloadBlockNum", dPrimes.length, payloadBlockNum);
        int packedMatrixGroupNum = (payloadBlockNum + blocksPerPackedMatrix - 1) / blocksPerPackedMatrix;
        long[][][] matrices = new long[packedMatrixGroupNum]
            [params.getMatrixRowNum()][params.getMatrixColNum() * blocksPerPackedMatrix];
        for (int blockIndex = 0; blockIndex < dPrimes.length; blockIndex++) {
            MathPreconditions.checkLessOrEqual("dPrime.length", dPrimes[blockIndex].length,
                params.getMatrixRowNum() * params.getMatrixColNum());
            int groupIndex = blockIndex / blocksPerPackedMatrix;
            int blockOffset = blockIndex % blocksPerPackedMatrix;
            for (int u = 0; u < dPrimes[blockIndex].length; u++) {
                int row = u % params.getMatrixRowNum();
                int col = u / params.getMatrixRowNum();
                matrices[groupIndex][row][col * blocksPerPackedMatrix + blockOffset]
                    = blockToLong(dPrimes[blockIndex][u], params);
            }
        }
        return matrices;
    }

    static <T> long[][] buildLongBinaryFuseFilters(Map<T, long[]> keywordPayloadMap, int payloadBlockNum,
                                                   CapePirParams params, byte[] seed) {
        MathPreconditions.checkPositive("keywordPayloadMap.size", keywordPayloadMap.size());
        return buildLongBinaryFuseFilters(
            keywordPayloadMap.keySet(), payloadBlockNum, params, seed,
            (key, blockIndex) -> keywordPayloadMap.get(key)[blockIndex]
        );
    }

    static <T> long[][] buildLongBinaryFuseFilters(Collection<T> keys, int payloadBlockNum, CapePirParams params,
                                                   byte[] seed, LongPayloadBlockProvider<T> payloadBlockProvider) {
        return buildLongBinaryFuseFilters(keys, payloadBlockNum, params, seed, payloadBlockProvider, null);
    }

    static <T> long[][] buildLongBinaryFuseFilters(Collection<T> keys, int payloadBlockNum, CapePirParams params,
                                                   byte[] seed, LongPayloadBlockProvider<T> payloadBlockProvider,
                                                   LongBffBuildStats stats) {
        MathPreconditions.checkPositive("keys.size", keys.size());
        MathPreconditions.checkPositive("payloadBlockNum", payloadBlockNum);
        long graphStartTime = System.nanoTime();
        SameSeedFuseGraph<T> graph = buildSameSeedFuseGraph(keys, params, seed);
        if (graph == null) {
            throw new IllegalStateException("Cannot build same-seed CAPE long Binary Fuse Filter");
        }
        long graphBuildTimeMillis = (System.nanoTime() - graphStartTime) / 1_000_000L;
        long[][] storage = new long[payloadBlockNum][];
        long assignmentStartTime = System.nanoTime();
        for (int blockIndex = 0; blockIndex < payloadBlockNum; blockIndex++) {
            storage[blockIndex] = assignLongStorageForBlock(
                graph, payloadBlockProvider, blockIndex, params.getPlainModulus()
            );
        }
        long assignmentTotalTimeMillis = (System.nanoTime() - assignmentStartTime) / 1_000_000L;
        if (stats != null) {
            stats.set(
                payloadBlockNum, keys.size(), graph.filterLength, graphBuildTimeMillis, assignmentTotalTimeMillis
            );
        }
        return storage;
    }

    static <T> SameSeedFuseGraph<T> buildSameSeedFuseGraph(Collection<T> keys, CapePirParams params, byte[] seed) {
        return buildSameSeedFuseGraph(keys, keys.size(), params.getPayloadBlockByteLength(), seed);
    }

    static <T> long[][] buildLongBinaryFuseFilters(SameSeedFuseGraph<T> graph, int payloadBlockNum,
                                                   CapePirParams params,
                                                   IndexedLongPayloadBlockProvider payloadBlockProvider) {
        MathPreconditions.checkPositive("payloadBlockNum", payloadBlockNum);
        long[][] storage = new long[payloadBlockNum][];
        for (int blockIndex = 0; blockIndex < payloadBlockNum; blockIndex++) {
            storage[blockIndex] = assignLongStorageForBlockByIndex(
                graph, payloadBlockProvider, blockIndex, params.getPlainModulus()
            );
        }
        return storage;
    }

    static <T> List<byte[]> buildAndPreprocessLongBinaryFuseFiltersStreaming(SameSeedFuseGraph<T> graph,
                                                                             int payloadBlockNum, CapePirParams params,
                                                                             IndexedLongPayloadBlockProvider provider,
                                                                             NativePreprocessFunction preprocessFunction,
                                                                             long graphBuildTimeMillis,
                                                                             LongBffBuildStats stats) {
        MathPreconditions.checkPositive("payloadBlockNum", payloadBlockNum);
        int blocksPerPackedMatrix = params.getBlocksPerPackedMatrix();
        int packedGroupNum = CommonUtils.getUnitNum(payloadBlockNum, blocksPerPackedMatrix);
        List<byte[]> encodedMatrices = new ArrayList<>(packedGroupNum * params.getMatrixRowNum());
        long assignmentTotalTimeMillis = 0L;
        long matrixizeTotalTimeMillis = 0L;
        long preprocessTotalTimeMillis = 0L;
        for (int groupIndex = 0; groupIndex < packedGroupNum; groupIndex++) {
            int groupStartBlock = groupIndex * blocksPerPackedMatrix;
            int groupBlockNum = Math.min(blocksPerPackedMatrix, payloadBlockNum - groupStartBlock);
            long assignmentStartTime = System.nanoTime();
            long[] slotBlockValues = assignLongStorageForBlockGroupFlat(
                graph, provider, groupStartBlock, groupBlockNum, params.getPlainModulus()
            );
            assignmentTotalTimeMillis += (System.nanoTime() - assignmentStartTime) / 1_000_000L;
            long matrixizeStartTime = System.nanoTime();
            long[][][] singleGroupMatrix = matrixizeSinglePackedGroup(
                slotBlockValues, graph.filterLength, params, groupBlockNum, blocksPerPackedMatrix
            );
            matrixizeTotalTimeMillis += (System.nanoTime() - matrixizeStartTime) / 1_000_000L;
            long preprocessStartTime = System.nanoTime();
            encodedMatrices.addAll(preprocessFunction.preprocess(singleGroupMatrix));
            preprocessTotalTimeMillis += (System.nanoTime() - preprocessStartTime) / 1_000_000L;
        }
        if (stats != null) {
            stats.set(
                payloadBlockNum, graph.keys.size(), graph.filterLength, 0L, assignmentTotalTimeMillis,
                packedGroupNum, blocksPerPackedMatrix, matrixizeTotalTimeMillis, preprocessTotalTimeMillis,
                false, false, false, false
            );
            stats.graphBuildTimeMillis = graphBuildTimeMillis;
        }
        return encodedMatrices;
    }

    static <T> List<byte[]> buildAndPreprocessPackedBloomBinaryFuseFiltersStreaming(SameSeedFuseGraph<T> graph,
                                                                                   CapePirParams params,
                                                                                   IndexedPackedBloomPayloadProvider provider,
                                                                                   NativePreprocessFunction preprocessFunction,
                                                                                   long graphBuildTimeMillis,
                                                                                   LongBffBuildStats stats) {
        int packedPayloadBlockNum = params.getBloomPackedPayloadBlockNum();
        int coefficientStride = params.getBloomPackedCoefficientStride();
        int columnCapacity = params.getBloomPackedMatrixColumnCapacity();
        int columnTileNum = params.getBloomPackedMatrixColumnTileNum();
        MathPreconditions.checkPositive("packedPayloadBlockNum", packedPayloadBlockNum);
        MathPreconditions.checkPositive("coefficientStride", coefficientStride);
        MathPreconditions.checkLessOrEqual(
            "columnCapacity * coefficientStride", columnCapacity * coefficientStride,
            params.getPolyModulusDegree()
        );
        List<byte[]> encodedMatrices = new ArrayList<>(packedPayloadBlockNum * columnTileNum * params.getMatrixRowNum());
        long assignmentTotalTimeMillis = 0L;
        long matrixizeTotalTimeMillis = 0L;
        long preprocessTotalTimeMillis = 0L;
        for (int packedBlockIndex = 0; packedBlockIndex < packedPayloadBlockNum; packedBlockIndex++) {
            long assignmentStartTime = System.nanoTime();
            long[] slotCoefficientValues = assignPackedBloomStorageForBlockFlat(
                graph, provider, packedBlockIndex, coefficientStride, params.getPlainModulus()
            );
            assignmentTotalTimeMillis += (System.nanoTime() - assignmentStartTime) / 1_000_000L;
            for (int columnTileIndex = 0; columnTileIndex < columnTileNum; columnTileIndex++) {
                int tileStartColumn = columnTileIndex * columnCapacity;
                int tileColumnNum = Math.min(columnCapacity, params.getMatrixColNum() - tileStartColumn);
                long matrixizeStartTime = System.nanoTime();
                long[][][] singlePackedBlockMatrix = matrixizeSinglePackedGroupColumnTile(
                    slotCoefficientValues, graph.filterLength, params, coefficientStride, coefficientStride,
                    tileStartColumn, tileColumnNum
                );
                matrixizeTotalTimeMillis += (System.nanoTime() - matrixizeStartTime) / 1_000_000L;
                long preprocessStartTime = System.nanoTime();
                encodedMatrices.addAll(preprocessFunction.preprocess(singlePackedBlockMatrix));
                preprocessTotalTimeMillis += (System.nanoTime() - preprocessStartTime) / 1_000_000L;
            }
        }
        if (stats != null) {
            stats.set(
                packedPayloadBlockNum, graph.keys.size(), graph.filterLength, graphBuildTimeMillis,
                assignmentTotalTimeMillis, packedPayloadBlockNum * columnTileNum, coefficientStride,
                matrixizeTotalTimeMillis,
                preprocessTotalTimeMillis, false, false, false, false
            );
        }
        return encodedMatrices;
    }

    static long[][][] matrixizePackedBff(long[][] dPrimes, CapePirParams params, int payloadBlockNum,
                                         int blocksPerPackedMatrix) {
        MathPreconditions.checkEqual("dPrimes.length", "payloadBlockNum", dPrimes.length, payloadBlockNum);
        int packedMatrixGroupNum = (payloadBlockNum + blocksPerPackedMatrix - 1) / blocksPerPackedMatrix;
        long[][][] matrices = new long[packedMatrixGroupNum]
            [params.getMatrixRowNum()][params.getMatrixColNum() * blocksPerPackedMatrix];
        for (int blockIndex = 0; blockIndex < dPrimes.length; blockIndex++) {
            MathPreconditions.checkLessOrEqual("dPrime.length", dPrimes[blockIndex].length,
                params.getMatrixRowNum() * params.getMatrixColNum());
            int groupIndex = blockIndex / blocksPerPackedMatrix;
            int blockOffset = blockIndex % blocksPerPackedMatrix;
            for (int u = 0; u < dPrimes[blockIndex].length; u++) {
                int row = u % params.getMatrixRowNum();
                int col = u / params.getMatrixRowNum();
                matrices[groupIndex][row][col * blocksPerPackedMatrix + blockOffset] = dPrimes[blockIndex][u];
            }
        }
        return matrices;
    }

    private static long[][][] matrixizeSinglePackedGroup(long[] slotBlockValues, int filterLength,
                                                         CapePirParams params, int groupBlockNum,
                                                         int blocksPerPackedMatrix) {
        MathPreconditions.checkLessOrEqual("group_block_num", groupBlockNum, blocksPerPackedMatrix);
        long[][][] matrices = new long[1][params.getMatrixRowNum()][params.getMatrixColNum() * blocksPerPackedMatrix];
        MathPreconditions.checkEqual(
            "slotBlockValues.length", "filterLength * groupBlockNum",
            slotBlockValues.length, filterLength * groupBlockNum
        );
        for (int slot = 0; slot < filterLength; slot++) {
            int row = slot % params.getMatrixRowNum();
            int col = slot / params.getMatrixRowNum();
            for (int offset = 0; offset < groupBlockNum; offset++) {
                matrices[0][row][col * blocksPerPackedMatrix + offset] =
                    slotBlockValues[slot * groupBlockNum + offset];
            }
        }
        return matrices;
    }

    private static long[][][] matrixizeSinglePackedGroupColumnTile(long[] slotBlockValues, int filterLength,
                                                                   CapePirParams params, int groupBlockNum,
                                                                   int blocksPerPackedMatrix,
                                                                   int tileStartColumn, int tileColumnNum) {
        MathPreconditions.checkLessOrEqual("group_block_num", groupBlockNum, blocksPerPackedMatrix);
        MathPreconditions.checkNonNegative("tile_start_column", tileStartColumn);
        MathPreconditions.checkPositive("tile_column_num", tileColumnNum);
        MathPreconditions.checkLessOrEqual(
            "tile_start_column + tile_column_num", tileStartColumn + tileColumnNum, params.getMatrixColNum()
        );
        long[][][] matrices = new long[1][params.getMatrixRowNum()][tileColumnNum * blocksPerPackedMatrix];
        MathPreconditions.checkEqual(
            "slotBlockValues.length", "filterLength * groupBlockNum",
            slotBlockValues.length, filterLength * groupBlockNum
        );
        for (int slot = 0; slot < filterLength; slot++) {
            int row = slot % params.getMatrixRowNum();
            int col = slot / params.getMatrixRowNum();
            if (col < tileStartColumn || col >= tileStartColumn + tileColumnNum) {
                continue;
            }
            int localCol = col - tileStartColumn;
            for (int offset = 0; offset < groupBlockNum; offset++) {
                matrices[0][row][localCol * blocksPerPackedMatrix + offset] =
                    slotBlockValues[slot * groupBlockNum + offset];
            }
        }
        return matrices;
    }

    static int valueOnlyItemByteLength(CapePirParams params) {
        return Byte.BYTES + params.getValueByteLength();
    }

    static int valueOnlyPayloadByteLength(CapePirParams params) {
        return params.getFingerprintByteLength() + params.getMaxValueNumPerKeyword() * valueOnlyItemByteLength(params);
    }

    static int valueOnlyPayloadBlockNum(CapePirParams params) {
        return params.getValuePayloadCoeffNum();
    }

    static int bloomOnlyPayloadByteLength(CapePirParams params) {
        return params.getMaxValueNumPerKeyword() * params.getBloomBitLength();
    }

    private static byte[][] splitPayloadToBlocks(byte[] payload, int payloadByteLength, CapePirParams params) {
        MathPreconditions.checkLessOrEqual("payload.length", payload.length, payloadByteLength);
        int blockByteLength = params.getPayloadBlockByteLength();
        int blockNum = (payload.length + blockByteLength - 1) / blockByteLength;
        byte[][] blocks = new byte[blockNum][blockByteLength];
        for (int blockIndex = 0; blockIndex < blockNum; blockIndex++) {
            int copyByteLength = Math.min(blockByteLength, payload.length - blockIndex * blockByteLength);
            System.arraycopy(payload, blockIndex * blockByteLength, blocks[blockIndex], 0, copyByteLength);
        }
        return blocks;
    }

    static <T> int[] getHashPositions(T keyword, int keywordNum, byte[] seed, CapePirParams params) {
        Arity3ByteFusePosition<T> position = new Arity3ByteFusePosition<>(
            EnvType.STANDARD, keywordNum, params.getPayloadBlockByteLength(), seed
        );
        return position.positions(keyword);
    }

    static int[] getHashPositionsFromKeywordBytes(byte[] keywordBytes, int keywordNum, byte[] seed,
                                                  CapePirParams params) {
        return getHashPositions(ByteBuffer.wrap(BytesUtils.clone(keywordBytes)), keywordNum, seed, params);
    }

    static <T> Map<ByteBuffer, byte[]> toCanonicalBytePayloadMap(Map<T, byte[]> keywordPayloadMap) {
        Map<ByteBuffer, byte[]> canonicalMap = new LinkedHashMap<>(keywordPayloadMap.size());
        keywordPayloadMap.forEach((keyword, payload) ->
            canonicalMap.put(ByteBuffer.wrap(keywordToByteArray(keyword)), BytesUtils.clone(payload))
        );
        return canonicalMap;
    }

    static <T> Map<ByteBuffer, long[]> toCanonicalLongPayloadMap(Map<T, long[]> keywordPayloadMap) {
        Map<ByteBuffer, long[]> canonicalMap = new LinkedHashMap<>(keywordPayloadMap.size());
        keywordPayloadMap.forEach((keyword, payload) ->
            canonicalMap.put(ByteBuffer.wrap(keywordToByteArray(keyword)), Arrays.copyOf(payload, payload.length))
        );
        return canonicalMap;
    }

    static long innerProduct(long[] left, long[] right) {
        MathPreconditions.checkEqual("left.length", "right.length", left.length, right.length);
        long sum = 0L;
        for (int i = 0; i < left.length; i++) {
            sum += left[i] * right[i];
        }
        return sum;
    }

    static byte[] longToBlock(long value, CapePirParams params) {
        byte[] block = new byte[params.getPayloadBlockByteLength()];
        for (int i = block.length - 1; i >= 0; i--) {
            block[i] = (byte) value;
            value >>>= Byte.SIZE;
        }
        return block;
    }

    static long valueToOneCoeff(byte[] value) {
        if (value.length > Short.BYTES) {
            throw new IllegalArgumentException("CAPE one-coeff value encoding supports at most 16-bit values");
        }
        long encoded = 0L;
        for (byte b : value) {
            encoded = (encoded << Byte.SIZE) | (b & 0xFFL);
        }
        return encoded;
    }

    static byte[] oneCoeffToValue(long coeff, int valueByteLength) {
        if (valueByteLength > Short.BYTES) {
            throw new IllegalArgumentException("CAPE one-coeff value decoding supports at most 16-bit values");
        }
        byte[] value = new byte[valueByteLength];
        for (int i = valueByteLength - 1; i >= 0; i--) {
            value[i] = (byte) (coeff & 0xFF);
            coeff >>>= Byte.SIZE;
        }
        return value;
    }

    static long[] valueToCoeffArray(byte[] value, CapePirParams params) {
        MathPreconditions.checkEqual("value.length", "value_byte_length", value.length, params.getValueByteLength());
        long[] coeffs = new long[params.getValueCoeffNum()];
        for (int coeffIndex = 0; coeffIndex < coeffs.length; coeffIndex++) {
            coeffs[coeffIndex] = readUnsignedChunk(value, coeffIndex, params.getValueEncodingChunkBitLength());
            if (coeffs[coeffIndex] >= params.getAbsentValueSentinel()) {
                throw new IllegalArgumentException("CAPE value coefficient must be less than absent sentinel");
            }
        }
        return coeffs;
    }

    static byte[] coeffArrayToValue(long[] coeffs, CapePirParams params) {
        MathPreconditions.checkEqual("coeffs.length", "value_coeff_num", coeffs.length, params.getValueCoeffNum());
        byte[] value = new byte[params.getValueByteLength()];
        for (int coeffIndex = 0; coeffIndex < coeffs.length; coeffIndex++) {
            long coeff = coeffs[coeffIndex];
            if (coeff >= params.getAbsentValueSentinel()) {
                throw new IllegalArgumentException("CAPE value coefficient must be less than absent sentinel");
            }
            int offset = coeffIndex * Short.BYTES;
            for (int i = Short.BYTES - 1; i >= 0; i--) {
                int byteIndex = offset + i;
                if (byteIndex < value.length) {
                    value[byteIndex] = (byte) (coeff & 0xFF);
                }
                coeff >>>= Byte.SIZE;
            }
        }
        return value;
    }

    private static long readUnsignedChunk(byte[] bytes, int chunkIndex, int chunkBitLength) {
        if (chunkBitLength != Short.SIZE) {
            throw new IllegalArgumentException("CAPE value fingerprint chunks must be 16-bit");
        }
        int offset = chunkIndex * Short.BYTES;
        long value = 0L;
        for (int i = 0; i < Short.BYTES; i++) {
            int byteIndex = offset + i;
            int byteValue = byteIndex < bytes.length ? bytes[byteIndex] & 0xFF : 0;
            value = (value << Byte.SIZE) | byteValue;
        }
        return value;
    }

    static byte[] serializeValueSet(List<byte[]> values, CapePirParams params) {
        MathPreconditions.checkLessOrEqual("values.size", values.size(), params.getMaxValueNumPerKeyword());
        byte[] payload = new byte[params.getMaxValueNumPerKeyword() * params.getValueByteLength()];
        int offset = 0;
        for (byte[] value : values) {
            MathPreconditions.checkEqual("value.length", "value_byte_length", value.length, params.getValueByteLength());
            System.arraycopy(value, 0, payload, offset, params.getValueByteLength());
            offset += params.getValueByteLength();
        }
        return payload;
    }

    static List<byte[]> deserializeValueSet(byte[] payload, CapePirParams params) {
        MathPreconditions.checkEqual(
            "payload.length", "maxValueNumPerKeyword * valueByteLength", payload.length,
            params.getMaxValueNumPerKeyword() * params.getValueByteLength()
        );
        List<byte[]> values = new ArrayList<>(params.getMaxValueNumPerKeyword());
        for (int i = 0; i < params.getMaxValueNumPerKeyword(); i++) {
            byte[] value = BytesUtils.clone(payload, i * params.getValueByteLength(), params.getValueByteLength());
            if (!allZero(value)) {
                values.add(value);
            }
        }
        return values;
    }

    static byte[] keywordToByteArray(Object keyword) {
        if (keyword instanceof byte[]) {
            return BytesUtils.clone((byte[]) keyword);
        }
        if (keyword instanceof ByteBuffer) {
            return byteBufferToByteArray((ByteBuffer) keyword);
        }
        return ObjectUtils.objectToByteArray(keyword);
    }

    private static boolean allZero(byte[] value) {
        for (byte b : value) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    private static <T> byte[][] buildSameSeedStorage(Map<T, byte[]> keyValueMap, int keywordNum, int valueByteLength,
                                                     byte[] seed) {
        Arity3ByteFusePosition<T> position = new Arity3ByteFusePosition<>(
            EnvType.STANDARD, keywordNum, valueByteLength, seed
        );
        List<T> keys = new ArrayList<>(keyValueMap.keySet());
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
        if (peelSize != keyNum) {
            return null;
        }
        byte[][] storage = new byte[filterLength][valueByteLength];
        for (int peelIndex = peelSize - 1; peelIndex >= 0; peelIndex--) {
            int keyIndex = peelKeyIndexes[peelIndex];
            int slot = peelSlots[peelIndex];
            byte[] value = keyValueMap.get(keys.get(keyIndex));
            for (int byteIndex = 0; byteIndex < valueByteLength; byteIndex++) {
                byte share = value[byteIndex];
                for (int pos : keyPositions[keyIndex]) {
                    if (pos != slot) {
                        share -= storage[pos][byteIndex];
                    }
                }
                storage[slot][byteIndex] = share;
            }
        }
        return storage;
    }

    private static <T> SameSeedFuseGraph<T> buildSameSeedFuseGraph(Collection<T> keys, int keywordNum,
                                                                   int valueByteLength, byte[] seed) {
        Arity3ByteFusePosition<T> position = new Arity3ByteFusePosition<>(
            EnvType.STANDARD, keywordNum, valueByteLength, seed
        );
        List<T> keyList = new ArrayList<>(keys);
        int keyNum = keyList.size();
        int filterLength = position.filterLength();
        int[][] keyPositions = new int[keyNum][];
        int[] degrees = new int[filterLength];
        int[] xorKeyIndexes = new int[filterLength];
        for (int keyIndex = 0; keyIndex < keyNum; keyIndex++) {
            keyPositions[keyIndex] = position.positions(keyList.get(keyIndex));
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
        if (peelSize != keyNum) {
            return null;
        }
        return new SameSeedFuseGraph<>(keyList, keyPositions, peelKeyIndexes, peelSlots, peelSize, filterLength);
    }

    private static <T> long[] assignLongStorageForBlock(SameSeedFuseGraph<T> graph,
                                                        LongPayloadBlockProvider<T> payloadBlockProvider,
                                                        int blockIndex, long plainModulus) {
        long[] storage = new long[graph.filterLength];
        for (int peelIndex = graph.peelSize - 1; peelIndex >= 0; peelIndex--) {
            int keyIndex = graph.peelKeyIndexes[peelIndex];
            int slot = graph.peelSlots[peelIndex];
            long share = Math.floorMod(payloadBlockProvider.get(graph.keys.get(keyIndex), blockIndex), plainModulus);
            for (int pos : graph.keyPositions[keyIndex]) {
                if (pos != slot) {
                    share = Math.floorMod(share - storage[pos], plainModulus);
                }
            }
            storage[slot] = share;
        }
        return storage;
    }

    private static <T> long[] assignLongStorageForBlockByIndex(SameSeedFuseGraph<T> graph,
                                                               IndexedLongPayloadBlockProvider payloadBlockProvider,
                                                               int blockIndex, long plainModulus) {
        long[] storage = new long[graph.filterLength];
        for (int peelIndex = graph.peelSize - 1; peelIndex >= 0; peelIndex--) {
            int keyIndex = graph.peelKeyIndexes[peelIndex];
            int slot = graph.peelSlots[peelIndex];
            long share = Math.floorMod(payloadBlockProvider.get(keyIndex, blockIndex), plainModulus);
            for (int pos : graph.keyPositions[keyIndex]) {
                if (pos != slot) {
                    share = Math.floorMod(share - storage[pos], plainModulus);
                }
            }
            storage[slot] = share;
        }
        return storage;
    }

    static <T> long[] assignLongStorageForBlockGroupForTest(Collection<T> keys, int payloadBlockNum,
                                                            CapePirParams params, byte[] seed,
                                                            IndexedLongPayloadBlockProvider provider) {
        SameSeedFuseGraph<T> graph = buildSameSeedFuseGraph(
            keys, keys.size(), params.getPayloadBlockByteLength(), seed
        );
        if (graph == null) {
            throw new IllegalStateException("Cannot build same-seed CAPE streaming long Binary Fuse Filter");
        }
        return assignLongStorageForBlockGroupFlat(graph, provider, 0, payloadBlockNum, params.getPlainModulus());
    }

    private static <T> long[] assignLongStorageForBlockGroupFlat(SameSeedFuseGraph<T> graph,
                                                                 IndexedLongPayloadBlockProvider payloadBlockProvider,
                                                                 int groupStartBlock, int groupBlockNum,
                                                                 long plainModulus) {
        long[] slotBlockValues = new long[graph.filterLength * groupBlockNum];
        for (int peelIndex = graph.peelSize - 1; peelIndex >= 0; peelIndex--) {
            int keyIndex = graph.peelKeyIndexes[peelIndex];
            int slot = graph.peelSlots[peelIndex];
            int[] positions = graph.keyPositions[keyIndex];
            for (int offset = 0; offset < groupBlockNum; offset++) {
                int blockIndex = groupStartBlock + offset;
                long share = Math.floorMod(payloadBlockProvider.get(keyIndex, blockIndex), plainModulus);
                for (int pos : positions) {
                    if (pos != slot) {
                        share = Math.floorMod(share - slotBlockValues[pos * groupBlockNum + offset], plainModulus);
                    }
                }
                slotBlockValues[slot * groupBlockNum + offset] = share;
            }
        }
        return slotBlockValues;
    }

    private static <T> long[] assignPackedBloomStorageForBlockFlat(
        SameSeedFuseGraph<T> graph, IndexedPackedBloomPayloadProvider payloadProvider, int packedBlockIndex,
        int coefficientStride, long plainModulus) {
        long[] slotCoefficientValues = new long[graph.filterLength * coefficientStride];
        for (int peelIndex = graph.peelSize - 1; peelIndex >= 0; peelIndex--) {
            int keyIndex = graph.peelKeyIndexes[peelIndex];
            int slot = graph.peelSlots[peelIndex];
            int[] positions = graph.keyPositions[keyIndex];
            for (int offset = 0; offset < coefficientStride; offset++) {
                long share = payloadProvider.get(keyIndex, packedBlockIndex, offset);
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

    @Deprecated
    private static <T> long[] buildSameSeedLongStorage(Map<T, Long> keyValueMap, int keywordNum, int valueByteLength,
                                                       byte[] seed, long plainModulus) {
        SameSeedFuseGraph<T> graph = buildSameSeedFuseGraph(keyValueMap.keySet(), keywordNum, valueByteLength, seed);
        if (graph == null) {
            return null;
        }
        return assignLongStorageForBlock(graph, (key, ignored) -> keyValueMap.get(key), 0, plainModulus);
    }

    private static byte[] fingerprint(byte[] keywordBytes, CapePirParams params) {
        Hash hash = HashFactory.createInstance(HashFactory.HashType.BC_SHA3_256, params.getFingerprintByteLength());
        byte[] fingerprint = hash.digestToBytes(keywordBytes);
        BytesUtils.reduceByteArray(fingerprint, params.getFingerprintBitLength());
        return fingerprint;
    }

    private static long blockToLong(byte[] block, CapePirParams params) {
        MathPreconditions.checkLessOrEqual("payload_block_byte_length", block.length, Long.BYTES);
        long value = 0L;
        for (byte b : block) {
            value = (value << Byte.SIZE) | (b & 0xFFL);
        }
        MathPreconditions.checkLess("payload_block", value, params.getPlainModulus());
        return value;
    }

    private static byte[] byteBufferToByteArray(ByteBuffer byteBuffer) {
        ByteBuffer duplicate = byteBuffer.asReadOnlyBuffer();
        duplicate.rewind();
        byte[] bytes = new byte[duplicate.remaining()];
        duplicate.get(bytes);
        return bytes;
    }

    static class ValueWithBloomFilter {
        /**
         * value.
         */
        private final byte[] value;
        /**
         * Bloom Filter bytes.
         */
        private final byte[] bloomFilterBytes;
        /**
         * whether this item is present.
         */
        private final boolean present;

        ValueWithBloomFilter(byte[] value, byte[] bloomFilterBytes) {
            this(value, bloomFilterBytes, true);
        }

        ValueWithBloomFilter(byte[] value, byte[] bloomFilterBytes, boolean present) {
            this.value = BytesUtils.clone(value);
            this.bloomFilterBytes = BytesUtils.clone(bloomFilterBytes);
            this.present = present;
        }

        byte[] getValue() {
            return BytesUtils.clone(value);
        }

        byte[] getBloomFilterBytes() {
            return BytesUtils.clone(bloomFilterBytes);
        }

        boolean isPresent() {
            return present;
        }
    }

    static class BinaryFuseFilterData {
        private final byte[] seed;
        private final byte[][][] storage;

        BinaryFuseFilterData(byte[] seed, byte[][][] storage) {
            this.seed = BytesUtils.clone(seed);
            this.storage = Arrays.stream(storage)
                .map(block -> Arrays.stream(block).map(BytesUtils::clone).toArray(byte[][]::new))
                .toArray(byte[][][]::new);
        }

        byte[] getSeed() {
            return BytesUtils.clone(seed);
        }

        byte[][][] getStorage() {
            return Arrays.stream(storage)
                .map(block -> Arrays.stream(block).map(BytesUtils::clone).toArray(byte[][]::new))
                .toArray(byte[][][]::new);
        }
    }

    static class LongBffBuildStats {
        private int payloadBlockNum;
        private int keywordNum;
        private int filterLength;
        private int packedGroupNum;
        private int blocksPerPackedMatrix;
        private long graphBuildTimeMillis;
        private long assignmentTotalTimeMillis;
        private long matrixizeTotalTimeMillis;
        private long preprocessTotalTimeMillis;
        private boolean fullBloomStorageMaterialized;
        private boolean bloomOnlyMatricesMaterialized;
        private boolean innerLoopMapLookup;
        private boolean innerLoopByteBufferWrap;

        private void set(int payloadBlockNum, int keywordNum, int filterLength, long graphBuildTimeMillis,
                         long assignmentTotalTimeMillis) {
            set(payloadBlockNum, keywordNum, filterLength, graphBuildTimeMillis, assignmentTotalTimeMillis,
                CommonUtils.getUnitNum(payloadBlockNum, 1), 1, 0L, 0L, true, true, true, true);
        }

        private void set(int payloadBlockNum, int keywordNum, int filterLength, long graphBuildTimeMillis,
                         long assignmentTotalTimeMillis, int packedGroupNum, int blocksPerPackedMatrix,
                         long matrixizeTotalTimeMillis, long preprocessTotalTimeMillis,
                         boolean fullBloomStorageMaterialized, boolean bloomOnlyMatricesMaterialized,
                         boolean innerLoopMapLookup, boolean innerLoopByteBufferWrap) {
            this.payloadBlockNum = payloadBlockNum;
            this.keywordNum = keywordNum;
            this.filterLength = filterLength;
            this.packedGroupNum = packedGroupNum;
            this.blocksPerPackedMatrix = blocksPerPackedMatrix;
            this.graphBuildTimeMillis = graphBuildTimeMillis;
            this.assignmentTotalTimeMillis = assignmentTotalTimeMillis;
            this.matrixizeTotalTimeMillis = matrixizeTotalTimeMillis;
            this.preprocessTotalTimeMillis = preprocessTotalTimeMillis;
            this.fullBloomStorageMaterialized = fullBloomStorageMaterialized;
            this.bloomOnlyMatricesMaterialized = bloomOnlyMatricesMaterialized;
            this.innerLoopMapLookup = innerLoopMapLookup;
            this.innerLoopByteBufferWrap = innerLoopByteBufferWrap;
        }

        int getPayloadBlockNum() {
            return payloadBlockNum;
        }

        int getKeywordNum() {
            return keywordNum;
        }

        int getFilterLength() {
            return filterLength;
        }

        long getGraphBuildTimeMillis() {
            return graphBuildTimeMillis;
        }

        long getAssignmentTotalTimeMillis() {
            return assignmentTotalTimeMillis;
        }

        int getPackedGroupNum() {
            return packedGroupNum;
        }

        int getBlocksPerPackedMatrix() {
            return blocksPerPackedMatrix;
        }

        long getPreprocessTotalTimeMillis() {
            return preprocessTotalTimeMillis;
        }

        long getMatrixizeTotalTimeMillis() {
            return matrixizeTotalTimeMillis;
        }

        boolean isFullBloomStorageMaterialized() {
            return fullBloomStorageMaterialized;
        }

        boolean isBloomOnlyMatricesMaterialized() {
            return bloomOnlyMatricesMaterialized;
        }

        boolean isInnerLoopMapLookup() {
            return innerLoopMapLookup;
        }

        boolean isInnerLoopByteBufferWrap() {
            return innerLoopByteBufferWrap;
        }
    }

    static class SameSeedFuseGraph<T> {
        private final List<T> keys;
        private final int[][] keyPositions;
        private final int[] peelKeyIndexes;
        private final int[] peelSlots;
        private final int peelSize;
        private final int filterLength;

        private SameSeedFuseGraph(List<T> keys, int[][] keyPositions, int[] peelKeyIndexes, int[] peelSlots,
                                  int peelSize, int filterLength) {
            this.keys = keys;
            this.keyPositions = keyPositions;
            this.peelKeyIndexes = peelKeyIndexes;
            this.peelSlots = peelSlots;
            this.peelSize = peelSize;
            this.filterLength = filterLength;
        }

        int[] getKeyPositions(int keyIndex) {
            return Arrays.copyOf(keyPositions[keyIndex], keyPositions[keyIndex].length);
        }
    }
}
