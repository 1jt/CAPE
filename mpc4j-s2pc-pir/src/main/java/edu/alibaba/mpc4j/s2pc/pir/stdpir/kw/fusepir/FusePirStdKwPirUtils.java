package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import edu.alibaba.mpc4j.common.structure.fusefilter.Arity3ByteFuseFilter;
import edu.alibaba.mpc4j.common.structure.fusefilter.Arity3ByteFusePosition;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.crypto.hash.Hash;
import edu.alibaba.mpc4j.common.tool.crypto.hash.HashFactory;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.common.tool.utils.ObjectUtils;

import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;

/**
 * FUSE_PIR standard keyword PIR utilities.
 *
 * <p>FUSE_PIR uses Chalamet's arity-3 additive Binary Fuse Filter as the key-to-share map. In contrast to Chalamet's
 * single-value payload, FUSE_PIR encodes a fixed-size value set as {@code fingerprint(keyword) || value_0 || ...}. Missing
 * values are padded with all-zero blocks. The first version skips all-zero padded value blocks during decoding; a later
 * version should add an explicit value count if all-zero values must be supported as real values.</p>
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
class FusePirStdKwPirUtils {

    private FusePirStdKwPirUtils() {
        // empty
    }

    static <T> byte[] buildMultiValuePayload(T keyword, List<byte[]> values, FusePirStdKwPirParams params) {
        MathPreconditions.checkLessOrEqual("values.size", values.size(), params.getMaxValueNumPerKeyword());
        values.forEach(value -> MathPreconditions.checkEqual(
            "value.length", "value_byte_length", value.length, params.getValueByteLength()
        ));
        byte[] fingerprint = fingerprint(ObjectUtils.objectToByteArray(keyword), params);
        byte[] payload = new byte[params.getPayloadByteLength()];
        System.arraycopy(fingerprint, 0, payload, 0, fingerprint.length);
        int offset = fingerprint.length;
        for (byte[] value : values) {
            System.arraycopy(value, 0, payload, offset, params.getValueByteLength());
            offset += params.getValueByteLength();
        }
        return payload;
    }

    static byte[][] splitPayloadToBlocks(byte[] payload, FusePirStdKwPirParams params) {
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

    static List<byte[]> deserializeValueSet(byte[] payload, FusePirStdKwPirParams params) {
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

    static byte[] serializeValueSet(List<byte[]> values, FusePirStdKwPirParams params) {
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

    static <T> BinaryFuseFilterData buildBinaryFuseFilters(Map<T, List<byte[]>> keywordValueMap,
                                                           FusePirStdKwPirParams params, SecureRandom secureRandom) {
        MathPreconditions.checkPositive("keywordValueMap.size", keywordValueMap.size());
        int blockNum = params.getPayloadBlockNum();
        Map<T, byte[][]> keywordPayloadBlocks = new LinkedHashMap<>(keywordValueMap.size());
        for (Map.Entry<T, List<byte[]>> entry : keywordValueMap.entrySet()) {
            byte[][] blocks = splitPayloadToBlocks(
                buildMultiValuePayload(entry.getKey(), entry.getValue(), params), params
            );
            byte[][] paddedBlocks = new byte[blockNum][params.getPayloadBlockByteLength()];
            for (int blockIndex = 0; blockIndex < blockNum; blockIndex++) {
                if (blockIndex < blocks.length) {
                    paddedBlocks[blockIndex] = BytesUtils.clone(blocks[blockIndex]);
                }
            }
            keywordPayloadBlocks.put(entry.getKey(), paddedBlocks);
        }
        if (blockNum == 1) {
            Map<T, byte[]> blockMap = new LinkedHashMap<>(keywordPayloadBlocks.size());
            keywordPayloadBlocks.forEach((key, blocks) -> blockMap.put(key, BytesUtils.clone(blocks[0])));
            Arity3ByteFuseFilter<T> fuseFilter = new Arity3ByteFuseFilter<>(
                EnvType.STANDARD, blockMap, params.getPayloadBlockByteLength(), secureRandom
            );
            return new BinaryFuseFilterData(BytesUtils.clone(fuseFilter.seed()), new byte[][][]{fuseFilter.storage()});
        }
        List<T> keys = new ArrayList<>(keywordPayloadBlocks.keySet());
        int maxEncodeTries = 1 << 10;
        byte[] seed = new byte[16];
        for (int encodeTry = 0; encodeTry < maxEncodeTries; encodeTry++) {
            secureRandom.nextBytes(seed);
            PeelResult<T> peelResult = peel(keys, keywordPayloadBlocks.size(), params.getPayloadBlockByteLength(), seed);
            if (peelResult != null) {
                byte[][][] storage = assignSharesForAllBlocks(
                    peelResult, keywordPayloadBlocks, blockNum, params.getPayloadBlockByteLength()
                );
                return new BinaryFuseFilterData(seed, storage);
            }
        }
        throw new IllegalStateException("Cannot build same-seed FUSE_PIR Binary Fuse Filter");
    }

    static <T> BinaryFuseMatrixData buildBinaryFuseMatrices(Map<T, List<byte[]>> keywordValueMap,
                                                            FusePirStdKwPirParams params, SecureRandom secureRandom) {
        MathPreconditions.checkPositive("keywordValueMap.size", keywordValueMap.size());
        Map<T, long[]> keywordPayloadBlocks = new LinkedHashMap<>(keywordValueMap.size());
        for (Map.Entry<T, List<byte[]>> entry : keywordValueMap.entrySet()) {
            keywordPayloadBlocks.put(entry.getKey(), payloadToLongBlocks(
                buildMultiValuePayload(entry.getKey(), entry.getValue(), params), params
            ));
        }
        List<T> keys = new ArrayList<>(keywordPayloadBlocks.keySet());
        int maxEncodeTries = 1 << 10;
        byte[] seed = new byte[16];
        for (int encodeTry = 0; encodeTry < maxEncodeTries; encodeTry++) {
            secureRandom.nextBytes(seed);
            PeelResult<T> peelResult = peel(keys, keywordPayloadBlocks.size(), params.getPayloadBlockByteLength(), seed);
            if (peelResult != null) {
                long[][] storage = assignCoefficientSharesForAllBlocks(peelResult, keywordPayloadBlocks, params);
                long[][][] matrices = matrixizePackedCoefficientBff(storage, params);
                return new BinaryFuseMatrixData(seed, matrices);
            }
        }
        throw new IllegalStateException("Cannot build same-seed FUSE_PIR Binary Fuse matrix");
    }

    private static <T> PeelResult<T> peel(List<T> keys, int keywordNum, int valueByteLength, byte[] seed) {
        Arity3ByteFusePosition<T> position = new Arity3ByteFusePosition<>(
            EnvType.STANDARD, keywordNum, valueByteLength, seed
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
        if (peelSize != keyNum) {
            return null;
        }
        return new PeelResult<>(keys, keyPositions, peelKeyIndexes, peelSlots, peelSize, filterLength);
    }

    private static <T> byte[][][] assignSharesForAllBlocks(PeelResult<T> peelResult,
                                                           Map<T, byte[][]> keywordPayloadBlocks, int blockNum,
                                                           int valueByteLength) {
        byte[][][] storage = new byte[blockNum][peelResult.filterLength][valueByteLength];
        for (int peelIndex = peelResult.peelSize - 1; peelIndex >= 0; peelIndex--) {
            int keyIndex = peelResult.peelKeyIndexes[peelIndex];
            int slot = peelResult.peelSlots[peelIndex];
            byte[][] valueBlocks = keywordPayloadBlocks.get(peelResult.keys.get(keyIndex));
            for (int blockIndex = 0; blockIndex < blockNum; blockIndex++) {
                byte[] value = valueBlocks[blockIndex];
                for (int byteIndex = 0; byteIndex < valueByteLength; byteIndex++) {
                    byte share = value[byteIndex];
                    for (int pos : peelResult.keyPositions[keyIndex]) {
                        if (pos != slot) {
                            share -= storage[blockIndex][pos][byteIndex];
                        }
                    }
                    storage[blockIndex][slot][byteIndex] = share;
                }
            }
        }
        return storage;
    }

    private static <T> long[][] assignCoefficientSharesForAllBlocks(PeelResult<T> peelResult,
                                                                    Map<T, long[]> keywordPayloadBlocks,
                                                                    FusePirStdKwPirParams params) {
        long[][] storage = new long[params.getPayloadBlockNum()][peelResult.filterLength];
        long modulus = params.getPlainModulus();
        for (int blockIndex = 0; blockIndex < params.getPayloadBlockNum(); blockIndex++) {
            for (int peelIndex = peelResult.peelSize - 1; peelIndex >= 0; peelIndex--) {
                int keyIndex = peelResult.peelKeyIndexes[peelIndex];
                int slot = peelResult.peelSlots[peelIndex];
                long[] valueBlocks = keywordPayloadBlocks.get(peelResult.keys.get(keyIndex));
                long share = valueBlocks[blockIndex] % modulus;
                for (int pos : peelResult.keyPositions[keyIndex]) {
                    if (pos != slot) {
                        share = subMod(share, storage[blockIndex][pos], modulus);
                    }
                }
                storage[blockIndex][slot] = share;
            }
        }
        return storage;
    }

    static long[][] matrixizeBff(byte[][] dPrime, FusePirStdKwPirParams params) {
        MathPreconditions.checkLessOrEqual("dPrime.length", dPrime.length, params.getMatrixRowNum() * params.getMatrixColNum());
        long[][] matrix = new long[params.getMatrixRowNum()][params.getMatrixColNum()];
        for (int u = 0; u < dPrime.length; u++) {
            int[] rowCol = getRowColFromBffIndex(u, params);
            matrix[rowCol[0]][rowCol[1]] = blockToLong(dPrime[u], params);
        }
        return matrix;
    }

    static long[][][] matrixizePackedBff(byte[][][] dPrimes, FusePirStdKwPirParams params) {
        MathPreconditions.checkEqual("dPrimes.length", "payloadBlockNum", dPrimes.length,
            params.getPayloadBlockNum());
        int blocksPerPackedMatrix = params.getBlocksPerPackedMatrix();
        long[][][] matrices = new long[params.getPackedMatrixGroupNum()]
            [params.getMatrixRowNum()][params.getMatrixColNum() * blocksPerPackedMatrix];
        for (int blockIndex = 0; blockIndex < dPrimes.length; blockIndex++) {
            MathPreconditions.checkLessOrEqual("dPrime.length", dPrimes[blockIndex].length,
                params.getMatrixRowNum() * params.getMatrixColNum());
            int groupIndex = blockIndex / blocksPerPackedMatrix;
            int blockOffset = blockIndex % blocksPerPackedMatrix;
            for (int u = 0; u < dPrimes[blockIndex].length; u++) {
                int[] rowCol = getRowColFromBffIndex(u, params);
                matrices[groupIndex][rowCol[0]][rowCol[1] * blocksPerPackedMatrix + blockOffset]
                    = blockToLong(dPrimes[blockIndex][u], params);
            }
        }
        return matrices;
    }

    private static long[][][] matrixizePackedCoefficientBff(long[][] dPrimes, FusePirStdKwPirParams params) {
        MathPreconditions.checkEqual("dPrimes.length", "payloadBlockNum", dPrimes.length,
            params.getPayloadBlockNum());
        int blocksPerPackedMatrix = params.getBlocksPerPackedMatrix();
        long[][][] matrices = new long[params.getPackedMatrixGroupNum()]
            [params.getMatrixRowNum()][params.getMatrixColNum() * blocksPerPackedMatrix];
        for (int blockIndex = 0; blockIndex < dPrimes.length; blockIndex++) {
            MathPreconditions.checkLessOrEqual("dPrime.length", dPrimes[blockIndex].length,
                params.getMatrixRowNum() * params.getMatrixColNum());
            int groupIndex = blockIndex / blocksPerPackedMatrix;
            int blockOffset = blockIndex % blocksPerPackedMatrix;
            for (int u = 0; u < dPrimes[blockIndex].length; u++) {
                int[] rowCol = getRowColFromBffIndex(u, params);
                matrices[groupIndex][rowCol[0]][rowCol[1] * blocksPerPackedMatrix + blockOffset]
                    = dPrimes[blockIndex][u];
            }
        }
        return matrices;
    }

    static <T> int[] getHashPositions(T keyword, int keywordNum, byte[] seed, FusePirStdKwPirParams params) {
        Arity3ByteFusePosition<T> position = new Arity3ByteFusePosition<>(
            EnvType.STANDARD, keywordNum, params.getPayloadBlockByteLength(), seed
        );
        return position.positions(keyword);
    }

    static int[] getRowColFromBffIndex(int u, FusePirStdKwPirParams params) {
        MathPreconditions.checkNonNegativeInRange("u", u, params.getBffSlotNum());
        return new int[]{u % params.getMatrixRowNum(), u / params.getMatrixRowNum()};
    }

    static <T> List<byte[]> decodePayloadBlocks(T keyword, byte[][] decryptedBlocks, FusePirStdKwPirParams params) {
        byte[] payload = new byte[params.getPayloadByteLength()];
        int offset = 0;
        for (byte[] block : decryptedBlocks) {
            int copyByteLength = Math.min(block.length, payload.length - offset);
            if (copyByteLength <= 0) {
                break;
            }
            System.arraycopy(block, 0, payload, offset, copyByteLength);
            offset += copyByteLength;
        }
        byte[] actualFingerprint = Arrays.copyOf(payload, params.getFingerprintByteLength());
        byte[] expectFingerprint = fingerprint(ObjectUtils.objectToByteArray(keyword), params);
        if (!BytesUtils.equals(actualFingerprint, expectFingerprint)) {
            return List.of();
        }
        List<byte[]> values = new ArrayList<>(params.getMaxValueNumPerKeyword());
        int valueOffset = params.getFingerprintByteLength();
        for (int i = 0; i < params.getMaxValueNumPerKeyword(); i++) {
            byte[] value = BytesUtils.clone(payload, valueOffset, params.getValueByteLength());
            if (!allZero(value)) {
                values.add(value);
            }
            valueOffset += params.getValueByteLength();
        }
        return values;
    }

    static <T> List<byte[]> decodePackedPayloadCoefficients(T keyword, long[] coeffs, FusePirStdKwPirParams params) {
        MathPreconditions.checkGreaterOrEqual("coeffs.length", coeffs.length, params.getPayloadBlockNum());
        byte[][] blocks = new byte[params.getPayloadBlockNum()][];
        for (int blockIndex = 0; blockIndex < params.getPayloadBlockNum(); blockIndex++) {
            blocks[blockIndex] = longToBlock(coeffs[blockIndex], params);
        }
        return decodePayloadBlocks(keyword, blocks, params);
    }

    static byte[] reconstruct(byte[][] storage, int[] positions, FusePirStdKwPirParams params) {
        byte[] value = new byte[params.getPayloadBlockByteLength()];
        for (int position : positions) {
            for (int i = 0; i < value.length; i++) {
                value[i] += storage[position][i];
            }
        }
        return value;
    }

    static byte[] longToBlock(long value, FusePirStdKwPirParams params) {
        byte[] block = new byte[params.getPayloadBlockByteLength()];
        for (int i = block.length - 1; i >= 0; i--) {
            block[i] = (byte) value;
            value >>>= Byte.SIZE;
        }
        return block;
    }

    private static byte[] fingerprint(byte[] keywordBytes, FusePirStdKwPirParams params) {
        Hash hash = HashFactory.createInstance(HashFactory.HashType.BC_SHA3_256, params.getFingerprintByteLength());
        byte[] fingerprint = hash.digestToBytes(keywordBytes);
        BytesUtils.reduceByteArray(fingerprint, params.getFingerprintBitLength());
        return fingerprint;
    }

    private static long blockToLong(byte[] block, FusePirStdKwPirParams params) {
        MathPreconditions.checkLessOrEqual("payload_block_byte_length", block.length, Long.BYTES);
        long value = 0L;
        for (byte b : block) {
            value = (value << Byte.SIZE) | (b & 0xFFL);
        }
        MathPreconditions.checkLess("payload_block", value, params.getPlainModulus());
        return value;
    }

    private static long[] payloadToLongBlocks(byte[] payload, FusePirStdKwPirParams params) {
        byte[][] blocks = splitPayloadToBlocks(payload, params);
        long[] longBlocks = new long[params.getPayloadBlockNum()];
        for (int blockIndex = 0; blockIndex < blocks.length; blockIndex++) {
            longBlocks[blockIndex] = blockToLong(blocks[blockIndex], params);
        }
        return longBlocks;
    }

    private static long subMod(long a, long b, long modulus) {
        long result = (a - b) % modulus;
        return result >= 0 ? result : result + modulus;
    }

    private static boolean allZero(byte[] value) {
        for (byte b : value) {
            if (b != 0) {
                return false;
            }
        }
        return true;
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

        byte[][] getStorage(int blockIndex) {
            return Arrays.stream(storage[blockIndex]).map(BytesUtils::clone).toArray(byte[][]::new);
        }

        byte[][][] getStorage() {
            return Arrays.stream(storage)
                .map(block -> Arrays.stream(block).map(BytesUtils::clone).toArray(byte[][]::new))
                .toArray(byte[][][]::new);
        }

        int getBlockNum() {
            return storage.length;
        }
    }

    static class BinaryFuseMatrixData {
        private final byte[] seed;
        private final long[][][] matrices;

        BinaryFuseMatrixData(byte[] seed, long[][][] matrices) {
            this.seed = BytesUtils.clone(seed);
            this.matrices = Arrays.stream(matrices)
                .map(matrix -> Arrays.stream(matrix).map(long[]::clone).toArray(long[][]::new))
                .toArray(long[][][]::new);
        }

        byte[] getSeed() {
            return BytesUtils.clone(seed);
        }

        long[][][] getMatrices() {
            return Arrays.stream(matrices)
                .map(matrix -> Arrays.stream(matrix).map(long[]::clone).toArray(long[][]::new))
                .toArray(long[][][]::new);
        }
    }

    private static class PeelResult<T> {
        /**
         * keys in key-index order.
         */
        private final List<T> keys;
        /**
         * key positions.
         */
        private final int[][] keyPositions;
        /**
         * peeled key indexes.
         */
        private final int[] peelKeyIndexes;
        /**
         * peeled slots.
         */
        private final int[] peelSlots;
        /**
         * peel size.
         */
        private final int peelSize;
        /**
         * filter length.
         */
        private final int filterLength;

        private PeelResult(List<T> keys, int[][] keyPositions, int[] peelKeyIndexes, int[] peelSlots, int peelSize,
                           int filterLength) {
            this.keys = new ArrayList<>(keys);
            this.keyPositions = Arrays.stream(keyPositions).map(int[]::clone).toArray(int[][]::new);
            this.peelKeyIndexes = Arrays.copyOf(peelKeyIndexes, peelSize);
            this.peelSlots = Arrays.copyOf(peelSlots, peelSize);
            this.peelSize = peelSize;
            this.filterLength = filterLength;
        }
    }

}
