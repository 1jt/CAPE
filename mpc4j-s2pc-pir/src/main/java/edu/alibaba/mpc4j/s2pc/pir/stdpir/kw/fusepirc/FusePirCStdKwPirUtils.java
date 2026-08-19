package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc;

import edu.alibaba.mpc4j.common.structure.fusefilter.Arity3ByteFusePosition;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.crypto.hash.HashFactory;
import edu.alibaba.mpc4j.common.tool.utils.ObjectUtils;

import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;

/**
 * FUSE_PIR_C standard keyword PIR utilities.
 *
 * @author Weiran Liu
 * @date 2026/06/16
 */
class FusePirCStdKwPirUtils {
    /**
     * BFF seed byte length.
     */
    static final int BFF_SEED_BYTE_LENGTH = 16;
    /**
     * Maximum BFF seed attempts.
     */
    private static final int MAX_BFF_SEED_ATTEMPTS = 1 << 10;
    /**
     * Secure random state for BFF seed retries.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private FusePirCStdKwPirUtils() {
        // empty
    }

    static class RawBffStorage {
        final byte[] seed;
        final long[][] storageByBlock;
        final int seedTryCount;
        final long peelMs;
        final long shareAssignmentMs;

        RawBffStorage(byte[] seed, long[][] storageByBlock, int seedTryCount, long peelMs, long shareAssignmentMs) {
            this.seed = Arrays.copyOf(seed, seed.length);
            this.storageByBlock = storageByBlock;
            this.seedTryCount = seedTryCount;
            this.peelMs = peelMs;
            this.shareAssignmentMs = shareAssignmentMs;
        }
    }

    static class RawBffEncodedMatrix {
        final byte[] seed;
        final byte[] encodedMatrix;
        final int seedTryCount;
        final long peelMs;
        final long shareAssignmentMs;
        final long rawMatrixPackMs;

        RawBffEncodedMatrix(byte[] seed, byte[] encodedMatrix, int seedTryCount, long peelMs,
                            long shareAssignmentMs, long rawMatrixPackMs) {
            this.seed = Arrays.copyOf(seed, seed.length);
            this.encodedMatrix = encodedMatrix;
            this.seedTryCount = seedTryCount;
            this.peelMs = peelMs;
            this.shareAssignmentMs = shareAssignmentMs;
            this.rawMatrixPackMs = rawMatrixPackMs;
        }
    }

    static class RawBffMatrixHandle {
        final byte[] seed;
        final long rawMatrixHandle;
        final long estimatedRawEncodedMatrixBytes;
        final int seedTryCount;
        final long peelMs;
        final long shareAssignmentMs;
        final long rawMatrixPackMs;

        RawBffMatrixHandle(byte[] seed, long rawMatrixHandle, long estimatedRawEncodedMatrixBytes, int seedTryCount,
                           long peelMs, long shareAssignmentMs, long rawMatrixPackMs) {
            this.seed = Arrays.copyOf(seed, seed.length);
            this.rawMatrixHandle = rawMatrixHandle;
            this.estimatedRawEncodedMatrixBytes = estimatedRawEncodedMatrixBytes;
            this.seedTryCount = seedTryCount;
            this.peelMs = peelMs;
            this.shareAssignmentMs = shareAssignmentMs;
            this.rawMatrixPackMs = rawMatrixPackMs;
        }
    }

    static <T> int[] getHashPositions(T keyword, int keywordNum, byte[] seed, FusePirCStdKwPirParams params) {
        Arity3ByteFusePosition<T> fusePosition = new Arity3ByteFusePosition<>(
            EnvType.STANDARD, keywordNum, params.getPayloadBlockByteLength(), seed
        );
        return fusePosition.positions(keyword);
    }

    static int[] getRowColFromBffIndex(int u, FusePirCStdKwPirParams params) {
        MathPreconditions.checkNonNegativeInRange("u", u, params.getBffSlotNum());
        int row = u % params.getMatrixRowNum();
        int col = u / params.getMatrixRowNum();
        return new int[]{row, col};
    }

    static <T> byte[] keywordBytes(T keyword) {
        return ObjectUtils.objectToByteArray(keyword);
    }

    static long payloadToRawLong(byte[] payload) {
        long value = 0L;
        int start = Math.max(0, payload.length - Long.BYTES);
        for (int i = start; i < payload.length; i++) {
            value = (value << Byte.SIZE) | (payload[i] & 0xFFL);
        }
        return value;
    }

    static <T> long[] payloadToBlocks(T keyword, byte[] payload, FusePirCStdKwPirParams params) {
        byte[] encoded = encodePayloadBytes(keyword, payload, params);
        int blockBytes = params.getPayloadBlockByteLength();
        long[] blocks = new long[params.getPayloadBlockNum()];
        for (int blockIndex = 0; blockIndex < blocks.length; blockIndex++) {
            long value = 0L;
            for (int j = 0; j < blockBytes; j++) {
                int index = blockIndex * blockBytes + j;
                value <<= Byte.SIZE;
                if (index < encoded.length) {
                    value |= encoded[index] & 0xFFL;
                }
            }
            blocks[blockIndex] = value;
        }
        return blocks;
    }

    static <T> RawBffStorage buildRawAdditiveBffStorage(Map<T, long[]> keywordPayloadBlocks, int keywordNum,
                                                        byte[] seed, FusePirCStdKwPirParams params) {
        if (keywordPayloadBlocks.size() != keywordNum) {
            throw new IllegalArgumentException("FUSE_PIR_C BFF keyword count mismatch");
        }
        List<T> keys = new ArrayList<>(keywordPayloadBlocks.keySet());
        for (T key : keys) {
            long[] payloadBlocks = keywordPayloadBlocks.get(key);
            if (payloadBlocks == null || payloadBlocks.length != params.getPayloadBlockNum()) {
                throw new IllegalArgumentException("FUSE_PIR_C BFF payload block count mismatch");
            }
        }
        byte[] workingSeed = Arrays.copyOf(seed, seed.length);
        for (int attempt = 1; attempt <= MAX_BFF_SEED_ATTEMPTS; attempt++) {
            long peelStart = System.nanoTime();
            PeelResult peelResult = peel(keys, keywordNum, workingSeed, params);
            long peelMs = elapsedMs(peelStart);
            if (peelResult != null) {
                long shareStart = System.nanoTime();
                long[][] storage = assignAdditiveShares(keys, keywordPayloadBlocks, peelResult, params);
                return new RawBffStorage(workingSeed, storage, attempt, peelMs, elapsedMs(shareStart));
            }
            SECURE_RANDOM.nextBytes(workingSeed);
        }
        throw new IllegalStateException("FUSE_PIR_C BFF peeling failed after seed retries");
    }

    static <T> RawBffEncodedMatrix encodeRawMatrixFromAdditiveBffStorage(Map<T, long[]> keywordPayloadBlocks,
                                                                         int keywordNum, byte[] seed,
                                                                         FusePirCStdKwPirParams params) {
        if (keywordPayloadBlocks.size() != keywordNum) {
            throw new IllegalArgumentException("FUSE_PIR_C BFF keyword count mismatch");
        }
        List<T> keys = new ArrayList<>(keywordPayloadBlocks.keySet());
        for (T key : keys) {
            long[] payloadBlocks = keywordPayloadBlocks.get(key);
            if (payloadBlocks == null || payloadBlocks.length != params.getPayloadBlockNum()) {
                throw new IllegalArgumentException("FUSE_PIR_C BFF payload block count mismatch");
            }
        }
        byte[] workingSeed = Arrays.copyOf(seed, seed.length);
        for (int attempt = 1; attempt <= MAX_BFF_SEED_ATTEMPTS; attempt++) {
            long peelStart = System.nanoTime();
            PeelResult peelResult = peel(keys, keywordNum, workingSeed, params);
            long peelMs = elapsedMs(peelStart);
            if (peelResult != null) {
                long shareStart = System.nanoTime();
                byte[] encoded = encodePackedRawMatrix(keys, keywordPayloadBlocks, peelResult, params);
                long shareAndPackMs = elapsedMs(shareStart);
                return new RawBffEncodedMatrix(workingSeed, encoded, attempt, peelMs, shareAndPackMs, shareAndPackMs);
            }
            SECURE_RANDOM.nextBytes(workingSeed);
        }
        throw new IllegalStateException("FUSE_PIR_C BFF peeling failed after seed retries");
    }

    static <T> RawBffMatrixHandle createRawMatrixHandleFromAdditiveBffStorage(Map<T, long[]> keywordPayloadBlocks,
                                                                              int keywordNum, byte[] seed,
                                                                              FusePirCStdKwPirParams params,
                                                                              byte[] circuitBootstrapParams) {
        if (keywordPayloadBlocks.size() != keywordNum) {
            throw new IllegalArgumentException("FUSE_PIR_C BFF keyword count mismatch");
        }
        List<T> keys = new ArrayList<>(keywordPayloadBlocks.keySet());
        for (T key : keys) {
            long[] payloadBlocks = keywordPayloadBlocks.get(key);
            if (payloadBlocks == null || payloadBlocks.length != params.getPayloadBlockNum()) {
                throw new IllegalArgumentException("FUSE_PIR_C BFF payload block count mismatch");
            }
        }
        byte[] workingSeed = Arrays.copyOf(seed, seed.length);
        for (int attempt = 1; attempt <= MAX_BFF_SEED_ATTEMPTS; attempt++) {
            long peelStart = System.nanoTime();
            PeelResult peelResult = peel(keys, keywordNum, workingSeed, params);
            long peelMs = elapsedMs(peelStart);
            if (peelResult != null) {
                long rawMatrixHandle = 0L;
                try {
                    rawMatrixHandle = FusePirCStdKwPirNativeUtils.createEmptyRawMatrix(
                        params.getMatrixRowNum(), params.getMatrixColNum(), params.getPayloadBlockNum(),
                        params.getRowStride(), circuitBootstrapParams
                    );
                    long shareStart = System.nanoTime();
                    for (int payloadBlockIndex = 0; payloadBlockIndex < params.getPayloadBlockNum();
                         payloadBlockIndex++) {
                        long[] storageBlock = assignAdditiveSharesForSingleBlock(
                            keys, keywordPayloadBlocks, peelResult, params, payloadBlockIndex
                        );
                        FusePirCStdKwPirNativeUtils.setRawMatrixPayloadBlock(
                            rawMatrixHandle, payloadBlockIndex, storageBlock, params.getBffSlotNum(),
                            circuitBootstrapParams
                        );
                    }
                    FusePirCStdKwPirNativeUtils.finalizeRawMatrix(rawMatrixHandle, circuitBootstrapParams);
                    long shareAndPackMs = elapsedMs(shareStart);
                    return new RawBffMatrixHandle(
                        workingSeed, rawMatrixHandle, estimateRawEncodedMatrixBytes(params), attempt, peelMs,
                        shareAndPackMs, shareAndPackMs
                    );
                } catch (RuntimeException e) {
                    if (rawMatrixHandle != 0L) {
                        FusePirCStdKwPirNativeUtils.destroyRawMatrix(rawMatrixHandle);
                    }
                    throw e;
                }
            }
            SECURE_RANDOM.nextBytes(workingSeed);
        }
        throw new IllegalStateException("FUSE_PIR_C BFF peeling failed after seed retries");
    }

    static long rawEncodePayloadBlock(long block, FusePirCStdKwPirParams params) {
        long modulus = params.getRawRlweModulus();
        long payloadSpace = 1L << params.getPayloadElementBitLength();
        long scale = modulus / payloadSpace;
        return Math.floorMod(block, payloadSpace) * scale % modulus;
    }

    static <T> byte[] decodeBlocks(T keyword, long[] blocks, int valueByteLength, FusePirCStdKwPirParams params) {
        if (blocks.length != params.getPayloadBlockNum()) {
            throw new IllegalArgumentException("FUSE_PIR_C response block count mismatch");
        }
        int blockBytes = params.getPayloadBlockByteLength();
        byte[] encoded = new byte[blocks.length * blockBytes];
        for (int blockIndex = 0; blockIndex < blocks.length; blockIndex++) {
            long value = blocks[blockIndex];
            for (int j = blockBytes - 1; j >= 0; j--) {
                encoded[blockIndex * blockBytes + j] = (byte) value;
                value >>>= Byte.SIZE;
            }
        }
        byte[] expectedFingerprint = fingerprint(keyword, params);
        byte[] actualFingerprint = Arrays.copyOfRange(encoded, 0, params.getFingerprintByteLength());
        if (!Arrays.equals(expectedFingerprint, actualFingerprint)) {
            return new byte[0];
        }
        byte[] value = new byte[valueByteLength];
        int valueOffset = params.getFingerprintByteLength();
        System.arraycopy(encoded, valueOffset, value, 0, Math.min(value.length, encoded.length - valueOffset));
        return value;
    }

    private static <T> byte[] encodePayloadBytes(T keyword, byte[] payload, FusePirCStdKwPirParams params) {
        byte[] encoded = new byte[params.getPayloadBlockNum() * params.getPayloadBlockByteLength()];
        byte[] fingerprint = fingerprint(keyword, params);
        System.arraycopy(fingerprint, 0, encoded, 0, fingerprint.length);
        int valueOffset = params.getFingerprintByteLength();
        int valueBytes = params.getValueByteLength() * params.getMaxValueNumPerKeyword();
        System.arraycopy(payload, 0, encoded, valueOffset, Math.min(payload.length, valueBytes));
        return encoded;
    }

    private static <T> byte[] fingerprint(T keyword, FusePirCStdKwPirParams params) {
        byte[] digest = HashFactory.createInstance(EnvType.STANDARD, params.getFingerprintByteLength())
            .digestToBytes(keywordBytes(keyword));
        return Arrays.copyOf(digest, params.getFingerprintByteLength());
    }

    private static <T> PeelResult peel(List<T> keys, int keywordNum, byte[] seed, FusePirCStdKwPirParams params) {
        Arity3ByteFusePosition<T> fusePosition = new Arity3ByteFusePosition<>(
            EnvType.STANDARD, keywordNum, params.getPayloadBlockByteLength(), seed
        );
        if (fusePosition.filterLength() != params.getBffSlotNum()) {
            throw new IllegalStateException("FUSE_PIR_C BFF slot number mismatch");
        }
        int keyNum = keys.size();
        int[][] keyPositions = new int[keyNum][];
        int[] degrees = new int[params.getBffSlotNum()];
        int[] xorKeyIndexes = new int[params.getBffSlotNum()];
        for (int keyIndex = 0; keyIndex < keyNum; keyIndex++) {
            keyPositions[keyIndex] = fusePosition.positions(keys.get(keyIndex));
            if (keyPositions[keyIndex].length != params.getBffHashNum()) {
                throw new IllegalStateException("FUSE_PIR_C BFF position arity mismatch");
            }
            for (int position : keyPositions[keyIndex]) {
                degrees[position]++;
                xorKeyIndexes[position] ^= keyIndex;
            }
        }
        Queue<Integer> queue = new ArrayDeque<>();
        for (int slot = 0; slot < degrees.length; slot++) {
            if (degrees[slot] == 1) {
                queue.add(slot);
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
            if (keyIndex < 0 || keyIndex >= keyNum || removed[keyIndex]) {
                continue;
            }
            removed[keyIndex] = true;
            peelKeyIndexes[peelSize] = keyIndex;
            peelSlots[peelSize] = slot;
            peelSize++;
            for (int position : keyPositions[keyIndex]) {
                degrees[position]--;
                xorKeyIndexes[position] ^= keyIndex;
                if (degrees[position] == 1) {
                    queue.add(position);
                }
            }
        }
        if (peelSize != keyNum) {
            return null;
        }
        return new PeelResult(keyPositions, peelKeyIndexes, peelSlots, peelSize);
    }

    private static <T> long[][] assignAdditiveShares(List<T> keys, Map<T, long[]> keywordPayloadBlocks,
                                                     PeelResult peelResult, FusePirCStdKwPirParams params) {
        long[][] storage = new long[params.getPayloadBlockNum()][params.getBffSlotNum()];
        long modulus = params.getRawRlweModulus();
        for (int payloadBlockIndex = 0; payloadBlockIndex < params.getPayloadBlockNum(); payloadBlockIndex++) {
            for (int peelIndex = peelResult.peelSize - 1; peelIndex >= 0; peelIndex--) {
                int keyIndex = peelResult.peelKeyIndexes[peelIndex];
                int slot = peelResult.peelSlots[peelIndex];
                long[] payloadBlocks = keywordPayloadBlocks.get(keys.get(keyIndex));
                long share = rawEncodePayloadBlock(payloadBlocks[payloadBlockIndex], params);
                for (int position : peelResult.keyPositions[keyIndex]) {
                    if (position != slot) {
                        share = subMod(share, storage[payloadBlockIndex][position], modulus);
                    }
                }
                storage[payloadBlockIndex][slot] = share;
            }
        }
        return storage;
    }

    private static <T> byte[] encodePackedRawMatrix(List<T> keys, Map<T, long[]> keywordPayloadBlocks,
                                                    PeelResult peelResult, FusePirCStdKwPirParams params) {
        int degree = params.getRawRlweDegree();
        long modulus = params.getRawRlweModulus();
        int groupNum = params.getPackedMatrixGroupNum();
        int colNum = params.getMatrixColNum();
        int rowNum = params.getMatrixRowNum();
        int blocksPerPackedMatrix = params.getBlocksPerPackedMatrix();
        int payloadBlockNum = params.getPayloadBlockNum();
        int bffSlotNum = params.getBffSlotNum();
        long polyBytes = Integer.BYTES + Long.BYTES + (long) degree * Long.BYTES;
        long totalBytes = 8L * Integer.BYTES + (long) groupNum * colNum * polyBytes;
        if (totalBytes > Integer.MAX_VALUE) {
            throw new IllegalStateException("FUSE_PIR_C raw matrix serialization exceeds Java byte[] limit");
        }
        byte[] out = new byte[(int) totalBytes];
        Cursor cursor = new Cursor();
        putInt(out, cursor, 0x4F584D52);
        putInt(out, cursor, rowNum);
        putInt(out, cursor, colNum);
        putInt(out, cursor, params.getRowStride());
        putInt(out, cursor, payloadBlockNum);
        putInt(out, cursor, blocksPerPackedMatrix);
        putInt(out, cursor, groupNum);
        putInt(out, cursor, params.getBffHashNum());
        long rawModulus = params.getRawRlweModulus();
        for (int group = 0; group < groupNum; group++) {
            int firstBlock = group * blocksPerPackedMatrix;
            int blockCount = Math.min(blocksPerPackedMatrix, payloadBlockNum - firstBlock);
            long[][] groupStorage = assignAdditiveSharesForBlockRange(
                keys, keywordPayloadBlocks, peelResult, params, firstBlock, blockCount
            );
            for (int col = 0; col < colNum; col++) {
                putInt(out, cursor, degree);
                putLong(out, cursor, modulus);
                int columnOffset = col * rowNum;
                for (int coeff = 0; coeff < degree; coeff++) {
                    long value = 0L;
                    int row = coeff / blocksPerPackedMatrix;
                    int localBlock = coeff % blocksPerPackedMatrix;
                    int slot = columnOffset + row;
                    if (localBlock < blockCount && row < rowNum && slot < bffSlotNum) {
                        value = groupStorage[localBlock][slot] % rawModulus;
                    }
                    putLong(out, cursor, value);
                }
            }
        }
        if (cursor.offset != out.length) {
            throw new IllegalStateException("FUSE_PIR_C raw matrix serialization size mismatch");
        }
        return out;
    }

    private static <T> long[][] assignAdditiveSharesForBlockRange(List<T> keys, Map<T, long[]> keywordPayloadBlocks,
                                                                  PeelResult peelResult, FusePirCStdKwPirParams params,
                                                                  int firstBlock, int blockCount) {
        long[][] storage = new long[blockCount][params.getBffSlotNum()];
        long modulus = params.getRawRlweModulus();
        for (int localBlock = 0; localBlock < blockCount; localBlock++) {
            int payloadBlockIndex = firstBlock + localBlock;
            for (int peelIndex = peelResult.peelSize - 1; peelIndex >= 0; peelIndex--) {
                int keyIndex = peelResult.peelKeyIndexes[peelIndex];
                int slot = peelResult.peelSlots[peelIndex];
                long[] payloadBlocks = keywordPayloadBlocks.get(keys.get(keyIndex));
                long share = rawEncodePayloadBlock(payloadBlocks[payloadBlockIndex], params);
                for (int position : peelResult.keyPositions[keyIndex]) {
                    if (position != slot) {
                        share = subMod(share, storage[localBlock][position], modulus);
                    }
                }
                storage[localBlock][slot] = share;
            }
        }
        return storage;
    }

    private static <T> long[] assignAdditiveSharesForSingleBlock(List<T> keys, Map<T, long[]> keywordPayloadBlocks,
                                                                 PeelResult peelResult, FusePirCStdKwPirParams params,
                                                                 int payloadBlockIndex) {
        long[] storage = new long[params.getBffSlotNum()];
        long modulus = params.getRawRlweModulus();
        for (int peelIndex = peelResult.peelSize - 1; peelIndex >= 0; peelIndex--) {
            int keyIndex = peelResult.peelKeyIndexes[peelIndex];
            int slot = peelResult.peelSlots[peelIndex];
            long[] payloadBlocks = keywordPayloadBlocks.get(keys.get(keyIndex));
            long share = rawEncodePayloadBlock(payloadBlocks[payloadBlockIndex], params);
            for (int position : peelResult.keyPositions[keyIndex]) {
                if (position != slot) {
                    share = subMod(share, storage[position], modulus);
                }
            }
            storage[slot] = share;
        }
        return storage;
    }

    private static long estimateRawEncodedMatrixBytes(FusePirCStdKwPirParams params) {
        long polyBytes = Integer.BYTES + Long.BYTES + (long) params.getRawRlweDegree() * Long.BYTES;
        return 8L * Integer.BYTES + (long) params.getPackedMatrixGroupNum() * params.getMatrixColNum() * polyBytes;
    }

    private static void putInt(byte[] out, Cursor cursor, int value) {
        out[cursor.offset++] = (byte) (value >>> 24);
        out[cursor.offset++] = (byte) (value >>> 16);
        out[cursor.offset++] = (byte) (value >>> 8);
        out[cursor.offset++] = (byte) value;
    }

    private static void putLong(byte[] out, Cursor cursor, long value) {
        out[cursor.offset++] = (byte) (value >>> 56);
        out[cursor.offset++] = (byte) (value >>> 48);
        out[cursor.offset++] = (byte) (value >>> 40);
        out[cursor.offset++] = (byte) (value >>> 32);
        out[cursor.offset++] = (byte) (value >>> 24);
        out[cursor.offset++] = (byte) (value >>> 16);
        out[cursor.offset++] = (byte) (value >>> 8);
        out[cursor.offset++] = (byte) value;
    }

    private static long subMod(long a, long b, long modulus) {
        long result = (a - b) % modulus;
        return result >= 0 ? result : result + modulus;
    }

    private static long elapsedMs(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000L;
    }

    private static class PeelResult {
        final int[][] keyPositions;
        final int[] peelKeyIndexes;
        final int[] peelSlots;
        final int peelSize;

        PeelResult(int[][] keyPositions, int[] peelKeyIndexes, int[] peelSlots, int peelSize) {
            this.keyPositions = keyPositions;
            this.peelKeyIndexes = peelKeyIndexes;
            this.peelSlots = peelSlots;
            this.peelSize = peelSize;
        }
    }

    private static class Cursor {
        int offset;
    }
}
