package edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir;

import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.crypto.hash.Hash;
import edu.alibaba.mpc4j.common.tool.crypto.hash.HashFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * BKPIR utilities. BKPIR maps each keyword to a value map (VM), where slot i is 1 iff the keyword is associated with
 * value i. The value payload is encoded as multiple BFV plaintexts: plaintext b stores byte b of every value in the
 * corresponding slot, using byte + 1 so that zero can mean no hit.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
class BkPirUtils {

    private BkPirUtils() {
        // empty
    }

    /**
     * Hashes a keyword to a non-negative integer. This matches MMKPIR's SHA3-256 based keyword hashing.
     *
     * @param keywordBytes keyword bytes.
     * @return hash integer.
     */
    static BigInteger hashKeywordToBigInteger(byte[] keywordBytes) {
        Hash hash = HashFactory.createInstance(HashFactory.HashType.BC_SHA3_256, 32);
        return new BigInteger(1, hash.digestToBytes(keywordBytes));
    }

    /**
     * Encodes an integer to a constant-weight codeword following Algorithm 1 CWEncode.
     *
     * @param h hash integer.
     * @param w codeword length.
     * @param k Hamming weight.
     * @return constant-weight codeword.
     */
    static long[] cwEncode(BigInteger h, int w, int k) {
        MathPreconditions.checkNonNegative("h", h);
        MathPreconditions.checkPositive("w", w);
        MathPreconditions.checkPositiveInRangeClosed("k", k, w);
        BigInteger domain = binomial(w, k);
        BigInteger rank = h.mod(domain);
        long[] codeword = new long[w];
        int remainingWeight = k;
        for (int i = 0; i < w && remainingWeight > 0; i++) {
            BigInteger onePrefixCount = binomial(w - i - 1, remainingWeight - 1);
            if (rank.compareTo(onePrefixCount) < 0) {
                codeword[i] = 1L;
                remainingWeight--;
            } else {
                rank = rank.subtract(onePrefixCount);
            }
        }
        assert Arrays.stream(codeword).sum() == k;
        return codeword;
    }

    /**
     * Encodes one keyword's value map. Slot i is 1 iff the keyword is associated with value i.
     *
     * @param valueIndices   associated value indices.
     * @param valueSpaceSize value space size.
     * @param slotCount      slot count.
     * @return value map plaintext slots.
     */
    static long[] encodeValueMap(Set<Integer> valueIndices, int valueSpaceSize, int slotCount) {
        MathPreconditions.checkPositive("value_space_size", valueSpaceSize);
        MathPreconditions.checkPositiveInRangeClosed("value_space_size", valueSpaceSize, slotCount);
        long[] valueMap = new long[slotCount];
        for (int valueIndex : valueIndices) {
            MathPreconditions.checkNonNegativeInRange("value_index", valueIndex, valueSpaceSize);
            valueMap[valueIndex] = 1L;
        }
        return valueMap;
    }

    /**
     * Encodes one keyword's value map using BKPIR params.
     *
     * @param valueIndices associated value indices.
     * @param params       params.
     * @return value map plaintext slots.
     */
    static long[] encodeValueMap(Set<Integer> valueIndices, BkPirParams params) {
        return encodeValueMapChunk(valueIndices, params, 0);
    }

    /**
     * Encodes one keyword's value map chunk using BKPIR params.
     *
     * @param valueIndices associated value indices.
     * @param params       params.
     * @param chunkIndex   chunk index.
     * @return value map plaintext slots.
     */
    static long[] encodeValueMapChunk(Set<Integer> valueIndices, BkPirParams params, int chunkIndex) {
        MathPreconditions.checkNonNegativeInRange("chunkIndex", chunkIndex, params.valueChunkNum);
        int slotCount = params.getPolyModulusDegree();
        int startIndex = chunkIndex * slotCount;
        int chunkValueSpaceSize = Math.min(slotCount, params.valueSpaceSize - startIndex);
        long[] valueMap = new long[slotCount];
        for (int valueIndex : valueIndices) {
            MathPreconditions.checkNonNegativeInRange("value_index", valueIndex, params.valueSpaceSize);
            if (valueIndex >= startIndex && valueIndex < startIndex + chunkValueSpaceSize) {
                valueMap[valueIndex - startIndex] = 1L;
            }
        }
        return valueMap;
    }

    /**
     * Encodes the value payload. The first BKPIR implementation uses valueIndex + 1 as the recoverable slot payload.
     * Slot 0 means no hit after boolean evaluation.
     *
     * @param valueSpaceSize value space size.
     * @param slotCount      slot count.
     * @return value payload plaintext slots.
     */
    static long[] encodeValuePayload(int valueSpaceSize, int slotCount) {
        MathPreconditions.checkPositive("value_space_size", valueSpaceSize);
        MathPreconditions.checkPositiveInRangeClosed("value_space_size", valueSpaceSize, slotCount);
        long[] valuePayload = new long[slotCount];
        for (int valueIndex = 0; valueIndex < valueSpaceSize; valueIndex++) {
            valuePayload[valueIndex] = valueIndex + 1L;
        }
        return valuePayload;
    }

    /**
     * Encodes real value payloads. Each plaintext slot packs up to
     * {@link BkPirParams#valueByteNumPerPayloadPlaintext} value bytes, plus one as the non-zero hit sentinel.
     *
     * @param valueSpace value space.
     * @param params     BKPIR params.
     * @return value payload plaintexts.
     */
    static long[][] encodeValuePayloads(List<byte[]> valueSpace, BkPirParams params) {
        MathPreconditions.checkEqual("valueSpace.size()", "valueSpaceSize", valueSpace.size(), params.valueSpaceSize);
        long[][] valuePayloads = new long[params.payloadPlaintextNum][params.getPolyModulusDegree()];
        for (int valueIndex = 0; valueIndex < valueSpace.size(); valueIndex++) {
            byte[] value = valueSpace.get(valueIndex);
            MathPreconditions.checkEqual("value.length", "valueByteLength", value.length, params.valueByteLength);
            int chunkIndex = valueIndex / params.getPolyModulusDegree();
            int localValueIndex = valueIndex % params.getPolyModulusDegree();
            for (int payloadIndex = 0; payloadIndex < params.payloadPlaintextNumPerChunk; payloadIndex++) {
                int startByteIndex = payloadIndex * params.valueByteNumPerPayloadPlaintext;
                int endByteIndex = Math.min(params.valueByteLength,
                    startByteIndex + params.valueByteNumPerPayloadPlaintext);
                int blockIndex = chunkIndex * params.payloadPlaintextNumPerChunk + payloadIndex;
                valuePayloads[blockIndex][localValueIndex] = encodePayloadBytes(value, startByteIndex, endByteIndex);
            }
        }
        return valuePayloads;
    }

    /**
     * Computes plaintext AND over value maps. This helper mirrors the boolean logic that native BKPIR will evaluate.
     *
     * @param valueMaps value maps.
     * @return AND result.
     */
    static long[] andValueMaps(long[]... valueMaps) {
        MathPreconditions.checkPositive("value_maps.length", valueMaps.length);
        int slotCount = valueMaps[0].length;
        long[] result = Arrays.copyOf(valueMaps[0], slotCount);
        for (int mapIndex = 1; mapIndex < valueMaps.length; mapIndex++) {
            MathPreconditions.checkEqual("slotCount", "valueMaps[mapIndex].length", slotCount,
                valueMaps[mapIndex].length);
            for (int slotIndex = 0; slotIndex < slotCount; slotIndex++) {
                result[slotIndex] *= valueMaps[mapIndex][slotIndex];
            }
        }
        return result;
    }

    /**
     * Multiplies the boolean AND result with value payload slots.
     *
     * @param andResult    AND result.
     * @param valuePayload value payload.
     * @return selected value payload.
     */
    static long[] applyValuePayload(long[] andResult, long[] valuePayload) {
        MathPreconditions.checkEqual("andResult.length", "valuePayload.length", andResult.length,
            valuePayload.length);
        long[] result = new long[andResult.length];
        for (int slotIndex = 0; slotIndex < andResult.length; slotIndex++) {
            result[slotIndex] = andResult[slotIndex] * valuePayload[slotIndex];
        }
        return result;
    }

    /**
     * Decodes an AND result into value indices. A non-zero slot is interpreted as valueIndex + 1.
     *
     * @param decrypted      decrypted slots.
     * @param valueSpaceSize value space size.
     * @return matching value indices.
     */
    static List<Integer> decodeAndResult(long[] decrypted, int valueSpaceSize) {
        MathPreconditions.checkPositiveInRangeClosed("value_space_size", valueSpaceSize, decrypted.length);
        List<Integer> values = new ArrayList<>();
        for (int valueIndex = 0; valueIndex < valueSpaceSize; valueIndex++) {
            if (decrypted[valueIndex] != 0L) {
                MathPreconditions.checkEqual("decrypted[valueIndex]", "valueIndex + 1", decrypted[valueIndex],
                    valueIndex + 1L);
                values.add(valueIndex);
            }
        }
        return values;
    }

    /**
     * Decodes real value payloads from multiple decrypted response plaintexts.
     *
     * @param decrypted       decrypted payload blocks.
     * @param valueSpaceSize  value space size.
     * @param valueByteLength value byte length.
     * @return matching values.
     */
    static List<byte[]> decodeAndResultPayload(long[][] decrypted, int valueSpaceSize, int valueByteLength) {
        return decodeAndResultPayload(decrypted, valueSpaceSize, valueByteLength, BkPirParams.DEFAULT_PARAMS);
    }

    /**
     * Decodes real value payloads from multiple decrypted response plaintexts.
     *
     * @param decrypted       decrypted payload blocks.
     * @param valueSpaceSize  value space size.
     * @param valueByteLength value byte length.
     * @param params          BKPIR params.
     * @return matching values.
     */
    static List<byte[]> decodeAndResultPayload(long[][] decrypted, int valueSpaceSize, int valueByteLength,
                                               BkPirParams params) {
        MathPreconditions.checkPositive("decrypted.length", decrypted.length);
        MathPreconditions.checkPositive("value_byte_length", valueByteLength);
        int valueByteNumPerPayloadPlaintext = params.valueByteNumPerPayloadPlaintext > 0
            ? params.valueByteNumPerPayloadPlaintext
            : Math.max(1, (Long.SIZE - Long.numberOfLeadingZeros(params.getPlainModulus() - 2L)) / Byte.SIZE);
        int payloadPlaintextNumPerChunk = (valueByteLength + valueByteNumPerPayloadPlaintext - 1)
            / valueByteNumPerPayloadPlaintext;
        MathPreconditions.checkEqual("decrypted.length % payloadPlaintextNumPerChunk", "0",
            decrypted.length % payloadPlaintextNumPerChunk, 0);
        int chunkNum = decrypted.length / payloadPlaintextNumPerChunk;
        int slotCount = decrypted[0].length;
        MathPreconditions.checkPositiveInRangeClosed("value_space_size", valueSpaceSize, chunkNum * slotCount);
        List<byte[]> values = new ArrayList<>();
        for (int valueIndex = 0; valueIndex < valueSpaceSize; valueIndex++) {
            int chunkIndex = valueIndex / slotCount;
            int localValueIndex = valueIndex % slotCount;
            boolean hit = false;
            byte[] value = new byte[valueByteLength];
            for (int payloadIndex = 0; payloadIndex < payloadPlaintextNumPerChunk; payloadIndex++) {
                int blockIndex = chunkIndex * payloadPlaintextNumPerChunk + payloadIndex;
                MathPreconditions.checkEqual("decrypted[blockIndex].length", "slotCount",
                    decrypted[blockIndex].length, slotCount);
                long encoded = decrypted[blockIndex][localValueIndex];
                if (encoded != 0L) {
                    MathPreconditions.checkPositive("encoded payload", encoded);
                    hit = true;
                    int startByteIndex = payloadIndex * valueByteNumPerPayloadPlaintext;
                    int endByteIndex = Math.min(valueByteLength, startByteIndex + valueByteNumPerPayloadPlaintext);
                    decodePayloadBytes(encoded, value, startByteIndex, endByteIndex);
                }
            }
            if (hit) {
                values.add(value);
            }
        }
        return values;
    }

    private static long encodePayloadBytes(byte[] value, int startByteIndex, int endByteIndex) {
        long encoded = 0L;
        for (int byteIndex = startByteIndex; byteIndex < endByteIndex; byteIndex++) {
            encoded = (encoded << Byte.SIZE) | Byte.toUnsignedInt(value[byteIndex]);
        }
        return encoded + 1L;
    }

    private static void decodePayloadBytes(long encoded, byte[] value, int startByteIndex, int endByteIndex) {
        long payload = encoded - 1L;
        for (int byteIndex = endByteIndex - 1; byteIndex >= startByteIndex; byteIndex--) {
            value[byteIndex] = (byte) payload;
            payload >>>= Byte.SIZE;
        }
        MathPreconditions.checkEqual("payload", "0", payload, 0L);
    }

    private static BigInteger binomial(int n, int k) {
        MathPreconditions.checkNonNegative("n", n);
        MathPreconditions.checkNonNegativeInRangeClosed("k", k, n);
        if (k > n - k) {
            k = n - k;
        }
        BigInteger result = BigInteger.ONE;
        for (int i = 1; i <= k; i++) {
            result = result
                .multiply(BigInteger.valueOf(n - k + i))
                .divide(BigInteger.valueOf(i));
        }
        return result;
    }
}
