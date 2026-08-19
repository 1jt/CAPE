package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk;

import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.crypto.hash.Hash;
import edu.alibaba.mpc4j.common.tool.crypto.hash.HashFactory;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import edu.alibaba.mpc4j.s2pc.pir.PirUtils;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * MMK standard keyword PIR utilities. MMKPIR semantically supports keyword -> value-set retrieval. The current
 * StdKwPir interface exposes {@code Map<T, byte[]>}, so this stage treats each {@code byte[]} as the serialized
 * value-set payload for the keyword. A later interface extension can expose true multi-value inputs directly.
 *
 * @author Weiran Liu
 * @date 2026/06/04
 */
class MmkStdKwPirUtils {

    private MmkStdKwPirUtils() {
        // empty
    }

    /**
     * Checks whether the current stage-1 MMKPIR scope supports the input.
     *
     * @param keywordSize keyword size.
     * @param maxBatchNum max batch num.
     */
    static void checkStage1Scope(int keywordSize, int maxBatchNum) {
        MathPreconditions.checkPositive("keyword_size", keywordSize);
        MathPreconditions.checkEqual("max_batch_num", "1", maxBatchNum, 1);
    }

    /**
     * Hashes a keyword to a non-negative integer. MPC4J has a common hash abstraction, so we use Bouncy Castle
     * SHA3-256 through {@link HashFactory} instead of direct JDK digest calls.
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

    static long[][] encodePayload(byte[] payload, MmkStdKwPirParams params) {
        MathPreconditions.checkPositive("payload_coeff_num", params.payloadCoeffNum);
        long[] coeffs = PirUtils.convertBytesToCoeffs(params.getPlainModulusBitLength(), 0, payload.length, payload);
        MathPreconditions.checkLessOrEqual("coeffs.length", coeffs.length, params.payloadCoeffNum);
        long[][] plaintexts = new long[params.payloadPlaintextNum][params.getPolyModulusDegree()];
        for (int blockIndex = 0; blockIndex < params.payloadPlaintextNum; blockIndex++) {
            int offset = blockIndex * params.getPolyModulusDegree();
            int copyNum = Math.min(params.getPolyModulusDegree(), coeffs.length - offset);
            if (copyNum > 0) {
                System.arraycopy(coeffs, offset, plaintexts[blockIndex], 0, copyNum);
            }
        }
        return plaintexts;
    }

    /**
     * Decodes a decrypted BFV plaintext coefficient array into the serialized value-set payload.
     *
     * @param coeffs            plaintext coefficients.
     * @param payloadByteLength payload byte length.
     * @param params            params.
     * @return payload bytes.
     */
    static byte[] decodePayload(long[] coeffs, int payloadByteLength, MmkStdKwPirParams params) {
        MathPreconditions.checkPositive("payload_byte_length", payloadByteLength);
        MathPreconditions.checkGreaterOrEqual("coeffs.length", coeffs.length, params.payloadCoeffNum);
        long[] payloadCoeffs = Arrays.copyOf(coeffs, params.payloadCoeffNum);
        return BytesUtils.clone(PirUtils.convertCoeffsToBytes(payloadCoeffs, params.getPlainModulusBitLength()),
            0, payloadByteLength);
    }

    static byte[] decodePayload(long[][] coeffBlocks, int payloadByteLength, MmkStdKwPirParams params) {
        MathPreconditions.checkEqual("coeffBlocks.length", "payload_plaintext_num", coeffBlocks.length,
            params.payloadPlaintextNum);
        long[] coeffs = new long[params.payloadCoeffNum];
        for (int blockIndex = 0; blockIndex < coeffBlocks.length; blockIndex++) {
            MathPreconditions.checkGreaterOrEqual("coeffBlocks[blockIndex].length", coeffBlocks[blockIndex].length,
                params.getPolyModulusDegree());
            int offset = blockIndex * params.getPolyModulusDegree();
            int copyNum = Math.min(params.getPolyModulusDegree(), coeffs.length - offset);
            if (copyNum > 0) {
                System.arraycopy(coeffBlocks[blockIndex], 0, coeffs, offset, copyNum);
            }
        }
        return decodePayload(coeffs, payloadByteLength, params);
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
