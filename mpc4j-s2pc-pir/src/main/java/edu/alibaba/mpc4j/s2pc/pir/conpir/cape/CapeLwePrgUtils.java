package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * PRG utilities for CAPE compressed LWE bit queries.
 *
 * @author Weiran Liu
 * @date 2026/06/22
 */
class CapeLwePrgUtils {
    /**
     * seed byte length.
     */
    static final int SEED_BYTE_LENGTH = 32;
    /**
     * domain separation label.
     */
    private static final byte[] DOMAIN = "CAPE-LWE-PRG".getBytes(StandardCharsets.UTF_8);

    private CapeLwePrgUtils() {
        // empty
    }

    static byte[] generateSeed() {
        byte[] seed = new byte[SEED_BYTE_LENGTH];
        new SecureRandom().nextBytes(seed);
        return seed;
    }

    static long[] expandA(byte[] seed, int index, int lweDimension, long modulus) {
        MathPreconditions.checkEqual("seed.length", "SEED_BYTE_LENGTH", seed.length, SEED_BYTE_LENGTH);
        MathPreconditions.checkNonNegative("index", index);
        MathPreconditions.checkPositive("lwe_dimension", lweDimension);
        MathPreconditions.checkGreater("modulus", modulus, 1L);
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

    static byte[] serializeBArray(long[] bArray) {
        ByteBuffer buffer = ByteBuffer.allocate(bArray.length * Long.BYTES);
        for (long b : bArray) {
            buffer.putLong(b);
        }
        return buffer.array();
    }

    static long[] deserializeBArray(byte[] bArrayBytes) {
        MathPreconditions.checkEqual("bArrayBytes.length % Long.BYTES", "0", bArrayBytes.length % Long.BYTES, 0);
        ByteBuffer buffer = ByteBuffer.wrap(BytesUtils.clone(bArrayBytes));
        long[] bArray = new long[bArrayBytes.length / Long.BYTES];
        for (int i = 0; i < bArray.length; i++) {
            bArray[i] = buffer.getLong();
        }
        return bArray;
    }

    static CapeCompressedLweBitQuery generateCompressedRowBitQuery(int rowIndex, int rowNum, long[] lweSecretKey,
                                                                  long modulus, long deltaBit) {
        MathPreconditions.checkNonNegativeInRange("row_index", rowIndex, rowNum);
        MathPreconditions.checkPositive("row_num", rowNum);
        MathPreconditions.checkPositive("lwe_secret_key.length", lweSecretKey.length);
        MathPreconditions.checkGreater("modulus", modulus, 1L);
        int bitNum = ceilLog2(rowNum);
        byte[] seed = generateSeed();
        long[] bArray = new long[bitNum];
        for (int bitIndex = 0; bitIndex < bitNum; bitIndex++) {
            long bit = (rowIndex >>> bitIndex) & 1L;
            long[] a = expandA(seed, bitIndex, lweSecretKey.length, modulus);
            long b = innerProductBinarySecret(a, lweSecretKey);
            b += deltaBit * bit;
            bArray[bitIndex] = b;
        }
        return new CapeCompressedLweBitQuery(seed, bitNum, lweSecretKey.length, modulus, bArray);
    }

    static List<CapeLweCiphertext> recoverLweBitCiphertexts(CapeCompressedLweBitQuery query) {
        long[] bArray = query.getBArray();
        List<CapeLweCiphertext> ciphertexts = new ArrayList<>(query.getBitNum());
        for (int bitIndex = 0; bitIndex < query.getBitNum(); bitIndex++) {
            long[] a = expandA(query.getSeed(), bitIndex, query.getLweDimension(), query.getModulus());
            ciphertexts.add(new CapeLweCiphertext(a, bArray[bitIndex], query.getModulus()));
        }
        return ciphertexts;
    }

    static int[] debugDecryptBits(List<CapeLweCiphertext> ciphertexts, long[] lweSecretKey) {
        int[] bits = new int[ciphertexts.size()];
        for (int i = 0; i < ciphertexts.size(); i++) {
            CapeLweCiphertext ciphertext = ciphertexts.get(i);
            long phase = ciphertext.getB() - innerProductBinarySecret(ciphertext.getA(), lweSecretKey);
            bits[i] = phase == 0L ? 0 : 1;
        }
        return bits;
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

    private static long innerProductBinarySecret(long[] a, long[] secretKey) {
        MathPreconditions.checkEqual("a.length", "secret_key.length", a.length, secretKey.length);
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
            messageDigest.update(DOMAIN);
            messageDigest.update(seed);
            messageDigest.update(ByteBuffer.allocate(Integer.BYTES).putInt(index).array());
            messageDigest.update(ByteBuffer.allocate(Integer.BYTES).putInt(counter).array());
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }
}
