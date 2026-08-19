package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;

import java.nio.ByteBuffer;

/**
 * PRG-compressed LWE bit query for FUSE_PIR row-bit compression.
 *
 * <p>For each LWE ciphertext {@code ct_i = (a_i, b_i)}, the online query sends one seed and all {@code b_i}
 * components. The server deterministically reconstructs {@code a_i = PRG(seed, i)}. This class is only the Java-side
 * transport container; conversion from compressed LWE bits to RGSW bits is handled by the FUSE_PIR native code.</p>
 *
 * @author Weiran Liu
 * @date 2026/06/10
 */
class FusePirCompressedLweBitQuery {
    /**
     * serialization magic.
     */
    private static final int MAGIC = 0x4F58434C;
    /**
     * PRG seed.
     */
    private final byte[] seed;
    /**
     * number of encrypted bits.
     */
    private final int bitNum;
    /**
     * LWE dimension.
     */
    private final int lweDimension;
    /**
     * LWE modulus.
     */
    private final long modulus;
    /**
     * serialized b components.
     */
    private final byte[] bArray;

    FusePirCompressedLweBitQuery(byte[] seed, int bitNum, int lweDimension, long modulus, long[] bArray) {
        MathPreconditions.checkPositive("bit_num", bitNum);
        MathPreconditions.checkPositive("lwe_dimension", lweDimension);
        MathPreconditions.checkGreater("modulus", modulus, 1L);
        MathPreconditions.checkEqual("bArray.length", "bit_num", bArray.length, bitNum);
        this.seed = BytesUtils.clone(seed);
        this.bitNum = bitNum;
        this.lweDimension = lweDimension;
        this.modulus = modulus;
        this.bArray = FusePirLwePrgUtils.serializeBArray(bArray);
    }

    FusePirCompressedLweBitQuery(byte[] seed, int bitNum, int lweDimension, long modulus, byte[] bArray) {
        MathPreconditions.checkPositive("bit_num", bitNum);
        MathPreconditions.checkPositive("lwe_dimension", lweDimension);
        MathPreconditions.checkGreater("modulus", modulus, 1L);
        MathPreconditions.checkEqual("bArray.length", "bit_num * Long.BYTES", bArray.length, bitNum * Long.BYTES);
        this.seed = BytesUtils.clone(seed);
        this.bitNum = bitNum;
        this.lweDimension = lweDimension;
        this.modulus = modulus;
        this.bArray = BytesUtils.clone(bArray);
    }

    byte[] getSeed() {
        return BytesUtils.clone(seed);
    }

    int getBitNum() {
        return bitNum;
    }

    int getLweDimension() {
        return lweDimension;
    }

    long getModulus() {
        return modulus;
    }

    byte[] getBArrayBytes() {
        return BytesUtils.clone(bArray);
    }

    long[] getBArray() {
        return FusePirLwePrgUtils.deserializeBArray(bArray);
    }

    byte[] toByteArray() {
        ByteBuffer buffer = ByteBuffer.allocate(
            Integer.BYTES * 5 + Long.BYTES + seed.length + bArray.length
        );
        buffer.putInt(MAGIC);
        buffer.putInt(bitNum);
        buffer.putInt(lweDimension);
        buffer.putLong(modulus);
        buffer.putInt(seed.length);
        buffer.put(seed);
        buffer.putInt(bArray.length);
        buffer.put(bArray);
        return buffer.array();
    }

    static FusePirCompressedLweBitQuery fromByteArray(byte[] encoded) {
        ByteBuffer buffer = ByteBuffer.wrap(BytesUtils.clone(encoded));
        MathPreconditions.checkEqual("magic", "FusePirCompressedLweBitQuery.MAGIC", buffer.getInt(), MAGIC);
        int bitNum = buffer.getInt();
        int lweDimension = buffer.getInt();
        long modulus = buffer.getLong();
        int seedByteLength = buffer.getInt();
        MathPreconditions.checkEqual("seedByteLength", "SEED_BYTE_LENGTH",
            seedByteLength, FusePirLwePrgUtils.SEED_BYTE_LENGTH);
        byte[] seed = new byte[seedByteLength];
        buffer.get(seed);
        int bArrayByteLength = buffer.getInt();
        MathPreconditions.checkEqual("bArrayByteLength", "bitNum * Long.BYTES",
            bArrayByteLength, bitNum * Long.BYTES);
        byte[] bArray = new byte[bArrayByteLength];
        buffer.get(bArray);
        MathPreconditions.checkEqual("remaining", "0", buffer.remaining(), 0);
        return new FusePirCompressedLweBitQuery(seed, bitNum, lweDimension, modulus, bArray);
    }
}
