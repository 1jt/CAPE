package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc;

import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;

import java.nio.ByteBuffer;

/**
 * FUSE_PIR_C compressed query container.
 *
 * @author Weiran Liu
 * @date 2026/06/16
 */
class FusePirCCompressedQuery {
    /**
     * serialization magic.
     */
    private static final int MAGIC = 0x4F584D50;
    /**
     * layout version.
     */
    static final int VERSION = 1;
    /**
     * PRG seed.
     */
    private final byte[] seed;
    /**
     * serialized b array.
     */
    private final byte[] bArray;
    /**
     * row bit num.
     */
    private final int rowBitNum;
    /**
     * column bit num.
     */
    private final int colBitNum;
    /**
     * BFF hash num.
     */
    private final int bffHashNum;
    /**
     * LWE dimension.
     */
    private final int lweDimension;
    /**
     * LWE modulus.
     */
    private final long modulus;
    /**
     * b element byte length.
     */
    private final int bElementByteLength;

    FusePirCCompressedQuery(byte[] seed, byte[] bArray, int rowBitNum, int colBitNum, int bffHashNum,
                         int lweDimension, long modulus, int bElementByteLength) {
        MathPreconditions.checkPositive("seed.length", seed.length);
        MathPreconditions.checkNonNegative("row_bit_num", rowBitNum);
        MathPreconditions.checkNonNegative("col_bit_num", colBitNum);
        MathPreconditions.checkEqual("bff_hash_num", "3", bffHashNum, 3);
        MathPreconditions.checkPositive("lwe_dimension", lweDimension);
        MathPreconditions.checkGreater("modulus", modulus, 1L);
        MathPreconditions.checkPositive("b_element_byte_length", bElementByteLength);
        int bitNum = bffHashNum * (rowBitNum + colBitNum);
        MathPreconditions.checkEqual("bArray.length", "bitNum * bElementByteLength", bArray.length,
            bitNum * bElementByteLength);
        this.seed = BytesUtils.clone(seed);
        this.bArray = BytesUtils.clone(bArray);
        this.rowBitNum = rowBitNum;
        this.colBitNum = colBitNum;
        this.bffHashNum = bffHashNum;
        this.lweDimension = lweDimension;
        this.modulus = modulus;
        this.bElementByteLength = bElementByteLength;
    }

    byte[] toByteArray() {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES * 9 + Long.BYTES + seed.length + bArray.length);
        buffer.putInt(MAGIC);
        buffer.putInt(VERSION);
        buffer.putInt(rowBitNum);
        buffer.putInt(colBitNum);
        buffer.putInt(bffHashNum);
        buffer.putInt(lweDimension);
        buffer.putLong(modulus);
        buffer.putInt(bElementByteLength);
        buffer.putInt(seed.length);
        buffer.put(seed);
        buffer.putInt(bArray.length);
        buffer.put(bArray);
        return buffer.array();
    }

    int getRowBitNum() {
        return rowBitNum;
    }

    int getColBitNum() {
        return colBitNum;
    }

    int getBffHashNum() {
        return bffHashNum;
    }

    int getLweDimension() {
        return lweDimension;
    }

    long getModulus() {
        return modulus;
    }

    int getBElementByteLength() {
        return bElementByteLength;
    }

    int getSeedByteLength() {
        return seed.length;
    }

    int getBArrayByteLength() {
        return bArray.length;
    }

    int getMetadataByteLength() {
        return Integer.BYTES * 9 + Long.BYTES;
    }

    static FusePirCCompressedQuery fromByteArray(byte[] encoded) {
        ByteBuffer buffer = ByteBuffer.wrap(BytesUtils.clone(encoded));
        MathPreconditions.checkEqual("magic", "FusePirCCompressedQuery.MAGIC", buffer.getInt(), MAGIC);
        MathPreconditions.checkEqual("version", "FusePirCCompressedQuery.VERSION", buffer.getInt(), VERSION);
        int rowBitNum = buffer.getInt();
        int colBitNum = buffer.getInt();
        int bffHashNum = buffer.getInt();
        int lweDimension = buffer.getInt();
        long modulus = buffer.getLong();
        int bElementByteLength = buffer.getInt();
        int seedByteLength = buffer.getInt();
        byte[] seed = new byte[seedByteLength];
        buffer.get(seed);
        int bArrayByteLength = buffer.getInt();
        byte[] bArray = new byte[bArrayByteLength];
        buffer.get(bArray);
        MathPreconditions.checkEqual("remaining", "0", buffer.remaining(), 0);
        return new FusePirCCompressedQuery(seed, bArray, rowBitNum, colBitNum, bffHashNum, lweDimension, modulus,
            bElementByteLength);
    }
}
