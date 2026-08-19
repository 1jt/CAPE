package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;

import java.nio.ByteBuffer;

/**
 * CAPE_C compressed anchor query container.
 *
 * <p>The encoded query contains {@code 3 * (rowBitNum + colBitNum)} compressed LWE bit ciphertexts represented as
 * one PRG seed plus serialized LWE {@code b} components and metadata.</p>
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
class CapeCCompressedAnchorQuery {
    /**
     * serialization magic.
     */
    static final int MAGIC = 0x4F585450;
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
    private final long lweModulus;
    /**
     * b element byte length.
     */
    private final int bElementByteLength;

    CapeCCompressedAnchorQuery(byte[] seed, byte[] bArray, int rowBitNum, int colBitNum, int bffHashNum,
                              int lweDimension, long lweModulus, int bElementByteLength) {
        MathPreconditions.checkPositive("seed.length", seed.length);
        MathPreconditions.checkNonNegative("row_bit_num", rowBitNum);
        MathPreconditions.checkNonNegative("col_bit_num", colBitNum);
        MathPreconditions.checkEqual("bff_hash_num", "3", bffHashNum, 3);
        MathPreconditions.checkPositive("lwe_dimension", lweDimension);
        MathPreconditions.checkGreater("lwe_modulus", lweModulus, 1L);
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
        this.lweModulus = lweModulus;
        this.bElementByteLength = bElementByteLength;
    }

    byte[] toByteArray() {
        ByteBuffer buffer = ByteBuffer.allocate(getMetadataByteLength() + seed.length + bArray.length);
        buffer.putInt(MAGIC);
        buffer.putInt(VERSION);
        buffer.putInt(rowBitNum);
        buffer.putInt(colBitNum);
        buffer.putInt(bffHashNum);
        buffer.putInt(lweDimension);
        buffer.putLong(lweModulus);
        buffer.putInt(bElementByteLength);
        buffer.putInt(seed.length);
        buffer.put(seed);
        buffer.putInt(bArray.length);
        buffer.put(bArray);
        return buffer.array();
    }

    byte[] getSeed() {
        return BytesUtils.clone(seed);
    }

    byte[] getBArray() {
        return BytesUtils.clone(bArray);
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

    long getLweModulus() {
        return lweModulus;
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

    static CapeCCompressedAnchorQuery fromByteArray(byte[] encoded) {
        ByteBuffer buffer = ByteBuffer.wrap(BytesUtils.clone(encoded));
        MathPreconditions.checkEqual("magic", "CapeCCompressedAnchorQuery.MAGIC", buffer.getInt(), MAGIC);
        MathPreconditions.checkEqual("version", "CapeCCompressedAnchorQuery.VERSION", buffer.getInt(), VERSION);
        int rowBitNum = buffer.getInt();
        int colBitNum = buffer.getInt();
        int bffHashNum = buffer.getInt();
        int lweDimension = buffer.getInt();
        long lweModulus = buffer.getLong();
        int bElementByteLength = buffer.getInt();
        int seedByteLength = buffer.getInt();
        byte[] seed = new byte[seedByteLength];
        buffer.get(seed);
        int bArrayByteLength = buffer.getInt();
        byte[] bArray = new byte[bArrayByteLength];
        buffer.get(bArray);
        MathPreconditions.checkEqual("remaining", "0", buffer.remaining(), 0);
        return new CapeCCompressedAnchorQuery(seed, bArray, rowBitNum, colBitNum, bffHashNum, lweDimension,
            lweModulus, bElementByteLength);
    }
}
