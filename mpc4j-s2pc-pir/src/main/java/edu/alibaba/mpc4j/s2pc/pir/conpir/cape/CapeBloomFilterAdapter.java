package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.crypto.prf.Prf;
import edu.alibaba.mpc4j.common.tool.crypto.prf.PrfFactory;
import edu.alibaba.mpc4j.common.tool.utils.BinaryUtils;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.common.tool.utils.IntUtils;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * CAPE-local Bloom Filter adapter.
 *
 * <p>CAPE needs an experimental Bloom false-positive exponent independent from the shared MPC4J Bloom Filter defaults.
 * This adapter keeps the same bit-vector semantics needed by CAPE's encrypted Bloom inner product, but sizes the Bloom
 * Filter using {@link CapePirParams#getBloomBitLength()} and {@link CapePirParams#getBloomHashNum()}.</p>
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
class CapeBloomFilterAdapter {
    /**
     * Serialized CAPE Bloom Filter magic.
     */
    private static final int SERIALIZATION_MAGIC = 0x4F585442;
    /**
     * Bloom Filter bit length.
     */
    private final int bitLength;
    /**
     * hash num.
     */
    private final int hashNum;
    /**
     * Bloom Filter seed.
     */
    private final byte[] seed;
    /**
     * storage bytes.
     */
    private final byte[] storage;
    /**
     * bit vector cache.
     */
    private final long[] bitVector;
    /**
     * PRF for hash positions.
     */
    private final Prf hash;

    private CapeBloomFilterAdapter(int bitLength, int hashNum, byte[] seed, byte[] storage) {
        MathPreconditions.checkPositive("bit_length", bitLength);
        MathPreconditions.checkPositive("hash_num", hashNum);
        this.bitLength = bitLength;
        this.hashNum = hashNum;
        this.seed = BytesUtils.clone(seed);
        this.storage = BytesUtils.clone(storage);
        this.bitVector = storageToLongBitVector(this.storage, bitLength);
        hash = PrfFactory.createInstance(EnvType.STANDARD, hashNum * Integer.BYTES);
        hash.setKey(this.seed);
    }

    static CapeBloomFilterAdapter create(Collection<byte[]> keywords, CapePirParams params) {
        int bitLength = params.getBloomBitLength();
        byte[] storage = new byte[params.getBloomByteLength()];
        CapeBloomFilterAdapter adapter = new CapeBloomFilterAdapter(
            bitLength, params.getBloomHashNum(), params.getBloomSeed(), storage
        );
        Set<ByteBuffer> uniqueKeywords = new LinkedHashSet<>();
        keywords.forEach(keyword -> uniqueKeywords.add(ByteBuffer.wrap(BytesUtils.clone(keyword))));
        uniqueKeywords.forEach(keyword -> adapter.put(byteBufferToByteArray(keyword)));
        return new CapeBloomFilterAdapter(bitLength, params.getBloomHashNum(), params.getBloomSeed(), adapter.storage);
    }

    static CapeBloomFilterAdapter deserialize(List<byte[]> serializedBloomFilter, CapePirParams params) {
        MathPreconditions.checkEqual("serialized_bloom_filter.size", "5", serializedBloomFilter.size(), 5);
        int magic = IntUtils.byteArrayToInt(serializedBloomFilter.get(0));
        MathPreconditions.checkEqual("serialized_bloom_filter.magic", "CAPE", magic, SERIALIZATION_MAGIC);
        int bitLength = IntUtils.byteArrayToInt(serializedBloomFilter.get(1));
        int hashNum = IntUtils.byteArrayToInt(serializedBloomFilter.get(2));
        byte[] seed = serializedBloomFilter.get(3);
        byte[] storage = serializedBloomFilter.get(4);
        MathPreconditions.checkEqual("bit_length", "params.getBloomBitLength()", bitLength, params.getBloomBitLength());
        MathPreconditions.checkEqual("hash_num", "params.getBloomHashNum()", hashNum, params.getBloomHashNum());
        return new CapeBloomFilterAdapter(bitLength, hashNum, seed, storage);
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

    long getBit(int bitIndex) {
        return bitVector[bitIndex];
    }

    boolean mightContain(byte[] keyword) {
        for (int position : positions(keyword)) {
            if (!BinaryUtils.getBoolean(storage, bitOffset(position))) {
                return false;
            }
        }
        return true;
    }

    int getBitLength() {
        return bitLength;
    }

    int getHashNum() {
        return hashNum;
    }

    List<byte[]> serialize() {
        List<byte[]> serialized = new ArrayList<>(5);
        serialized.add(IntUtils.intToByteArray(SERIALIZATION_MAGIC));
        serialized.add(IntUtils.intToByteArray(bitLength));
        serialized.add(IntUtils.intToByteArray(hashNum));
        serialized.add(BytesUtils.clone(seed));
        serialized.add(BytesUtils.clone(storage));
        return serialized;
    }

    byte[] getStorage() {
        return BytesUtils.clone(storage);
    }

    static long[] storageToLongBitVector(byte[] storage, int bitLength) {
        int offset = storage.length * Byte.SIZE - bitLength;
        long[] longBitVector = new long[bitLength];
        for (int bitIndex = 0; bitIndex < bitLength; bitIndex++) {
            longBitVector[bitIndex] = BinaryUtils.getBoolean(storage, bitIndex + offset) ? 1L : 0L;
        }
        return longBitVector;
    }

    private void put(byte[] keyword) {
        for (int position : positions(keyword)) {
            BinaryUtils.setBoolean(storage, bitOffset(position), true);
        }
    }

    private int[] positions(byte[] keyword) {
        int[] hashValues = IntUtils.byteArrayToIntArray(hash.getBytes(keyword));
        int[] positions = new int[hashNum];
        for (int hashIndex = 0; hashIndex < hashNum; hashIndex++) {
            positions[hashIndex] = Math.floorMod(hashValues[hashIndex], bitLength);
        }
        return positions;
    }

    private int bitOffset(int bitIndex) {
        return storage.length * Byte.SIZE - bitLength + bitIndex;
    }

    private static byte[] byteBufferToByteArray(ByteBuffer byteBuffer) {
        ByteBuffer duplicate = byteBuffer.duplicate();
        byte[] bytes = new byte[duplicate.remaining()];
        duplicate.get(bytes);
        return bytes;
    }
}
