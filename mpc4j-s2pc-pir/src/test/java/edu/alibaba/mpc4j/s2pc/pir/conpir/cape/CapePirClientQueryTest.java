package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir.FusePirStdKwPirParams;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

/**
 * CAPE PIR client query tests.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class CapePirClientQueryTest {

    @Test
    public void testCompressedRowBitQueryRoundtrip() {
        long[] lweSecretKey = new long[CapePirNativeUtils.LWE_DIMENSION];
        for (int i = 0; i < lweSecretKey.length; i++) {
            lweSecretKey[i] = (i & 1) == 0 ? 1L : 0L;
        }
        int rowNum = 64;
        int rowIndex = 37;
        CapeCompressedLweBitQuery query = CapeLwePrgUtils.generateCompressedRowBitQuery(
            rowIndex, rowNum, lweSecretKey, CapePirNativeUtils.LWE_MODULUS, CapePirNativeUtils.DELTA_BIT
        );
        CapeCompressedLweBitQuery decoded = CapeCompressedLweBitQuery.fromByteArray(query.toByteArray());
        List<CapeLweCiphertext> ciphertexts = CapeLwePrgUtils.recoverLweBitCiphertexts(decoded);
        int[] bits = CapeLwePrgUtils.debugDecryptBits(ciphertexts, lweSecretKey);
        for (int bitIndex = 0; bitIndex < bits.length; bitIndex++) {
            Assert.assertEquals((rowIndex >>> bitIndex) & 1, bits[bitIndex]);
        }
    }

    @Test
    public void testClientGenerateCapeQuery() throws Exception {
        MemoryRpcManager rpcManager = new MemoryRpcManager(2);
        CapePirConfig config = new CapePirConfig.Builder().build();
        CapePirServer<ByteBuffer> server = new CapePirServer<>(
            rpcManager.getRpc(0), rpcManager.getRpc(1).ownParty(), config
        );
        server.init(createKeywordValueMap(), 1);
        CapePirClient<ByteBuffer> client = new CapePirClient<>(
            rpcManager.getRpc(1), rpcManager.getRpc(0).ownParty(), config
        );
        client.init(3, 2, 3, 1);
        client.setBffSeed(server.getBffSeed());
        client.getCapeParams().applySerializedBloomParams(server.getCapeParams().serializeBloomParams());

        List<ByteBuffer> queryKeywords = List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        );
        CapePirQuery query = client.generateCapeQuery(queryKeywords);
        Assert.assertArrayEquals(
            CapePirUtils.keywordToByteArray(queryKeywords.get(0)),
            query.getAnchorKeywordBytes()
        );
        Assert.assertEquals(3, query.getFusePirColumnQueries().size());
        Assert.assertTrue(query.getFusePirBitColumnQueries().isEmpty());
        Assert.assertTrue(query.getFusePirEncryptedRowBits().isEmpty());
        Assert.assertEquals(client.getCapeParams().getBffHashNum(), query.getCompressedRowBitQueries().size());
        Assert.assertEquals(0, byteLength(query.getFusePirEncryptedRowBits()));
        Assert.assertTrue(byteLength(query.getCompressedRowBitQueries()) > 0);
        Assert.assertTrue(query.getEncryptedBloomFilter().isEmpty());
        Assert.assertEquals(client.getCapeParams().getCoeffBloomCiphertextNum(), query.getEncryptedCoeffBloomFilters().size());
        Assert.assertEquals(
            client.getCapeParams().getPackedQueryBloomCiphertextNum(),
            query.getEncryptedCoeffBloomFilters().size()
        );
        Assert.assertTrue(
            client.getCapeParams().getGlobalTiledCoeffBloomCiphertextNum()
                > client.getCapeParams().getPackedQueryBloomCiphertextNum()
        );
        Assert.assertEquals(3, query.getBoolKeywordNum());

        CapeBloomFilterAdapter plainQueryBloomFilter = CapePirUtils.buildQueryBloomFilter(
            queryKeywords.subList(1, queryKeywords.size()), client.getCapeParams()
        );
        Assert.assertEquals(plainQueryBloomFilter.countOnes(), query.getBloomOneCount());
        long[] expectedBloom = plainQueryBloomFilter.toLongBitVector();
        Assert.assertEquals(
            client.getCapeParams().getBffHashNum()
                + client.getCapeParams().getBffHashNum()
                + client.getCapeParams().getCoeffBloomCiphertextNum(),
            query.getServerPayload().size()
        );
        Assert.assertNotEquals(client.getCapeParams().getBloomBitLength(), query.getEncryptedCoeffBloomFilters().size());
        for (byte[] serverPayloadItem : query.getServerPayload()) {
            Assert.assertFalse(java.util.Arrays.equals("k1".getBytes(), serverPayloadItem));
            Assert.assertFalse(java.util.Arrays.equals("k2".getBytes(), serverPayloadItem));
            Assert.assertFalse(java.util.Arrays.equals("k3".getBytes(), serverPayloadItem));
            Assert.assertFalse(java.util.Arrays.equals(expectedBloomToBytes(expectedBloom), serverPayloadItem));
        }
    }

    @Test
    public void testFormalQueryUsesPackedBloomQuery() throws Exception {
        MemoryRpcManager rpcManager = new MemoryRpcManager(2);
        CapePirConfig config = new CapePirConfig.Builder().build();
        CapePirServer<ByteBuffer> server = new CapePirServer<>(
            rpcManager.getRpc(0), rpcManager.getRpc(1).ownParty(), config
        );
        server.init(createKeywordValueMap(), 1);
        CapePirClient<ByteBuffer> client = new CapePirClient<>(
            rpcManager.getRpc(1), rpcManager.getRpc(0).ownParty(), config
        );
        client.init(3, 2, 3, 1);
        client.setBffSeed(server.getBffSeed());
        client.getCapeParams().applySerializedBloomParams(server.getCapeParams().serializeBloomParams());
        List<ByteBuffer> queryKeywords = List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        );
        CapePirQuery query = client.generateCapeQuery(queryKeywords);
        Assert.assertTrue(client.getCapeParams().getBloomBitLength() <= client.getCapeParams().getPolyModulusDegree());
        Assert.assertEquals(1, client.getCapeParams().getPackedQueryBloomCiphertextNum());
        Assert.assertEquals(
            client.getCapeParams().getPackedQueryBloomCiphertextNum(),
            query.getEncryptedCoeffBloomFilters().size()
        );
        Assert.assertTrue(
            client.getCapeParams().getGlobalTiledCoeffBloomCiphertextNum()
                > query.getEncryptedCoeffBloomFilters().size()
        );
        Assert.assertEquals(0, query.getEncryptedBloomFilter().size());
        Assert.assertEquals(0, query.getFusePirBitColumnQueries().size());
        Assert.assertEquals(0, query.getFusePirEncryptedRowBits().size());
    }

    @Test
    public void testCapeParamsAlignedToFusePir() throws Exception {
        CapePirParams capeParams = new CapePirParams(CapePirParams.DEFAULT_PARAMS);
        FusePirStdKwPirParams fusepirParams = FusePirStdKwPirParams.DEFAULT_PARAMS;
        Assert.assertEquals(16384, capeParams.getPolyModulusDegree());
        Assert.assertEquals(fusepirParams.getPolyModulusDegree(), capeParams.getPolyModulusDegree());
        Assert.assertEquals(65537L, capeParams.getPlainModulus());
        Assert.assertArrayEquals(fusepirParams.getCoeffModulusBits(), capeParams.getCoeffModulusBits());
        Assert.assertEquals(Byte.SIZE, capeParams.getPayloadElementBitLength());

        MemoryRpcManager rpcManager = new MemoryRpcManager(2);
        CapePirConfig config = new CapePirConfig.Builder().build();
        CapePirServer<ByteBuffer> server = new CapePirServer<>(
            rpcManager.getRpc(0), rpcManager.getRpc(1).ownParty(), config
        );
        server.init(createKeywordValueMap(), 1);
        CapePirClient<ByteBuffer> client = new CapePirClient<>(
            rpcManager.getRpc(1), rpcManager.getRpc(0).ownParty(), config
        );
        client.init(3, 2, 3, 1);
        client.getCapeParams().applySerializedBloomParams(server.getCapeParams().serializeBloomParams());
        Assert.assertEquals(server.getCapeParams().getBloomExpectedInsertions(),
            client.getCapeParams().getBloomExpectedInsertions());
        Assert.assertEquals(server.getCapeParams().getBloomBitLength(), client.getCapeParams().getBloomBitLength());
        Assert.assertEquals(server.getCapeParams().getBloomHashNum(), client.getCapeParams().getBloomHashNum());
        Assert.assertEquals(3, server.getCapeParams().getBloomExpectedInsertions());
    }

    private byte[] expectedBloomToBytes(long[] bloomBits) {
        byte[] bytes = new byte[bloomBits.length];
        for (int i = 0; i < bloomBits.length; i++) {
            bytes[i] = (byte) bloomBits[i];
        }
        return bytes;
    }

    private static long byteLength(List<byte[]> payload) {
        return payload.stream().mapToLong(bytes -> bytes.length).sum();
    }

    private Map<ByteBuffer, List<byte[]>> createKeywordValueMap() {
        return Map.of(
            ByteBuffer.wrap("k1".getBytes()), List.of("v1".getBytes(), "v2".getBytes(), "v3".getBytes()),
            ByteBuffer.wrap("k2".getBytes()), List.of("v1".getBytes()),
            ByteBuffer.wrap("k3".getBytes()), List.of("v1".getBytes(), "v2".getBytes())
        );
    }

    private int ceilLog2(int n) {
        int log = 0;
        int pow = 1;
        while (pow < n) {
            pow <<= 1;
            log++;
        }
        return log;
    }
}
