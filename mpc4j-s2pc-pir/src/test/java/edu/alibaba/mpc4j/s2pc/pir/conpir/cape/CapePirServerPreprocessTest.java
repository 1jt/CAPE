package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;

/**
 * CAPE PIR server preprocess tests.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class CapePirServerPreprocessTest {

    @Test
    public void testServerPreprocessForwardIndex() throws Exception {
        CapePirServer<ByteBuffer> server = createInitializedServer();
        Map<ByteBuffer, List<ByteBuffer>> forwardIndex = server.getValueKeywordMap();
        Assert.assertEquals(3, forwardIndex.get(ByteBuffer.wrap("v1".getBytes())).size());
        Assert.assertEquals(2, forwardIndex.get(ByteBuffer.wrap("v2".getBytes())).size());
        Assert.assertEquals(1, forwardIndex.get(ByteBuffer.wrap("v3".getBytes())).size());
        Assert.assertTrue(forwardIndex.get(ByteBuffer.wrap("v1".getBytes())).contains(ByteBuffer.wrap("k1".getBytes())));
        Assert.assertTrue(forwardIndex.get(ByteBuffer.wrap("v1".getBytes())).contains(ByteBuffer.wrap("k2".getBytes())));
        Assert.assertTrue(forwardIndex.get(ByteBuffer.wrap("v1".getBytes())).contains(ByteBuffer.wrap("k3".getBytes())));

        Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters = server.getValueBloomFilters();
        CapeBloomFilterAdapter v1Filter = valueBloomFilters.get(ByteBuffer.wrap("v1".getBytes()));
        Assert.assertTrue(v1Filter.mightContain(CapePirUtils.keywordToByteArray(ByteBuffer.wrap("k1".getBytes()))));
        Assert.assertTrue(v1Filter.mightContain(CapePirUtils.keywordToByteArray(ByteBuffer.wrap("k2".getBytes()))));
        Assert.assertTrue(v1Filter.mightContain(CapePirUtils.keywordToByteArray(ByteBuffer.wrap("k3".getBytes()))));
        CapeBloomFilterAdapter v3Filter = valueBloomFilters.get(ByteBuffer.wrap("v3".getBytes()));
        Assert.assertTrue(v3Filter.mightContain(CapePirUtils.keywordToByteArray(ByteBuffer.wrap("k1".getBytes()))));
    }

    @Test
    public void testServerPreprocessPayload() throws Exception {
        CapePirServer<ByteBuffer> server = createInitializedServer();
        CapePirParams params = server.getCapeParams();
        byte[] k1Payload = server.getKeywordPayloadMap().get(ByteBuffer.wrap("k1".getBytes()));
        List<CapePirUtils.ValueWithBloomFilter> items = CapePirUtils.parseKeywordPayloadItems(k1Payload, params);
        Assert.assertEquals(3, items.size());
        Map<ByteBuffer, CapeBloomFilterAdapter> valueBloomFilters = server.getValueBloomFilters();
        Assert.assertArrayEquals("v1".getBytes(), items.get(0).getValue());
        Assert.assertArrayEquals(
            valueBloomFilters.get(ByteBuffer.wrap("v1".getBytes())).getStorage(), items.get(0).getBloomFilterBytes()
        );
        Assert.assertArrayEquals("v2".getBytes(), items.get(1).getValue());
        Assert.assertArrayEquals(
            valueBloomFilters.get(ByteBuffer.wrap("v2".getBytes())).getStorage(), items.get(1).getBloomFilterBytes()
        );
        Assert.assertArrayEquals("v3".getBytes(), items.get(2).getValue());
        Assert.assertArrayEquals(
            valueBloomFilters.get(ByteBuffer.wrap("v3".getBytes())).getStorage(), items.get(2).getBloomFilterBytes()
        );
    }

    @Test
    public void testFormalInitSameSeedBffStorage() throws Exception {
        Map<ByteBuffer, List<byte[]>> keywordValueMap = createKeywordValueMap();
        CapePirServer<ByteBuffer> server = createInitializedServer(keywordValueMap);
        Assert.assertFalse(server.isLegacyFullPayloadBuilt());
        Assert.assertFalse(server.isBloomOnlyBitMatricesBuilt());
        CapePirParams params = server.getCapeParams();
        long[][] valueOnlyBffStorage = server.getValueOnlyBffStorage();
        long[][] bloomOnlyBffStorage = server.getBloomOnlyBffStorage();
        byte[] bffSeed = server.getBffSeed();
        for (Map.Entry<ByteBuffer, List<byte[]>> entry : keywordValueMap.entrySet()) {
            int[] positions = CapePirUtils.getHashPositionsFromKeywordBytes(
                CapePirUtils.keywordToByteArray(entry.getKey()), keywordValueMap.size(), bffSeed, params
            );
            long[] valuePayload = CapePirUtils.buildValueOnlyLongPayload(entry.getKey(), entry.getValue(), params);
            long[] bloomPayload = CapePirUtils.buildBloomOnlyLongPayload(
                entry.getValue(), server.getValueBloomFilters(), params
            );
            for (int blockIndex = 0; blockIndex < valuePayload.length; blockIndex++) {
                long actual = 0;
                for (int position : positions) {
                    actual = Math.floorMod(
                        actual + valueOnlyBffStorage[blockIndex][position], params.getPlainModulus()
                    );
                }
                Assert.assertEquals(valuePayload[blockIndex], actual);
            }
            for (int blockIndex = 0; blockIndex < bloomPayload.length; blockIndex++) {
                long actual = 0L;
                for (int position : positions) {
                    actual = Math.floorMod(
                        actual + bloomOnlyBffStorage[blockIndex][position], params.getPlainModulus()
                    );
                }
                Assert.assertEquals(bloomPayload[blockIndex], actual);
            }
        }
    }

    private CapePirServer<ByteBuffer> createInitializedServer() throws Exception {
        return createInitializedServer(createKeywordValueMap());
    }

    private CapePirServer<ByteBuffer> createInitializedServer(Map<ByteBuffer, List<byte[]>> keywordValueMap)
        throws Exception {
        MemoryRpcManager rpcManager = new MemoryRpcManager(2);
        CapePirConfig config = new CapePirConfig.Builder().build();
        CapePirServer<ByteBuffer> server = new CapePirServer<>(
            rpcManager.getRpc(0), rpcManager.getRpc(1).ownParty(), config
        );
        server.init(keywordValueMap, 1);
        return server;
    }

    private Map<ByteBuffer, List<byte[]>> createKeywordValueMap() {
        return Map.of(
            ByteBuffer.wrap("k1".getBytes()), List.of("v1".getBytes(), "v2".getBytes(), "v3".getBytes()),
            ByteBuffer.wrap("k2".getBytes()), List.of("v1".getBytes()),
            ByteBuffer.wrap("k3".getBytes()), List.of("v1".getBytes(), "v2".getBytes())
        );
    }

}
