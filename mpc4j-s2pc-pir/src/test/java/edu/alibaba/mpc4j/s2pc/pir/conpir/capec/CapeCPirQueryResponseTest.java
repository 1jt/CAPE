package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;
import edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirQueryMethod;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * CAPE_C end-to-end query / response tests.
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
public class CapeCPirQueryResponseTest {
    private static final CapeCPirParams TEST_PARAMS = new CapeCPirParams(
        8192, 65537L, new int[]{60, 60, 60, 60}, 3, 40, 2, 3, true,
        Math.pow(2.0, -10), new byte[edu.alibaba.mpc4j.common.tool.CommonConstants.BLOCK_BYTE_LENGTH],
        CapePirQueryMethod.AND, 3
    );

    @Test
    public void testThreeKeywordFormalPir() throws Exception {
        ProtocolResult result = runFormalPir(3, List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        ));
        Assert.assertEquals(1, result.entries[0].size());
        Assert.assertArrayEquals(new byte[]{0x01, 0x01}, result.entries[0].get(0));
        assertProtocolShape(result);
    }

    @Test
    public void testTwoKeywordFormalPir() throws Exception {
        ProtocolResult result = runFormalPir(2, List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        ));
        Set<String> actual = result.entries[0].stream()
            .map(java.util.Arrays::toString)
            .collect(Collectors.toSet());
        Assert.assertEquals(2, actual.size());
        Assert.assertTrue(actual.contains(java.util.Arrays.toString(new byte[]{0x01, 0x01})));
        Assert.assertTrue(actual.contains(java.util.Arrays.toString(new byte[]{0x01, 0x02})));
        assertProtocolShape(result);
    }

    private static ProtocolResult runFormalPir(int boolKeywordNum, List<ByteBuffer> query) throws Exception {
        MemoryRpcManager rpcManager = new MemoryRpcManager(2);
        CapeCPirConfig clientConfig = new CapeCPirConfig.Builder()
            .setParams(new CapeCPirParams(TEST_PARAMS))
            .setBoolKeywordNum(boolKeywordNum)
            .build();
        CapeCPirConfig serverConfig = new CapeCPirConfig.Builder()
            .setParams(new CapeCPirParams(TEST_PARAMS))
            .setBoolKeywordNum(boolKeywordNum)
            .build();
        CapeCPirClient<ByteBuffer> client = new CapeCPirClient<>(
            rpcManager.getRpc(0), rpcManager.getRpc(1).ownParty(), clientConfig
        );
        CapeCPirServer<ByteBuffer> server = new CapeCPirServer<>(
            rpcManager.getRpc(1), rpcManager.getRpc(0).ownParty(), serverConfig
        );
        ArrayList<List<ByteBuffer>> queries = new ArrayList<>();
        queries.add(query);
        CapeCServerThread serverThread = new CapeCServerThread(server);
        CapeCClientThread clientThread = new CapeCClientThread(client, boolKeywordNum, queries);
        serverThread.start();
        clientThread.start();
        serverThread.join();
        clientThread.join();
        if (serverThread.throwable != null) {
            throw new AssertionError(serverThread.throwable);
        }
        if (clientThread.throwable != null) {
            throw new AssertionError(clientThread.throwable);
        }
        return new ProtocolResult(client, server, clientThread.entries);
    }

    private static void assertProtocolShape(ProtocolResult result) {
        CapeCPirParams params = result.client.getCapeCParams();
        CapeCPirQuery lastQuery = result.client.getLastQueries().get(0);
        Assert.assertEquals(1 + params.getPackedQueryBloomCiphertextNum(), lastQuery.getServerPayload().size());
        Assert.assertEquals(1 + params.getPackedQueryBloomCiphertextNum(), result.server.getLastExpectedQueryPayloadCount());
        Assert.assertEquals(result.server.getLastExpectedQueryPayloadCount(), result.server.getLastActualQueryPayloadCount());
        Assert.assertEquals(params.getExpectedPackedResultCiphertextCount(), result.server.getLastPackedResultCiphertextCount());
        Assert.assertEquals(result.server.getLastPackedResultCiphertextCount(), result.entries.length);
        Assert.assertTrue(result.client.getLastCompressedAnchorQueryBytes() > 0);
        Assert.assertEquals(params.getPackedQueryBloomCiphertextNum(), lastQuery.getEncryptedPackedBloomQuery().size());
        Assert.assertTrue(result.client.getLastPackedBloomQueryBytes() > 0);
        Assert.assertEquals(
            result.client.getLastCompressedAnchorQueryBytes() + result.client.getLastPackedBloomQueryBytes(),
            result.client.getLastTotalOnlineQueryBytes()
        );
        Assert.assertEquals(1, result.server.getLastValueCiphertextCount());
        Assert.assertEquals(1, result.server.getLastScoreCiphertextCount());
        Assert.assertTrue(result.server.getLastPackedResultBytes() > 0);
        Assert.assertTrue(result.server.getSetupLweToRgswKeyBytes() > 0);
    }

    private static Map<ByteBuffer, List<byte[]>> createKeywordValueMap() {
        Map<ByteBuffer, List<byte[]>> keywordMap = new LinkedHashMap<>();
        keywordMap.put(ByteBuffer.wrap("k1".getBytes()), List.of(
            new byte[]{0x01, 0x01}, new byte[]{0x01, 0x02}, new byte[]{0x01, 0x03}
        ));
        keywordMap.put(ByteBuffer.wrap("k2".getBytes()), List.of(new byte[]{0x01, 0x01}));
        keywordMap.put(ByteBuffer.wrap("k3".getBytes()), List.of(new byte[]{0x01, 0x01}, new byte[]{0x01, 0x02}));
        return keywordMap;
    }

    private static class CapeCServerThread extends Thread {
        private final CapeCPirServer<ByteBuffer> server;
        private Throwable throwable;

        private CapeCServerThread(CapeCPirServer<ByteBuffer> server) {
            this.server = server;
        }

        @Override
        public void run() {
            try {
                server.init(createKeywordValueMap(), 2, 3, 1);
                server.receivePublicKeysAndSendSeed();
                server.pir(1);
            } catch (Throwable t) {
                throwable = t;
            }
        }
    }

    private static class CapeCClientThread extends Thread {
        private final CapeCPirClient<ByteBuffer> client;
        private final int boolKeywordNum;
        private final ArrayList<List<ByteBuffer>> queries;
        private List<byte[]>[] entries;
        private Throwable throwable;

        private CapeCClientThread(CapeCPirClient<ByteBuffer> client, int boolKeywordNum,
                                 ArrayList<List<ByteBuffer>> queries) {
            this.client = client;
            this.boolKeywordNum = boolKeywordNum;
            this.queries = queries;
        }

        @Override
        public void run() {
            try {
                client.init(3, 2, 3, 1);
                Assert.assertEquals(boolKeywordNum, client.getCapeCParams().getBoolKeywordNum());
                client.sendPublicKeysAndReceiveSeed();
                entries = client.pir(queries);
            } catch (Throwable t) {
                throwable = t;
            }
        }
    }

    private record ProtocolResult(CapeCPirClient<ByteBuffer> client, CapeCPirServer<ByteBuffer> server,
                                  List<byte[]>[] entries) {
    }
}
