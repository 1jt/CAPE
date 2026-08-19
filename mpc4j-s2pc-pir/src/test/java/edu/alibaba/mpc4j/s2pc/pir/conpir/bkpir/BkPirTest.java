package edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir;

import edu.alibaba.mpc4j.common.rpc.pto.AbstractTwoPartyMemoryRpcPto;
import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * BKPIR test.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class BkPirTest extends AbstractTwoPartyMemoryRpcPto {

    public BkPirTest() {
        super(BkPirPtoDesc.getInstance().getPtoName());
    }

    @Test
    public void testAnd() throws InterruptedException {
        byte[] v1 = new byte[]{0x01, 0x11};
        byte[] v2 = new byte[]{0x02, 0x22};
        byte[] v3 = new byte[]{0x00, 0x33};
        byte[] v4 = new byte[]{0x04, 0x44};
        Map<String, List<byte[]>> keywordValueMap = new LinkedHashMap<>();
        keywordValueMap.put("kw1", Arrays.asList(v1, v2, v3));
        keywordValueMap.put("kw2", Arrays.asList(v2, v3));
        keywordValueMap.put("kw3", Arrays.asList(v3, v4));
        ArrayList<byte[]> valueSpace = new ArrayList<>(Arrays.asList(v1, v2, v3, v4));
        ArrayList<List<String>> queries = new ArrayList<>();
        queries.add(Arrays.asList("kw1", "kw2", "kw3"));
        List<byte[]>[] result = runPir(keywordValueMap, valueSpace, queries);
        Assert.assertEquals(1, result.length);
        Assert.assertEquals(1, result[0].size());
        Assert.assertArrayEquals(v3, result[0].get(0));
    }

    private List<byte[]>[] runPir(Map<String, List<byte[]>> keywordValueMap, List<byte[]> valueSpace,
                                  ArrayList<List<String>> queries) throws InterruptedException {
        BkPirConfig config = new BkPirConfig.Builder()
            .setQueryMethod(BkPirQueryMethod.AND)
            .setBoolKeywordNum(3)
            .build();
        BkPirServer<String> server = new BkPirServer<>(firstRpc, secondRpc.ownParty(), config);
        BkPirClient<String> client = new BkPirClient<>(secondRpc, firstRpc.ownParty(), config);
        AtomicReference<List<byte[]>[]> result = new AtomicReference<>();
        AtomicReference<Exception> exception = new AtomicReference<>();
        Thread serverThread = new Thread(() -> {
            try {
                server.init(keywordValueMap, queries.size());
                server.getRpc().synchronize();
                server.getRpc().reset();
                server.pir(queries.size());
                server.getRpc().synchronize();
                server.getRpc().reset();
            } catch (Throwable e) {
                exception.set(new Exception(e));
            }
        });
        Thread clientThread = new Thread(() -> {
            try {
                client.init(keywordValueMap.size(), valueSpace, queries.size());
                client.getRpc().synchronize();
                client.getRpc().reset();
                result.set(client.pir(queries));
                client.getRpc().synchronize();
                client.getRpc().reset();
            } catch (Throwable e) {
                exception.set(new Exception(e));
            }
        });
        serverThread.start();
        clientThread.start();
        serverThread.join();
        clientThread.join();
        new Thread(server::destroy).start();
        new Thread(client::destroy).start();
        if (exception.get() != null) {
            throw new AssertionError(exception.get());
        }
        return result.get();
    }
}
