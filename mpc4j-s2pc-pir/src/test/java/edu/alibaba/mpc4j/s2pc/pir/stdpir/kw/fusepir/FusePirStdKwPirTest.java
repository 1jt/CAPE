package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

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
 * FUSE_PIR standard keyword PIR test.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class FusePirStdKwPirTest extends AbstractTwoPartyMemoryRpcPto {

    public FusePirStdKwPirTest() {
        super(FusePirStdKwPirPtoDesc.getInstance().getPtoName());
    }

    @Test
    public void testSmallSingleKeyword() throws InterruptedException {
        FusePirStdKwPirParams params = new FusePirStdKwPirParams(
            8192, 65537L, new int[]{30, 30, 30, 30}, 3, 8, 1, 1, true
        );
        FusePirStdKwPirConfig config = new FusePirStdKwPirConfig.Builder().setParams(params).build();
        Map<String, byte[]> keyValueMap = new LinkedHashMap<>();
        keyValueMap.put("kw1", FusePirStdKwPirUtils.serializeValueSet(List.of(new byte[]{0x11}), params));
        keyValueMap.put("kw2", FusePirStdKwPirUtils.serializeValueSet(List.of(new byte[]{0x22}), params));
        keyValueMap.put("kw3", FusePirStdKwPirUtils.serializeValueSet(List.of(new byte[]{0x33}), params));
        keyValueMap.put("kw4", FusePirStdKwPirUtils.serializeValueSet(List.of(new byte[]{0x44}), params));
        FusePirStdKwPirServer<String> server = new FusePirStdKwPirServer<>(firstRpc, secondRpc.ownParty(), config);
        FusePirStdKwPirClient<String> client = new FusePirStdKwPirClient<>(secondRpc, firstRpc.ownParty(), config);
        AtomicReference<byte[][]> result = new AtomicReference<>();
        Thread serverThread = new Thread(() -> {
            try {
                server.init(keyValueMap, Byte.SIZE, 1);
                server.pir(1);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        Thread clientThread = new Thread(() -> {
            try {
                client.init(keyValueMap.size(), Byte.SIZE, 1);
                result.set(client.pir(new ArrayList<>(List.of("kw3"))));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        serverThread.start();
        clientThread.start();
        serverThread.join();
        clientThread.join();
        byte[] expected = FusePirStdKwPirUtils.serializeValueSet(List.of(new byte[]{0x33}), params);
        Assert.assertArrayEquals(expected, result.get()[0]);
        Assert.assertFalse(Arrays.equals(expected, new byte[expected.length]));
    }
}
