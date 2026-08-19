package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractTwoPartyMemoryRpcPto;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.StdKwPirClient;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.StdKwPirFactory;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.StdKwPirServer;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * MMK standard keyword PIR test.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class MmkStdKwPirTest extends AbstractTwoPartyMemoryRpcPto {
    /**
     * label byte length
     */
    private static final int LABEL_BYTE_LENGTH = Long.BYTES;

    public MmkStdKwPirTest() {
        super(StdKwPirFactory.StdKwPirType.MMK.name());
    }

    @Test
    public void testBatchHit() throws InterruptedException {
        Map<ByteBuffer, byte[]> keyValueMap = new LinkedHashMap<>();
        ByteBuffer key0 = ByteBuffer.wrap("KEY_0".getBytes());
        ByteBuffer key1 = ByteBuffer.wrap("KEY_1".getBytes());
        byte[] value0 = new byte[]{0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67};
        byte[] value1 = new byte[]{0x10, 0x32, 0x54, 0x76, 0x10, 0x32, 0x54, 0x76};
        keyValueMap.put(key0, value0);
        keyValueMap.put(key1, value1);
        ArrayList<ByteBuffer> keys = new ArrayList<>(Arrays.asList(key0, key1));
        byte[][] result = runPir(keyValueMap, keys);
        Assert.assertArrayEquals(value0, result[0]);
        Assert.assertArrayEquals(value1, result[1]);
    }

    @Test
    public void testMiss() throws InterruptedException {
        Map<ByteBuffer, byte[]> keyValueMap = new LinkedHashMap<>();
        keyValueMap.put(ByteBuffer.wrap("KEY_0".getBytes()), new byte[]{0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67});
        ArrayList<ByteBuffer> keys = new ArrayList<>();
        keys.add(ByteBuffer.wrap("MISS".getBytes()));
        byte[][] result = runPir(keyValueMap, keys);
        Assert.assertEquals(0, result[0].length);
    }

    private byte[][] runPir(Map<ByteBuffer, byte[]> keyValueMap, ArrayList<ByteBuffer> keys) throws InterruptedException {
        MmkStdKwPirConfig config = new MmkStdKwPirConfig.Builder().build();
        StdKwPirServer<ByteBuffer> server = StdKwPirFactory.createServer(firstRpc, secondRpc.ownParty(), config);
        StdKwPirClient<ByteBuffer> client = StdKwPirFactory.createClient(secondRpc, firstRpc.ownParty(), config);
        AtomicReference<byte[][]> result = new AtomicReference<>();
        AtomicReference<Exception> exception = new AtomicReference<>();
        Thread serverThread = new Thread(() -> {
            try {
                server.init(keyValueMap, LABEL_BYTE_LENGTH * Byte.SIZE, keys.size());
                server.getRpc().synchronize();
                server.getRpc().reset();
                server.pir(keys.size());
                server.getRpc().synchronize();
                server.getRpc().reset();
            } catch (Throwable e) {
                exception.set(new Exception(e));
            }
        });
        Thread clientThread = new Thread(() -> {
            try {
                client.init(keyValueMap.size(), LABEL_BYTE_LENGTH * Byte.SIZE, keys.size());
                client.getRpc().synchronize();
                client.getRpc().reset();
                result.set(client.pir(keys));
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
