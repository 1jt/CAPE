package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * CAPE_C server compressed anchor recovery tests.
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
public class CapeCPirServerRecoveryTest {
    @Test
    public void testParseAndRecoverCompressedAnchorQuery() throws Exception {
        MemoryRpcManager rpcManager = new MemoryRpcManager(2);
        CapeCPirConfig clientConfig = new CapeCPirConfig.Builder().build();
        CapeCPirConfig serverConfig = new CapeCPirConfig.Builder().build();
        CapeCPirClient<ByteBuffer> client = new CapeCPirClient<>(
            rpcManager.getRpc(0), rpcManager.getRpc(1).ownParty(), clientConfig
        );
        CapeCPirServer<ByteBuffer> server = new CapeCPirServer<>(
            rpcManager.getRpc(1), rpcManager.getRpc(0).ownParty(), serverConfig
        );
        int keywordNum = 128;
        byte[] bffSeed = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
        client.getCapeCParams().initPirParams(keywordNum, 2, 3, clientConfig.getBoolKeywordNum());
        server.setStateForTest(keywordNum, 2, 3, 1, bffSeed);
        long[] lweSecretKey = new long[CapeCPirUtils.LWE_DIMENSION];
        for (int i = 0; i < lweSecretKey.length; i++) {
            lweSecretKey[i] = i % 2;
        }
        client.setStateForTest(keywordNum, bffSeed, lweSecretKey);
        List<byte[]> packedBloomQuery = new ArrayList<>();
        for (int i = 0; i < client.getCapeCParams().getPackedQueryBloomCiphertextNum(); i++) {
            packedBloomQuery.add(new byte[]{(byte) i});
        }
        CapeCPirQuery clientQuery = client.generateCapeCQueryForTest(List.of(
            ByteBuffer.wrap(new byte[]{0x01}),
            ByteBuffer.wrap(new byte[]{0x02}),
            ByteBuffer.wrap(new byte[]{0x03})
        ), packedBloomQuery);
        List<byte[]> payload = clientQuery.getServerPayload();
        Assert.assertEquals(1 + server.getCapeCParams().getPackedQueryBloomCiphertextNum(), payload.size());
        CapeCPirQuery parsedQuery = server.parseQueryPayload(payload);
        CapeCCompressedAnchorQuery compressedAnchorQuery = CapeCCompressedAnchorQuery.fromByteArray(
            parsedQuery.getCompressedAnchorQuery()
        );
        int rowBitNum = CapeCPirUtils.ceilLog2(server.getCapeCParams().getMatrixRowNum());
        int colBitNum = CapeCPirUtils.ceilLog2(server.getCapeCParams().getMatrixColNum());
        int expectedBitCount = server.getCapeCParams().getBffHashNum() * (rowBitNum + colBitNum);
        Assert.assertEquals(rowBitNum, compressedAnchorQuery.getRowBitNum());
        Assert.assertEquals(colBitNum, compressedAnchorQuery.getColBitNum());
        List<byte[]> convertedRgswBits = new ArrayList<>(expectedBitCount);
        for (int bitIndex = 0; bitIndex < expectedBitCount; bitIndex++) {
            convertedRgswBits.add(new byte[]{(byte) bitIndex});
        }
        CapeCPirServer.RecoveredAnchorQuery recovered = server.recoverCompressedAnchorQueryForTest(
            parsedQuery, convertedRgswBits
        );
        Assert.assertEquals(rowBitNum, recovered.getRowBitNum());
        Assert.assertEquals(colBitNum, recovered.getColBitNum());
        Assert.assertEquals(expectedBitCount, recovered.getRecoveredLweBitCount());
        Assert.assertEquals(expectedBitCount, recovered.getConvertedRgswBitCount());
        Assert.assertEquals(server.getCapeCParams().getBffHashNum(), recovered.getRowRgswBits().length);
        Assert.assertEquals(server.getCapeCParams().getBffHashNum(), recovered.getColRgswBits().length);
    }

    @Test
    public void testMalformedQueryPayloadCountFailsClosed() {
        MemoryRpcManager rpcManager = new MemoryRpcManager(2);
        CapeCPirConfig clientConfig = new CapeCPirConfig.Builder().build();
        CapeCPirConfig serverConfig = new CapeCPirConfig.Builder().build();
        CapeCPirClient<ByteBuffer> client = new CapeCPirClient<>(
            rpcManager.getRpc(0), rpcManager.getRpc(1).ownParty(), clientConfig
        );
        CapeCPirServer<ByteBuffer> server = new CapeCPirServer<>(
            rpcManager.getRpc(1), rpcManager.getRpc(0).ownParty(), serverConfig
        );
        int keywordNum = 128;
        byte[] bffSeed = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
        client.getCapeCParams().initPirParams(keywordNum, 2, 3, clientConfig.getBoolKeywordNum());
        server.setStateForTest(keywordNum, 2, 3, 1, bffSeed);
        long[] lweSecretKey = new long[CapeCPirUtils.LWE_DIMENSION];
        client.setStateForTest(keywordNum, bffSeed, lweSecretKey);
        List<byte[]> packedBloomQuery = new ArrayList<>();
        for (int i = 0; i < client.getCapeCParams().getPackedQueryBloomCiphertextNum(); i++) {
            packedBloomQuery.add(new byte[]{(byte) i});
        }
        CapeCPirQuery clientQuery = client.generateCapeCQueryForTest(List.of(
            ByteBuffer.wrap(new byte[]{0x01}),
            ByteBuffer.wrap(new byte[]{0x02}),
            ByteBuffer.wrap(new byte[]{0x03})
        ), packedBloomQuery);
        List<byte[]> payload = new ArrayList<>(clientQuery.getServerPayload());
        List<byte[]> shortPayload = new ArrayList<>(payload);
        shortPayload.remove(shortPayload.size() - 1);
        Assert.assertThrows(IllegalArgumentException.class, () -> server.parseQueryPayload(shortPayload));
        List<byte[]> longPayload = new ArrayList<>(payload);
        longPayload.add(new byte[]{0x42});
        Assert.assertThrows(IllegalArgumentException.class, () -> server.parseQueryPayload(longPayload));
    }

}
