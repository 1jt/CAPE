package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;
import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * CAPE_C client query tests.
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
public class CapeCPirClientQueryTest {
    @Test
    public void testFormalPayloadShape() {
        CapeCPirConfig config = new CapeCPirConfig.Builder().build();
        MemoryRpcManager rpcManager = new MemoryRpcManager(2);
        CapeCPirClient<ByteBuffer> client = new CapeCPirClient<>(
            rpcManager.getRpc(0), rpcManager.getRpc(1).ownParty(), config
        );
        CapeCPirParams params = client.getCapeCParams();
        params.initPirParams(16, 2, 3, config.getBoolKeywordNum());
        byte[] bffSeed = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
        long[] lweSecretKey = new long[CapeCPirUtils.LWE_DIMENSION];
        for (int i = 0; i < lweSecretKey.length; i++) {
            lweSecretKey[i] = i % 2;
        }
        client.setStateForTest(16, bffSeed, lweSecretKey);
        List<byte[]> encryptedPackedBloomQuery = new ArrayList<>();
        for (int i = 0; i < params.getPackedQueryBloomCiphertextNum(); i++) {
            encryptedPackedBloomQuery.add(new byte[]{(byte) i, (byte) (i + 1)});
        }
        List<ByteBuffer> queryKeywords = List.of(
            ByteBuffer.wrap(new byte[]{0x01}),
            ByteBuffer.wrap(new byte[]{0x02}),
            ByteBuffer.wrap(new byte[]{0x03})
        );
        CapeCPirQuery query = client.generateCapeCQueryForTest(queryKeywords, encryptedPackedBloomQuery);
        List<byte[]> payload = query.getServerPayload();
        Assert.assertEquals(1 + params.getPackedQueryBloomCiphertextNum(), payload.size());
        Assert.assertEquals(encryptedPackedBloomQuery.size(), query.getEncryptedPackedBloomQuery().size());
        CapeCCompressedAnchorQuery anchorQuery = CapeCCompressedAnchorQuery.fromByteArray(payload.get(0));
        Assert.assertEquals(params.getBffHashNum(), anchorQuery.getBffHashNum());
        Assert.assertEquals(CapeCPirUtils.ceilLog2(params.getMatrixRowNum()), anchorQuery.getRowBitNum());
        Assert.assertEquals(CapeCPirUtils.ceilLog2(params.getMatrixColNum()), anchorQuery.getColBitNum());
        Assert.assertFalse(containsPayload(payload, query.getAnchorKeywordBytes()));
        Assert.assertArrayEquals(payload.get(0), query.getCompressedAnchorQuery());
        for (int i = 0; i < encryptedPackedBloomQuery.size(); i++) {
            Assert.assertArrayEquals(encryptedPackedBloomQuery.get(i), payload.get(i + 1));
        }
        Assert.assertNotEquals(params.getBffHashNum() + params.getBffHashNum()
            + params.getPackedQueryBloomCiphertextNum(), payload.size());
        Assert.assertEquals(3 * (anchorQuery.getRowBitNum() + anchorQuery.getColBitNum()) * Long.BYTES,
            anchorQuery.getBArrayByteLength());
    }

    private static boolean containsPayload(List<byte[]> payload, byte[] target) {
        for (byte[] item : payload) {
            if (java.util.Arrays.equals(item, target)) {
                return true;
            }
        }
        return false;
    }
}
