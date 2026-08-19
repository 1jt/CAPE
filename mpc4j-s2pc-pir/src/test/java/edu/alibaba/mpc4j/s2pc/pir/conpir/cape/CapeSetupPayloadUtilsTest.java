package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * Tests for chunked CAPE setup payload transfer utilities.
 */
public class CapeSetupPayloadUtilsTest {

    @Test
    public void testLweToRgswKeyChunkPlan() {
        int maxChunkBytes = 24;
        List<byte[]> items = List.of(
            bytes(1, 2),
            bytes(3, 4, 5, 6, 7, 8, 9, 10),
            bytes(11, 12, 13, 14, 15, 16, 17, 18),
            bytes(19, 20, 21)
        );

        List<CapeSetupPayloadUtils.SetupChunk> chunks = CapeSetupPayloadUtils.planChunks(items, maxChunkBytes);

        Assert.assertEquals(2, chunks.size());
        for (CapeSetupPayloadUtils.SetupChunk chunk : chunks) {
            Assert.assertTrue(chunk.getByteLength() + 2L * Integer.BYTES <= maxChunkBytes);
        }
        Assert.assertArrayEquals(flatten(items), flattenChunks(chunks));
    }

    @Test
    public void testLweToRgswKeyChunkPlanAllowsSingleOversizedItem() {
        int maxChunkBytes = 16;
        List<byte[]> items = List.of(bytes(1, 2), bytes(3, 4, 5, 6, 7, 8, 9, 10, 11), bytes(12));

        List<CapeSetupPayloadUtils.SetupChunk> chunks = CapeSetupPayloadUtils.planChunks(items, maxChunkBytes);

        Assert.assertEquals(3, chunks.size());
        Assert.assertEquals(1, chunks.get(1).getItems().size());
        Assert.assertTrue(chunks.get(1).getByteLength() + 2L * Integer.BYTES > maxChunkBytes);
        Assert.assertArrayEquals(flatten(items), flattenChunks(chunks));
    }

    @Test
    public void testChunkedPublicKeyPayloadRoundtrip() {
        byte[] publicKey = bytes(1, 2, 3);
        byte[] relinKeys = bytes(4, 5, 6, 7);
        byte[] galoisKeys = bytes(8, 9);
        List<byte[]> lweToRgswKey = List.of(bytes(10, 11), bytes(12, 13, 14), bytes(15), bytes(16, 17));
        int maxChunkBytes = 14;

        List<byte[]> bfvKeysPayload = List.of(publicKey, relinKeys, galoisKeys);
        Assert.assertEquals(3, bfvKeysPayload.size());
        Assert.assertArrayEquals(publicKey, bfvKeysPayload.get(0));
        Assert.assertArrayEquals(relinKeys, bfvKeysPayload.get(1));
        Assert.assertArrayEquals(galoisKeys, bfvKeysPayload.get(2));

        List<CapeSetupPayloadUtils.SetupChunk> chunks = CapeSetupPayloadUtils.planChunks(lweToRgswKey, maxChunkBytes);
        long totalBytes = CapeSetupPayloadUtils.byteLength(lweToRgswKey);
        CapeSetupPayloadUtils.SetupMeta meta = CapeSetupPayloadUtils.decodeMeta(
            CapeSetupPayloadUtils.encodeMeta(lweToRgswKey.size(), chunks.size(), totalBytes, maxChunkBytes)
        );
        Assert.assertEquals(lweToRgswKey.size(), meta.getItemCount());
        Assert.assertEquals(chunks.size(), meta.getChunkCount());
        Assert.assertEquals(totalBytes, meta.getTotalBytes());
        Assert.assertEquals(maxChunkBytes, meta.getMaxChunkBytes());

        List<byte[]> reassembled = new ArrayList<>();
        long reassembledBytes = 0L;
        for (int i = 0; i < chunks.size(); i++) {
            CapeSetupPayloadUtils.DecodedChunk decoded = CapeSetupPayloadUtils.decodeChunk(
                CapeSetupPayloadUtils.encodeChunk(chunks.get(i))
            );
            Assert.assertEquals(i, decoded.getChunkIndex());
            Assert.assertEquals(decoded.getItemCount(), decoded.getItems().size());
            reassembled.addAll(decoded.getItems());
            reassembledBytes += decoded.getByteLength();
        }
        Assert.assertEquals(totalBytes, reassembledBytes);
        Assert.assertEquals(lweToRgswKey.size(), reassembled.size());
        for (int i = 0; i < lweToRgswKey.size(); i++) {
            Assert.assertArrayEquals(lweToRgswKey.get(i), reassembled.get(i));
        }
    }

    private static byte[] bytes(int... values) {
        byte[] bytes = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            bytes[i] = (byte) values[i];
        }
        return bytes;
    }

    private static byte[] flatten(List<byte[]> items) {
        int length = items.stream().mapToInt(item -> item.length).sum();
        byte[] flattened = new byte[length];
        int offset = 0;
        for (byte[] item : items) {
            System.arraycopy(item, 0, flattened, offset, item.length);
            offset += item.length;
        }
        return flattened;
    }

    private static byte[] flattenChunks(List<CapeSetupPayloadUtils.SetupChunk> chunks) {
        List<byte[]> items = new ArrayList<>();
        chunks.forEach(chunk -> items.addAll(chunk.getItems()));
        return flatten(items);
    }
}
