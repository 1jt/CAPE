package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Utilities for chunked CAPE setup payload transfer.
 */
final class CapeSetupPayloadUtils {
    /**
     * Maximum RPC payload bytes per setup chunk. Chunks split only at byte[] item boundaries.
     */
    static final int DEFAULT_MAX_SETUP_CHUNK_BYTES = 32 * 1024 * 1024;
    /**
     * Chunk payload header: chunk index + item count.
     */
    private static final int CHUNK_HEADER_BYTES = 2 * Integer.BYTES;

    private CapeSetupPayloadUtils() {
        // empty
    }

    static byte[] intToByteArray(int value) {
        return ByteBuffer.allocate(Integer.BYTES).putInt(value).array();
    }

    static byte[] longToByteArray(long value) {
        return ByteBuffer.allocate(Long.BYTES).putLong(value).array();
    }

    static int byteArrayToInt(byte[] bytes, String name) {
        if (bytes.length != Integer.BYTES) {
            throw new IllegalArgumentException(name + " must be " + Integer.BYTES + " bytes: " + bytes.length);
        }
        return ByteBuffer.wrap(bytes).getInt();
    }

    static long byteArrayToLong(byte[] bytes, String name) {
        if (bytes.length != Long.BYTES) {
            throw new IllegalArgumentException(name + " must be " + Long.BYTES + " bytes: " + bytes.length);
        }
        return ByteBuffer.wrap(bytes).getLong();
    }

    static long byteLength(List<byte[]> payload) {
        return payload.stream().mapToLong(bytes -> bytes.length).sum();
    }

    static List<SetupChunk> planChunks(List<byte[]> items, int maxChunkBytes) {
        if (maxChunkBytes <= CHUNK_HEADER_BYTES) {
            throw new IllegalArgumentException("maxChunkBytes must exceed chunk header bytes: " + maxChunkBytes);
        }
        int maxItemBytesPerChunk = maxChunkBytes - CHUNK_HEADER_BYTES;
        List<SetupChunk> chunks = new ArrayList<>();
        List<byte[]> currentItems = new ArrayList<>();
        long currentBytes = 0L;
        for (byte[] item : items) {
            if (item == null) {
                throw new IllegalArgumentException("setup key item must not be null");
            }
            boolean itemFitsCurrentChunk = !currentItems.isEmpty()
                && currentBytes + item.length <= maxItemBytesPerChunk;
            if (!currentItems.isEmpty() && !itemFitsCurrentChunk) {
                chunks.add(new SetupChunk(chunks.size(), currentItems, currentBytes));
                currentItems = new ArrayList<>();
                currentBytes = 0L;
            }
            currentItems.add(item);
            currentBytes += item.length;
            if (item.length > maxItemBytesPerChunk) {
                chunks.add(new SetupChunk(chunks.size(), currentItems, currentBytes));
                currentItems = new ArrayList<>();
                currentBytes = 0L;
            }
        }
        if (!currentItems.isEmpty()) {
            chunks.add(new SetupChunk(chunks.size(), currentItems, currentBytes));
        }
        return chunks;
    }

    static List<byte[]> encodeMeta(int itemCount, int chunkCount, long totalBytes, int maxChunkBytes) {
        if (itemCount < 0 || chunkCount < 0 || totalBytes < 0 || maxChunkBytes <= CHUNK_HEADER_BYTES) {
            throw new IllegalArgumentException("invalid setup metadata");
        }
        return List.of(
            intToByteArray(itemCount),
            intToByteArray(chunkCount),
            longToByteArray(totalBytes),
            intToByteArray(maxChunkBytes)
        );
    }

    static SetupMeta decodeMeta(List<byte[]> payload) {
        if (payload.size() != 4) {
            throw new IllegalArgumentException("LWE-to-RGSW metadata payload must contain 4 items: " + payload.size());
        }
        int itemCount = byteArrayToInt(payload.get(0), "itemCount");
        int chunkCount = byteArrayToInt(payload.get(1), "chunkCount");
        long totalBytes = byteArrayToLong(payload.get(2), "totalBytes");
        int maxChunkBytes = byteArrayToInt(payload.get(3), "maxChunkBytes");
        if (itemCount < 0 || chunkCount < 0 || totalBytes < 0 || maxChunkBytes <= CHUNK_HEADER_BYTES) {
            throw new IllegalArgumentException("invalid LWE-to-RGSW metadata values");
        }
        return new SetupMeta(itemCount, chunkCount, totalBytes, maxChunkBytes);
    }

    static List<byte[]> encodeChunk(SetupChunk chunk) {
        List<byte[]> payload = new ArrayList<>(2 + chunk.items.size());
        payload.add(intToByteArray(chunk.chunkIndex));
        payload.add(intToByteArray(chunk.items.size()));
        chunk.items.forEach(item -> payload.add(Arrays.copyOf(item, item.length)));
        return payload;
    }

    static DecodedChunk decodeChunk(List<byte[]> payload) {
        if (payload.size() < 2) {
            throw new IllegalArgumentException("LWE-to-RGSW chunk payload must contain header");
        }
        int chunkIndex = byteArrayToInt(payload.get(0), "chunkIndex");
        int itemCount = byteArrayToInt(payload.get(1), "chunkItemCount");
        if (chunkIndex < 0 || itemCount < 0 || payload.size() != 2 + itemCount) {
            throw new IllegalArgumentException("invalid LWE-to-RGSW chunk shape");
        }
        List<byte[]> items = new ArrayList<>(itemCount);
        long byteLength = 0L;
        for (int i = 0; i < itemCount; i++) {
            byte[] item = payload.get(2 + i);
            items.add(Arrays.copyOf(item, item.length));
            byteLength += item.length;
        }
        return new DecodedChunk(chunkIndex, itemCount, items, byteLength);
    }

    static final class SetupMeta {
        private final int itemCount;
        private final int chunkCount;
        private final long totalBytes;
        private final int maxChunkBytes;

        private SetupMeta(int itemCount, int chunkCount, long totalBytes, int maxChunkBytes) {
            this.itemCount = itemCount;
            this.chunkCount = chunkCount;
            this.totalBytes = totalBytes;
            this.maxChunkBytes = maxChunkBytes;
        }

        int getItemCount() {
            return itemCount;
        }

        int getChunkCount() {
            return chunkCount;
        }

        long getTotalBytes() {
            return totalBytes;
        }

        int getMaxChunkBytes() {
            return maxChunkBytes;
        }
    }

    static final class SetupChunk {
        private final int chunkIndex;
        private final List<byte[]> items;
        private final long byteLength;

        private SetupChunk(int chunkIndex, List<byte[]> items, long byteLength) {
            this.chunkIndex = chunkIndex;
            this.items = new ArrayList<>(items.size());
            this.items.addAll(items);
            this.byteLength = byteLength;
        }

        int getChunkIndex() {
            return chunkIndex;
        }

        List<byte[]> getItems() {
            return items;
        }

        long getByteLength() {
            return byteLength;
        }

        void clearItems() {
            items.clear();
        }
    }

    static final class DecodedChunk {
        private final int chunkIndex;
        private final int itemCount;
        private final List<byte[]> items;
        private final long byteLength;

        private DecodedChunk(int chunkIndex, int itemCount, List<byte[]> items, long byteLength) {
            this.chunkIndex = chunkIndex;
            this.itemCount = itemCount;
            this.items = items;
            this.byteLength = byteLength;
        }

        int getChunkIndex() {
            return chunkIndex;
        }

        int getItemCount() {
            return itemCount;
        }

        List<byte[]> getItems() {
            return items;
        }

        long getByteLength() {
            return byteLength;
        }
    }
}
