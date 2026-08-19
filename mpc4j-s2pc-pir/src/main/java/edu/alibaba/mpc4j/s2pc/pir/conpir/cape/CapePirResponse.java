package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;

import java.util.List;

/**
 * CAPE PIR response.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
class CapePirResponse {
    /**
     * encrypted candidate value payloads.
     */
    private final List<byte[]> encryptedValuePayloads;
    /**
     * encrypted Bloom inner products.
     */
    private final List<byte[]> encryptedBloomInnerProducts;
    /**
     * packed result ciphertexts. Formal P11 response uses only this field.
     */
    private final List<byte[]> packedResultCiphertexts;

    CapePirResponse(List<byte[]> encryptedValuePayloads, List<byte[]> encryptedBloomInnerProducts) {
        this.encryptedValuePayloads = encryptedValuePayloads.stream().map(BytesUtils::clone).toList();
        this.encryptedBloomInnerProducts = encryptedBloomInnerProducts.stream().map(BytesUtils::clone).toList();
        this.packedResultCiphertexts = List.of();
    }

    private CapePirResponse(List<byte[]> packedResultCiphertexts) {
        this.encryptedValuePayloads = List.of();
        this.encryptedBloomInnerProducts = List.of();
        this.packedResultCiphertexts = packedResultCiphertexts.stream().map(BytesUtils::clone).toList();
    }

    static CapePirResponse createPackedResultResponse(List<byte[]> packedResultCiphertexts) {
        return new CapePirResponse(packedResultCiphertexts);
    }

    List<byte[]> getEncryptedValuePayloads() {
        return encryptedValuePayloads.stream().map(BytesUtils::clone).toList();
    }

    List<byte[]> getEncryptedBloomInnerProducts() {
        return encryptedBloomInnerProducts.stream().map(BytesUtils::clone).toList();
    }

    List<byte[]> getPackedResultCiphertexts() {
        return packedResultCiphertexts.stream().map(BytesUtils::clone).toList();
    }

    List<byte[]> getServerPayload() {
        return packedResultCiphertexts.isEmpty()
            ? java.util.stream.Stream.concat(encryptedValuePayloads.stream(), encryptedBloomInnerProducts.stream())
                .map(BytesUtils::clone)
                .toList()
            : getPackedResultCiphertexts();
    }
}
