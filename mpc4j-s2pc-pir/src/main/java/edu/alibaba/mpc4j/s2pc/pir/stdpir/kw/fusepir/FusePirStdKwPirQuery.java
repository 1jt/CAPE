package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;

import java.util.List;

/**
 * FUSE_PIR query for one keyword.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
class FusePirStdKwPirQuery {
    /**
     * column queries
     */
    private final List<byte[]> columnQueries;
    /**
     * encrypted row bits
     */
    private final List<byte[]> encryptedRowBits;

    FusePirStdKwPirQuery(List<byte[]> columnQueries, List<byte[]> encryptedRowBits) {
        this.columnQueries = columnQueries.stream().map(BytesUtils::clone).toList();
        this.encryptedRowBits = encryptedRowBits.stream().map(BytesUtils::clone).toList();
    }

    List<byte[]> getColumnQueries() {
        return columnQueries.stream().map(BytesUtils::clone).toList();
    }

    List<byte[]> getEncryptedRowBits() {
        return encryptedRowBits.stream().map(BytesUtils::clone).toList();
    }
}
