package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * FUSE_PIR native utility tests.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class FusePirStdKwPirNativeUtilsTest {

    @Test
    public void testKeyGenAndNativeShapes() {
        byte[] encryptionParams = FusePirStdKwPirNativeUtils.generateEncryptionParams(
            8192, 65537L, new int[]{30, 30, 30, 30}
        );
        List<byte[]> keys = FusePirStdKwPirNativeUtils.keyGen(encryptionParams);
        Assert.assertEquals(2, keys.size());
        byte[] columnQuery = FusePirStdKwPirNativeUtils.generateColumnQuery(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
            keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 1, 4
        );
        Assert.assertTrue(columnQuery.length > 0);
        List<byte[]> rowBits = FusePirStdKwPirNativeUtils.generateEncryptedRowBits(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
            keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 2, 4
        );
        Assert.assertEquals(2, rowBits.size());
        long[][][] matrices = new long[1][4][4];
        matrices[0][2][1] = 7L;
        List<byte[]> encodedMatrices = FusePirStdKwPirNativeUtils.preprocessDatabase(encryptionParams, matrices, 4, 1);
        Assert.assertEquals(4, encodedMatrices.size());
    }

    @Test
    public void testNativeColumnAndBlindRotate() {
        testNativeColumnAndBlindRotate(2);
    }

    @Test
    public void testNativeColumnWithoutRotate() {
        testNativeColumnAndBlindRotate(0);
    }

    @Test
    public void testNativeBlindRotateRowOne() {
        testNativeColumnAndBlindRotate(1);
    }

    @Test
    public void testColumnAndBlindRotateWithConvertedCompressedRowBits() {
        byte[] encryptionParams = FusePirStdKwPirNativeUtils.generateEncryptionParams(
            8192, 65537L, new int[]{30, 30, 30, 30}
        );
        List<byte[]> keys = FusePirStdKwPirNativeUtils.keyGen(encryptionParams);
        int targetRow = 2;
        int rowNum = 4;
        long[] lweSecretKey = new long[64];
        for (int i = 0; i < lweSecretKey.length; i++) {
            lweSecretKey[i] = (i & 1);
        }
        List<byte[]> lweToRgswKey = FusePirStdKwPirNativeUtils.generateLweToRgswKey(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX), lweSecretKey
        );

        List<byte[]> columnQueries = new ArrayList<>(3);
        List<byte[]> rowBits = new ArrayList<>(6);
        columnQueries.add(FusePirStdKwPirNativeUtils.generateColumnQuery(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
            keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 1, 4
        ));
        rowBits.addAll(convertCompressedRowBits(encryptionParams, keys, lweToRgswKey, lweSecretKey, targetRow, rowNum));
        for (int i = 0; i < 2; i++) {
            columnQueries.add(FusePirStdKwPirNativeUtils.generateColumnQuery(
                encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
                keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 0, 4
            ));
            rowBits.addAll(convertCompressedRowBits(encryptionParams, keys, lweToRgswKey, lweSecretKey, 0, rowNum));
        }
        long[][][] matrices = new long[1][4][4];
        matrices[0][targetRow][1] = 7L;
        List<byte[]> encodedMatrices = FusePirStdKwPirNativeUtils.preprocessDatabase(encryptionParams, matrices, 4, 1);
        List<byte[]> response = FusePirStdKwPirNativeUtils.generateReply(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
            columnQueries, rowBits, encodedMatrices, 1, rowNum, 4, 1
        );
        long[][] decoded = FusePirStdKwPirNativeUtils.decryptReply(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), response
        );
        Assert.assertEquals(7L, decoded[0][0]);
    }

    @Test
    public void testNoPlainRowLeak() {
        byte[] encryptionParams = FusePirStdKwPirNativeUtils.generateEncryptionParams(
            8192, 65537L, new int[]{30, 30, 30, 30}
        );
        List<byte[]> keys = FusePirStdKwPirNativeUtils.keyGen(encryptionParams);
        List<byte[]> rowBits = FusePirStdKwPirNativeUtils.generateEncryptedRowBits(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
            keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 2, 4
        );
        Assert.assertEquals(2, rowBits.size());
        for (byte[] rowBit : rowBits) {
            Assert.assertNotEquals(Integer.BYTES, rowBit.length);
        }
    }

    @Test
    public void testQuerySizeBreakdown() {
        FusePirStdKwPirParams params = new FusePirStdKwPirParams(
            8192, 65537L, new int[]{30, 30, 30, 30}, 3, 40, 8, 128, true
        );
        params.initPirParams(1 << 5);
        byte[] encryptionParams = params.encryptionParams;
        List<byte[]> keys = FusePirStdKwPirNativeUtils.keyGen(encryptionParams);
        Assert.assertEquals(2, keys.size());
        int rowBitNum = ceilLog2(params.getMatrixRowNum());
        List<byte[]> columnQueries = new ArrayList<>(params.getBffHashNum());
        List<byte[]> rowBits = new ArrayList<>(params.getBffHashNum() * rowBitNum);
        List<byte[]> compressedRowBits = new ArrayList<>(params.getBffHashNum());
        long[] lweSecretKey = new long[630];
        for (int i = 0; i < lweSecretKey.length; i++) {
            lweSecretKey[i] = (i & 1);
        }
        for (int i = 0; i < params.getBffHashNum(); i++) {
            columnQueries.add(FusePirStdKwPirNativeUtils.generateColumnQuery(
                encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
                keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 0, params.getMatrixColNum()
            ));
            rowBits.addAll(FusePirStdKwPirNativeUtils.generateEncryptedRowBits(
                encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
                keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 0, params.getMatrixRowNum()
            ));
            compressedRowBits.add(FusePirLwePrgUtils.generateCompressedRowBitQuery(
                0, params.getMatrixRowNum(), lweSecretKey, 1L << 32, 1L << 31
            ).toByteArray());
        }
        long columnQueryBytes = byteSize(columnQueries);
        long rowRgswBitsBytes = byteSize(rowBits);
        long compressedRowBitBytes = byteSize(compressedRowBits);
        long publicKeyBytes = keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX).length;
        System.out.printf(
            "FUSE_PIR query size breakdown: publicKeyBytes=%d, evalKeyBytes=%d, columnQueryBytes=%d, "
                + "rowRgswBitsBytes=%d, compressedRowBitBytes=%d, originalQueryBytes=%d, compressedQueryBytes=%d, "
                + "rowNum=%d, rowBitNum=%d, bffHashNum=%d%n",
            publicKeyBytes, 0, columnQueryBytes, rowRgswBitsBytes, compressedRowBitBytes,
            columnQueryBytes + rowRgswBitsBytes, columnQueryBytes + compressedRowBitBytes, params.getMatrixRowNum(),
            rowBitNum, params.getBffHashNum()
        );
        Assert.assertEquals(params.getBffHashNum(), columnQueries.size());
        Assert.assertEquals(params.getBffHashNum() * rowBitNum, rowBits.size());
        Assert.assertEquals(params.getBffHashNum(), compressedRowBits.size());
        Assert.assertTrue(compressedRowBitBytes < rowRgswBitsBytes);
    }

    private void testNativeColumnAndBlindRotate(int targetRow) {
        byte[] encryptionParams = FusePirStdKwPirNativeUtils.generateEncryptionParams(
            8192, 65537L, new int[]{30, 30, 30, 30}
        );
        List<byte[]> keys = FusePirStdKwPirNativeUtils.keyGen(encryptionParams);
        List<byte[]> columnQueries = new ArrayList<>(3);
        List<byte[]> rowBits = new ArrayList<>(6);
        columnQueries.add(FusePirStdKwPirNativeUtils.generateColumnQuery(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
            keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 1, 4
        ));
        rowBits.addAll(FusePirStdKwPirNativeUtils.generateEncryptedRowBits(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
            keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), targetRow, 4
        ));
        for (int i = 0; i < 2; i++) {
            columnQueries.add(FusePirStdKwPirNativeUtils.generateColumnQuery(
                encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
                keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 0, 4
            ));
            rowBits.addAll(FusePirStdKwPirNativeUtils.generateEncryptedRowBits(
                encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
                keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 0, 4
            ));
        }
        long[][][] matrices = new long[1][4][4];
        matrices[0][targetRow][1] = 7L;
        List<byte[]> encodedMatrices = FusePirStdKwPirNativeUtils.preprocessDatabase(encryptionParams, matrices, 4, 1);
        List<byte[]> response = FusePirStdKwPirNativeUtils.generateReply(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
            columnQueries, rowBits, encodedMatrices, 1, 4, 4, 1
        );
        long[][] decoded = FusePirStdKwPirNativeUtils.decryptReply(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), response
        );
        Assert.assertEquals(7L, decoded[0][0]);
        Assert.assertEquals(1, response.size());
    }

    private static long byteSize(List<byte[]> payload) {
        return payload.stream().mapToLong(bytes -> bytes.length).sum();
    }

    private static int ceilLog2(int n) {
        int log = 0;
        int pow = 1;
        while (pow < n) {
            pow <<= 1;
            log++;
        }
        return log;
    }

    private static List<byte[]> convertCompressedRowBits(byte[] encryptionParams, List<byte[]> keys,
                                                         List<byte[]> lweToRgswKey, long[] lweSecretKey,
                                                         int rowIndex, int rowNum) {
        FusePirCompressedLweBitQuery compressedQuery = FusePirLwePrgUtils.generateCompressedRowBitQuery(
            rowIndex, rowNum, lweSecretKey, 1L << 32, 1L
        );
        List<FusePirLweCiphertext> recovered = FusePirLwePrgUtils.recoverLweBitCiphertexts(compressedQuery);
        long[][] aArray = new long[recovered.size()][];
        long[] bArray = new long[recovered.size()];
        for (int i = 0; i < recovered.size(); i++) {
            aArray[i] = recovered.get(i).getA();
            bArray[i] = recovered.get(i).getB();
        }
        return FusePirStdKwPirNativeUtils.convertCompressedRowBitsToRgsw(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX), lweToRgswKey, aArray, bArray
        );
    }

    @Test
    public void testNativePackedResponse() {
        byte[] encryptionParams = FusePirStdKwPirNativeUtils.generateEncryptionParams(
            8192, 65537L, new int[]{30, 30, 30, 30}
        );
        List<byte[]> keys = FusePirStdKwPirNativeUtils.keyGen(encryptionParams);
        List<byte[]> columnQueries = new ArrayList<>(3);
        List<byte[]> rowBits = new ArrayList<>(6);
        columnQueries.add(FusePirStdKwPirNativeUtils.generateColumnQuery(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
            keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 1, 4
        ));
        rowBits.addAll(FusePirStdKwPirNativeUtils.generateEncryptedRowBits(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
            keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 2, 4
        ));
        for (int i = 0; i < 2; i++) {
            columnQueries.add(FusePirStdKwPirNativeUtils.generateColumnQuery(
                encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
                keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 0, 4
            ));
            rowBits.addAll(FusePirStdKwPirNativeUtils.generateEncryptedRowBits(
                encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
                keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 0, 4
            ));
        }
        long[] expected = new long[]{11L, 22L, 33L, 44L, 55L};
        int blocksPerPackedMatrix = 3;
        long[][][] matrices = new long[2][4][4 * blocksPerPackedMatrix];
        for (int blockIndex = 0; blockIndex < expected.length; blockIndex++) {
            int groupIndex = blockIndex / blocksPerPackedMatrix;
            int blockOffset = blockIndex % blocksPerPackedMatrix;
            matrices[groupIndex][2][1 * blocksPerPackedMatrix + blockOffset] = expected[blockIndex];
        }
        List<byte[]> encodedMatrices = FusePirStdKwPirNativeUtils.preprocessDatabase(
            encryptionParams, matrices, 4, blocksPerPackedMatrix
        );
        List<byte[]> response = FusePirStdKwPirNativeUtils.generateReply(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
            columnQueries, rowBits, encodedMatrices, expected.length, 4, 4, blocksPerPackedMatrix
        );
        Assert.assertEquals(1, response.size());
        long[][] decoded = FusePirStdKwPirNativeUtils.decryptReply(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), response
        );
        for (int blockIndex = 0; blockIndex < expected.length; blockIndex++) {
            Assert.assertEquals(expected[blockIndex], decoded[0][blockIndex]);
        }
    }

    @Test
    public void testPackedAndUnpackedConsistency() {
        byte[] encryptionParams = FusePirStdKwPirNativeUtils.generateEncryptionParams(
            8192, 65537L, new int[]{30, 30, 30, 30}
        );
        List<byte[]> keys = FusePirStdKwPirNativeUtils.keyGen(encryptionParams);
        List<byte[]> columnQueries = new ArrayList<>(3);
        List<byte[]> rowBits = new ArrayList<>(6);
        for (int hashIndex = 0; hashIndex < 3; hashIndex++) {
            int targetCol = hashIndex == 0 ? 1 : 0;
            int targetRow = hashIndex == 0 ? 2 : 0;
            columnQueries.add(FusePirStdKwPirNativeUtils.generateColumnQuery(
                encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
                keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), targetCol, 4
            ));
            rowBits.addAll(FusePirStdKwPirNativeUtils.generateEncryptedRowBits(
                encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
                keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), targetRow, 4
            ));
        }
        long[] expected = new long[]{17L, 29L, 43L};
        long[][][] unpackedMatrices = new long[expected.length][4][4];
        long[][][] packedMatrices = new long[1][4][4 * expected.length];
        for (int block = 0; block < expected.length; block++) {
            unpackedMatrices[block][2][1] = expected[block];
            packedMatrices[0][2][1 * expected.length + block] = expected[block];
        }
        List<byte[]> unpackedResponse = FusePirStdKwPirNativeUtils.generateReply(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX), columnQueries, rowBits,
            FusePirStdKwPirNativeUtils.preprocessDatabase(encryptionParams, unpackedMatrices, 4, 1),
            expected.length, 4, 4, 1
        );
        List<byte[]> packedResponse = FusePirStdKwPirNativeUtils.generateReply(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX), columnQueries, rowBits,
            FusePirStdKwPirNativeUtils.preprocessDatabase(encryptionParams, packedMatrices, 4, expected.length),
            expected.length, 4, 4, expected.length
        );
        long[][] unpacked = FusePirStdKwPirNativeUtils.decryptReply(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), unpackedResponse
        );
        long[][] packed = FusePirStdKwPirNativeUtils.decryptReply(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), packedResponse
        );
        for (int block = 0; block < expected.length; block++) {
            Assert.assertEquals(expected[block], unpacked[0][block]);
            Assert.assertEquals(unpacked[0][block], packed[0][block]);
        }
    }

    @Test
    public void testNativeMultiCiphertextPackedResponse() {
        byte[] encryptionParams = FusePirStdKwPirNativeUtils.generateEncryptionParams(
            8192, 65537L, new int[]{30, 30, 30, 30}
        );
        List<byte[]> keys = FusePirStdKwPirNativeUtils.keyGen(encryptionParams);
        int rowNum = 1;
        int colNum = 1;
        int blocksPerPackedMatrix = 4096;
        int payloadBlockNum = 8193;
        List<byte[]> columnQueries = new ArrayList<>(3);
        List<byte[]> rowBits = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            columnQueries.add(FusePirStdKwPirNativeUtils.generateColumnQuery(
                encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
                keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), 0, colNum
            ));
        }
        int packedMatrixGroupNum = (payloadBlockNum + blocksPerPackedMatrix - 1) / blocksPerPackedMatrix;
        long[][][] matrices = new long[packedMatrixGroupNum][rowNum][colNum * blocksPerPackedMatrix];
        int[] blockIndexes = new int[]{0, 4095, 4096, 8191, 8192};
        long[] expectedValues = new long[]{33L, 66L, 99L, 132L, 165L};
        for (int i = 0; i < blockIndexes.length; i++) {
            int blockIndex = blockIndexes[i];
            int groupIndex = blockIndex / blocksPerPackedMatrix;
            int blockOffset = blockIndex % blocksPerPackedMatrix;
            matrices[groupIndex][0][blockOffset] = expectedValues[i] / 3;
        }
        List<byte[]> encodedMatrices = FusePirStdKwPirNativeUtils.preprocessDatabase(
            encryptionParams, matrices, colNum, blocksPerPackedMatrix
        );
        List<byte[]> response = FusePirStdKwPirNativeUtils.generateReply(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.PUBLIC_KEY_INDEX),
            columnQueries, rowBits, encodedMatrices, payloadBlockNum, rowNum, colNum, blocksPerPackedMatrix
        );
        Assert.assertEquals(2, response.size());
        long[][] decoded = FusePirStdKwPirNativeUtils.decryptReply(
            encryptionParams, keys.get(FusePirStdKwPirNativeUtils.SECRET_KEY_INDEX), response
        );
        Assert.assertEquals(33L, decoded[0][0]);
        Assert.assertEquals(66L, decoded[0][4095]);
        Assert.assertEquals(99L, decoded[0][4096]);
        Assert.assertEquals(132L, decoded[0][8191]);
        Assert.assertEquals(165L, decoded[1][0]);
    }
}
