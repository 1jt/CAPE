package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.rpc.impl.memory.MemoryRpcManager;
import org.junit.Assert;
import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CAPE_C native utils tests.
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
public class CapeCPirNativeUtilsTest {
    private static final CapeCPirParams TEST_PARAMS = new CapeCPirParams(
        8192, 65537L, new int[]{60, 60, 60, 60}, 3, 40, 2, 3, true,
        Math.pow(2.0, -10), new byte[edu.alibaba.mpc4j.common.tool.CommonConstants.BLOCK_BYTE_LENGTH],
        edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirQueryMethod.AND, 3
    );

    @Test
    public void testCandidateReplyMatchesCapeColumnPath() throws Exception {
        TestContext context = createContext();
        CapeCPirQuery query = context.query;
        CapeCPirServer.RecoveredAnchorQuery recovered = context.server.recoverCompressedAnchorQuery(query);
        List<byte[]> capecValuePayloads = context.server.generateCompressedAnchorValueCandidateReply(query);

        int[] positions = CapeCPirUtils.getHashPositionsFromKeywordBytes(
            CapeCPirUtils.keywordToByteArray(context.queryKeywords.get(0)), context.keywordMap.size(),
            context.server.getBffSeed(), context.server.getCapeCParams()
        );
        List<byte[]> columnQueries = new ArrayList<>(context.server.getCapeCParams().getBffHashNum());
        for (int position : positions) {
            int col = position / context.server.getCapeCParams().getMatrixRowNum();
            columnQueries.add(invokeCapeNative(
                "generatePackedColumnQuery",
                new Class<?>[]{byte[].class, byte[].class, byte[].class, int.class, int.class, int.class},
                context.server.getCapeCParams().encryptionParams, context.client.getPublicKey(),
                context.client.getSecretKey(), col, context.server.getCapeCParams().getMatrixColNum(),
                context.server.getCapeCParams().getValueBlocksPerPackedMatrix()
            ));
        }
        List<byte[]> capeValuePayloads = invokeCapeNative(
            "generateFusePirCandidateReply",
            new Class<?>[]{byte[].class, byte[].class, List.class, List.class, List.class,
                int.class, int.class, int.class, int.class},
            context.server.getCapeCParams().encryptionParams, context.client.getPublicKey(), columnQueries,
            flatten(recovered.getRowRgswBits()), context.server.getEncodedValueOnlyMatricesForTest(),
            context.server.getCapeCParams().getValuePayloadCoeffNum(), context.server.getCapeCParams().getMatrixRowNum(),
            context.server.getCapeCParams().getMatrixColNum(), context.server.getCapeCParams().getValueBlocksPerPackedMatrix()
        );
        Assert.assertEquals(capeValuePayloads.size(), capecValuePayloads.size());
        long[] capeCoeffs = CapeCPirNativeUtils.decryptCoeffReply(
            context.server.getCapeCParams().encryptionParams, context.client.getSecretKey(), capeValuePayloads.get(0)
        );
        long[] capecCoeffs = CapeCPirNativeUtils.decryptCoeffReply(
            context.server.getCapeCParams().encryptionParams, context.client.getSecretKey(), capecValuePayloads.get(0)
        );
        int valueOnlyPayloadBlockNum = context.server.getCapeCParams().getValuePayloadCoeffNum();
        Assert.assertArrayEquals(
            Arrays.copyOf(capeCoeffs, valueOnlyPayloadBlockNum),
            Arrays.copyOf(capecCoeffs, valueOnlyPayloadBlockNum)
        );
    }

    @Test
    public void testPackedBloomScoreMatchesCapeColumnPath() throws Exception {
        TestContext context = createContext();
        CapeCPirQuery query = context.query;
        CapeCPirServer.RecoveredAnchorQuery recovered = context.server.recoverCompressedAnchorQuery(query);
        List<byte[]> capecScores = context.server.generateCompressedAnchorPackedBloomScores(query, recovered);

        int[] positions = CapeCPirUtils.getHashPositionsFromKeywordBytes(
            CapeCPirUtils.keywordToByteArray(context.queryKeywords.get(0)), context.keywordMap.size(),
            context.server.getBffSeed(), context.server.getCapeCParams()
        );
        List<byte[]> columnQueries = new ArrayList<>(context.server.getCapeCParams().getBffHashNum());
        for (int position : positions) {
            int col = position / context.server.getCapeCParams().getMatrixRowNum();
            columnQueries.add(invokeCapeNative(
                "generatePackedColumnQuery",
                new Class<?>[]{byte[].class, byte[].class, byte[].class, int.class, int.class, int.class},
                context.server.getCapeCParams().encryptionParams, context.client.getPublicKey(),
                context.client.getSecretKey(), col, context.server.getCapeCParams().getMatrixColNum(),
                context.server.getCapeCParams().getValueBlocksPerPackedMatrix()
            ));
        }
        List<byte[]> capeScores = invokeCapeNative(
            "generateFusedPackedCoeffCtCtBloomScoresPackedBloom",
            new Class<?>[]{byte[].class, byte[].class, byte[].class, byte[].class, List.class, List.class,
                List.class, List.class, int.class, int.class, int.class, int.class, int.class, int.class,
                int.class, int.class},
            context.server.getCapeCParams().encryptionParams, context.client.getPublicKey(), context.client.getRelinKeys(),
            context.client.getGaloisKeys(), columnQueries, flatten(recovered.getRowRgswBits()),
            context.server.getEncodedBloomOnlyMatricesForTest(), query.getEncryptedPackedBloomQuery(),
            context.server.getCapeCParams().getBloomPackedPayloadBlockNum(), context.server.getCapeCParams().getMatrixRowNum(),
            context.server.getCapeCParams().getMatrixColNum(), CapeCPirUtils.bloomPackedMatrixColumnCapacity(context.server.getCapeCParams()),
            context.server.getCapeCParams().getValueBlocksPerPackedMatrix(),
            CapeCPirUtils.bloomPackedCoefficientStride(context.server.getCapeCParams()),
            context.server.getCapeCParams().getMaxValueNumPerKeyword(), context.server.getCapeCParams().getBloomBitLength()
        );
        Assert.assertEquals(capeScores.size(), capecScores.size());
        long[] capeScoreCoeffs = CapeCPirNativeUtils.decryptCoeffReply(
            context.server.getCapeCParams().encryptionParams, context.client.getSecretKey(), capeScores.get(0)
        );
        long[] capecScoreCoeffs = CapeCPirNativeUtils.decryptCoeffReply(
            context.server.getCapeCParams().encryptionParams, context.client.getSecretKey(), capecScores.get(0)
        );
        Assert.assertArrayEquals(
            Arrays.copyOf(capeScoreCoeffs, context.server.getCapeCParams().getMaxValueNumPerKeyword()),
            Arrays.copyOf(capecScoreCoeffs, context.server.getCapeCParams().getMaxValueNumPerKeyword())
        );
    }

    static TestContext createContext() throws Exception {
        return createContext(List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        ));
    }

    static TestContext createContext(List<ByteBuffer> queryKeywords) throws Exception {
        return createContext(createKeywordValueMap(), queryKeywords);
    }

    static TestContext createSmallContext(List<ByteBuffer> queryKeywords) throws Exception {
        return createContext(createSmallKeywordValueMap(), queryKeywords);
    }

    static TestContext createContext(Map<ByteBuffer, List<byte[]>> keywordMap,
                                     List<ByteBuffer> queryKeywords) throws Exception {
        MemoryRpcManager rpcManager = new MemoryRpcManager(2);
        CapeCPirConfig clientConfig = new CapeCPirConfig.Builder().setParams(new CapeCPirParams(TEST_PARAMS)).build();
        CapeCPirConfig serverConfig = new CapeCPirConfig.Builder().setParams(new CapeCPirParams(TEST_PARAMS)).build();
        CapeCPirClient<ByteBuffer> client = new CapeCPirClient<>(
            rpcManager.getRpc(0), rpcManager.getRpc(1).ownParty(), clientConfig
        );
        CapeCPirServer<ByteBuffer> server = new CapeCPirServer<>(
            rpcManager.getRpc(1), rpcManager.getRpc(0).ownParty(), serverConfig
        );
        client.init(keywordMap.size(), 2, 3, 1);
        server.init(keywordMap, 2, 3, 1);
        server.setSetupForTest(client.getPublicKey(), client.getLweToRgswKey());
        server.setBfvEvaluationKeysForTest(client.getRelinKeys(), client.getGaloisKeys());
        client.setBffSeedAndBloomParamsForTest(server.getBffSeed(), server.getSerializedBloomParamsForTest());
        CapeCPirQuery clientQuery = client.generateCapeCQuery(queryKeywords);
        CapeCPirQuery serverQuery = server.parseQueryPayload(clientQuery.getServerPayload());
        return new TestContext(client, server, keywordMap, queryKeywords, serverQuery, clientQuery);
    }

    static Map<ByteBuffer, List<byte[]>> createKeywordValueMap() {
        Map<ByteBuffer, List<byte[]>> keywordMap = createSmallKeywordValueMap();
        for (int i = 4; i <= 128; i++) {
            keywordMap.put(ByteBuffer.wrap(("k" + i).getBytes()), List.of(new byte[]{0x02, (byte) i}));
        }
        return keywordMap;
    }

    static Map<ByteBuffer, List<byte[]>> createSmallKeywordValueMap() {
        Map<ByteBuffer, List<byte[]>> keywordMap = new LinkedHashMap<>();
        keywordMap.put(ByteBuffer.wrap("k1".getBytes()), List.of(
            new byte[]{0x01, 0x01}, new byte[]{0x01, 0x02}, new byte[]{0x01, 0x03}
        ));
        keywordMap.put(ByteBuffer.wrap("k2".getBytes()), List.of(new byte[]{0x01, 0x01}));
        keywordMap.put(ByteBuffer.wrap("k3".getBytes()), List.of(new byte[]{0x01, 0x01}, new byte[]{0x01, 0x02}));
        return keywordMap;
    }

    static Map<ByteBuffer, List<byte[]>> createNoIntersectionKeywordValueMap() {
        Map<ByteBuffer, List<byte[]>> keywordMap = new LinkedHashMap<>();
        keywordMap.put(ByteBuffer.wrap("k1".getBytes()), List.of(
            new byte[]{0x01, 0x01}, new byte[]{0x01, 0x02}
        ));
        keywordMap.put(ByteBuffer.wrap("k2".getBytes()), List.of(new byte[]{0x01, 0x03}));
        keywordMap.put(ByteBuffer.wrap("k3".getBytes()), List.of(new byte[]{0x01, 0x03}));
        return keywordMap;
    }

    static List<byte[]> flatten(byte[][][] bits) {
        return Arrays.stream(bits).flatMap(hashBits -> Arrays.stream(hashBits)).toList();
    }

    @SuppressWarnings("unchecked")
    static <T> T invokeCapeNative(String methodName, Class<?>[] parameterTypes, Object... args) {
        try {
            Class<?> nativeClass = Class.forName("edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirNativeUtils");
            Method method = nativeClass.getDeclaredMethod(methodName, parameterTypes);
            method.setAccessible(true);
            return (T) method.invoke(null, args);
        } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException e) {
            throw new IllegalStateException("Cannot access CAPE native helper: " + methodName, e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw new IllegalStateException("CAPE native helper failed: " + methodName, cause);
        }
    }

    record TestContext(CapeCPirClient<ByteBuffer> client, CapeCPirServer<ByteBuffer> server,
                       Map<ByteBuffer, List<byte[]>> keywordMap, List<ByteBuffer> queryKeywords,
                       CapeCPirQuery query, CapeCPirQuery clientQuery) {
    }
}
