package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirParams;
import org.junit.Assert;
import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CAPE_C server reply tests.
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
public class CapeCPirServerReplyTest {
    @Test
    public void testBloomExpectedInsertionsUsesMaxValueKeywordSetSize() throws Exception {
        Map<ByteBuffer, List<byte[]>> keywordMap = CapeCPirNativeUtilsTest.createKeywordValueMap();
        CapeCPirNativeUtilsTest.TestContext context = CapeCPirNativeUtilsTest.createContext(keywordMap, List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        ));
        int maxValueKeywordSetSize = CapeCPirUtils.buildForwardIndex(keywordMap).values()
            .stream()
            .mapToInt(List::size)
            .max()
            .orElse(1);
        Assert.assertEquals(128, keywordMap.size());
        Assert.assertEquals(3, maxValueKeywordSetSize);
        Assert.assertNotEquals(keywordMap.size(), maxValueKeywordSetSize);
        Assert.assertEquals(maxValueKeywordSetSize, context.server().getMaxValueKeywordSetSize());
        Assert.assertEquals(maxValueKeywordSetSize, context.server().getCapeCParams().getBloomExpectedInsertions());

        CapePirParams capeParams = new CapePirParams(context.server().getCapeCParams());
        capeParams.initPirParams(
            keywordMap.size(), 2, 3, context.server().getCapeCParams().getBoolKeywordNum(), maxValueKeywordSetSize
        );
        Assert.assertEquals(capeParams.getBloomExpectedInsertions(),
            context.server().getCapeCParams().getBloomExpectedInsertions());
        Assert.assertEquals(capeParams.getBloomBitLength(), context.server().getCapeCParams().getBloomBitLength());
    }

    @Test
    public void testAnchorValueCandidateRetrieval() throws Exception {
        CapeCPirNativeUtilsTest.TestContext context = CapeCPirNativeUtilsTest.createContext();
        List<byte[]> encryptedValuePayloads = context.server().generateCompressedAnchorValueCandidateReply(
            context.query()
        );
        Assert.assertEquals(context.server().getExpectedValueCiphertextCount(), encryptedValuePayloads.size());
        long[] coeffs = CapeCPirNativeUtils.decryptCoeffReply(
            context.server().getCapeCParams().encryptionParams, context.client().getSecretKey(),
            encryptedValuePayloads.get(0)
        );
        List<byte[]> values = decodeValueOnlyPayload(
            CapeCPirUtils.keywordToByteArray(context.queryKeywords().get(0)), coeffs, context.server().getCapeCParams()
        );
        Set<String> actual = new HashSet<>();
        values.forEach(value -> actual.add(java.util.Arrays.toString(value)));
        Assert.assertTrue(actual.contains(java.util.Arrays.toString(new byte[]{0x01, 0x01})));
        Assert.assertTrue(actual.contains(java.util.Arrays.toString(new byte[]{0x01, 0x02})));
        Assert.assertTrue(actual.contains(java.util.Arrays.toString(new byte[]{0x01, 0x03})));
    }

    @Test
    public void testPhase5PackedResultReply() throws Exception {
        CapeCPirNativeUtilsTest.TestContext context = CapeCPirNativeUtilsTest.createSmallContext(List.of(
            java.nio.ByteBuffer.wrap("k1".getBytes()),
            java.nio.ByteBuffer.wrap("k2".getBytes()),
            java.nio.ByteBuffer.wrap("k3".getBytes())
        ));
        CapeCPirResponse response = context.server().generatePhase5PackedResultReply(context.query());
        Assert.assertEquals(
            context.server().getCapeCParams().getExpectedPackedResultCiphertextCount(),
            response.getPackedResultCiphertexts().size()
        );
        Assert.assertEquals(response.getPackedResultCiphertexts().size(), response.getServerPayload().size());
        for (int i = 0; i < response.getPackedResultCiphertexts().size(); i++) {
            Assert.assertArrayEquals(response.getPackedResultCiphertexts().get(i), response.getServerPayload().get(i));
        }
        List<byte[]> results = context.client().decodePackedResultResponseForTest(context.clientQuery(), response);
        Assert.assertEquals(1, results.size());
        Assert.assertArrayEquals(new byte[]{0x01, 0x01}, results.get(0));
    }

    @Test
    public void testPhase5PackedResultReplyTwoKeywordConjunction() throws Exception {
        CapeCPirNativeUtilsTest.TestContext context = CapeCPirNativeUtilsTest.createSmallContext(List.of(
            java.nio.ByteBuffer.wrap("k1".getBytes()),
            java.nio.ByteBuffer.wrap("k3".getBytes()),
            java.nio.ByteBuffer.wrap("k3".getBytes())
        ));
        CapeCPirResponse response = context.server().generatePhase5PackedResultReply(context.query());
        List<byte[]> results = context.client().decodePackedResultResponseForTest(context.clientQuery(), response);
        Set<String> actual = new HashSet<>();
        results.forEach(value -> actual.add(java.util.Arrays.toString(value)));
        Assert.assertEquals(2, actual.size());
        Assert.assertTrue(actual.contains(java.util.Arrays.toString(new byte[]{0x01, 0x01})));
        Assert.assertTrue(actual.contains(java.util.Arrays.toString(new byte[]{0x01, 0x02})));
    }

    @SuppressWarnings("unchecked")
    private static List<byte[]> decodeValueOnlyPayload(byte[] anchorKeywordBytes, long[] coeffs,
                                                       CapeCPirParams params) {
        try {
            Class<?> utilsClass = Class.forName("edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirUtils");
            Method method = utilsClass.getDeclaredMethod(
                "decodeValueOnlyPayload", byte[].class, long[].class,
                Class.forName("edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirParams")
            );
            method.setAccessible(true);
            return (List<byte[]>) method.invoke(null, anchorKeywordBytes, coeffs, params);
        } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException e) {
            throw new IllegalStateException("Cannot access CAPE value-only decoder", e);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            throw new IllegalStateException("CAPE value-only decoder failed", cause);
        }
    }
}
