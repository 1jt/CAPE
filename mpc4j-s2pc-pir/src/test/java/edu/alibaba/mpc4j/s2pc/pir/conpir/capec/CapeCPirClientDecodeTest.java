package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import org.junit.Assert;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * CAPE_C packed result decode tests.
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
public class CapeCPirClientDecodeTest {
    @Test
    public void testDecodePackedResultFiltersScoresAndAbsentValues() throws Exception {
        CapeCPirNativeUtilsTest.TestContext context = CapeCPirNativeUtilsTest.createSmallContext(List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        ));
        CapeCPirResponse response = context.server().generatePhase5PackedResultReply(context.query());
        List<byte[]> results = context.client().decodePackedResultResponseForTest(context.clientQuery(), response);
        Assert.assertEquals(1, results.size());
        Assert.assertArrayEquals(new byte[]{0x01, 0x01}, results.get(0));
    }

    @Test
    public void testDecodePackedResultTwoHits() throws Exception {
        CapeCPirNativeUtilsTest.TestContext context = CapeCPirNativeUtilsTest.createSmallContext(List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k3".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        ));
        CapeCPirResponse response = context.server().generatePhase5PackedResultReply(context.query());
        List<byte[]> results = context.client().decodePackedResultResponseForTest(context.clientQuery(), response);
        Set<String> actual = results.stream().map(java.util.Arrays::toString).collect(Collectors.toSet());
        Assert.assertEquals(2, actual.size());
        Assert.assertTrue(actual.contains(java.util.Arrays.toString(new byte[]{0x01, 0x01})));
        Assert.assertTrue(actual.contains(java.util.Arrays.toString(new byte[]{0x01, 0x02})));
        Assert.assertFalse(actual.contains(java.util.Arrays.toString(new byte[]{0x01, 0x03})));
    }

    @Test
    public void testDecodePackedResultRejectsWrongAnchorFingerprint() throws Exception {
        CapeCPirNativeUtilsTest.TestContext context = CapeCPirNativeUtilsTest.createSmallContext(List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        ));
        CapeCPirResponse response = context.server().generatePhase5PackedResultReply(context.query());
        CapeCPirQuery wrongAnchorClientQuery = context.client().generateCapeCQuery(List.of(
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        ));
        List<byte[]> results = context.client().decodePackedResultResponseForTest(wrongAnchorClientQuery, response);
        Assert.assertTrue(results.isEmpty());
    }

    @Test
    public void testMissingAnchorKeywordReturnsEmpty() throws Exception {
        CapeCPirNativeUtilsTest.TestContext context = CapeCPirNativeUtilsTest.createSmallContext(List.of(
            ByteBuffer.wrap("missingKey".getBytes()),
            ByteBuffer.wrap("k2".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        ));
        CapeCPirResponse response = context.server().generatePhase5PackedResultReply(context.query());
        List<byte[]> results = context.client().decodePackedResultResponseForTest(context.clientQuery(), response);
        Assert.assertTrue(results.isEmpty());
    }

    @Test
    public void testMissingNonAnchorKeywordReturnsEmpty() throws Exception {
        CapeCPirNativeUtilsTest.TestContext context = CapeCPirNativeUtilsTest.createSmallContext(List.of(
            ByteBuffer.wrap("k1".getBytes()),
            ByteBuffer.wrap("missingKey".getBytes()),
            ByteBuffer.wrap("k3".getBytes())
        ));
        CapeCPirResponse response = context.server().generatePhase5PackedResultReply(context.query());
        List<byte[]> results = context.client().decodePackedResultResponseForTest(context.clientQuery(), response);
        Assert.assertTrue(results.isEmpty());
    }

    @Test
    public void testNoIntersectionReturnsEmpty() throws Exception {
        CapeCPirNativeUtilsTest.TestContext context = CapeCPirNativeUtilsTest.createContext(
            CapeCPirNativeUtilsTest.createNoIntersectionKeywordValueMap(),
            List.of(
                ByteBuffer.wrap("k1".getBytes()),
                ByteBuffer.wrap("k2".getBytes()),
                ByteBuffer.wrap("k3".getBytes())
            )
        );
        CapeCPirResponse response = context.server().generatePhase5PackedResultReply(context.query());
        List<byte[]> results = context.client().decodePackedResultResponseForTest(context.clientQuery(), response);
        Assert.assertTrue(results.isEmpty());
    }
}
