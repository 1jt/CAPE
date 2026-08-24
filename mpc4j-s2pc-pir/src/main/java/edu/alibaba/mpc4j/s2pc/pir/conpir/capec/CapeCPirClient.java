package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.PtoState;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractTwoPartyPto;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.s2pc.pir.conpir.cape.CapePirQueryMethod;

import java.security.SecureRandom;
import java.nio.ByteBuffer;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static edu.alibaba.mpc4j.s2pc.pir.conpir.capec.CapeCPirPtoDesc.PtoStep;
import static edu.alibaba.mpc4j.s2pc.pir.conpir.capec.CapeCPirPtoDesc.getInstance;

/**
 * CAPE_C PIR client.
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
public class CapeCPirClient<T> extends AbstractTwoPartyPto {
    /**
     * Logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CapeCPirClient.class);
    /**
     * checkpoint log prefix.
     */
    private static final String CHECKPOINT_PREFIX = "[CAPE-C-CHECKPOINT]";
    /**
     * query log prefix.
     */
    private static final String QUERY_PREFIX = "[CAPE-C-QUERY]";
    /**
     * config.
     */
    private final CapeCPirConfig config;
    /**
     * params.
     */
    private final CapeCPirParams params;
    /**
     * keyword num.
     */
    private int keywordNum;
    /**
     * max batch num.
     */
    private int maxBatchNum;
    /**
     * secret key.
     */
    private byte[] secretKey;
    /**
     * public key.
     */
    private byte[] publicKey;
    /**
     * relinearization keys.
     */
    private byte[] relinKeys;
    /**
     * galois keys.
     */
    private byte[] galoisKeys;
    /**
     * binary LWE secret key for compressed anchor bits.
     */
    private long[] lweSecretKey;
    /**
     * setup-time LWE-to-RGSW key.
     */
    private List<byte[]> lweToRgswKey;
    /**
     * BFF seed.
     */
    private byte[] bffSeed;
    /**
     * last generated queries.
     */
    private List<CapeCPirQuery> lastQueries;
    /**
     * last compressed anchor query bytes.
     */
    private long lastCompressedAnchorQueryBytes;
    /**
     * last packed Bloom query bytes.
     */
    private long lastPackedBloomQueryBytes;
    /**
     * last total online query bytes.
     */
    private long lastTotalOnlineQueryBytes;

    public CapeCPirClient(Rpc clientRpc, Party serverParty, CapeCPirConfig config) {
        super(getInstance(), clientRpc, serverParty, config);
        this.config = config;
        params = config.getParams();
    }

    public void init(int keywordNum, int valueByteLength, int maxValueNumPerKeyword, int maxBatchNum)
        throws MpcAbortException {
        MathPreconditions.checkPositive("keyword_num", keywordNum);
        MathPreconditions.checkPositive("value_byte_length", valueByteLength);
        MathPreconditions.checkPositive("max_value_num_per_keyword", maxValueNumPerKeyword);
        MathPreconditions.checkPositive("max_batch_num", maxBatchNum);
        this.keywordNum = keywordNum;
        this.maxBatchNum = maxBatchNum;
        logPhaseInfo(PtoState.INIT_BEGIN);
        stopWatch.start();
        params.initPirParams(keywordNum, valueByteLength, maxValueNumPerKeyword, config.getBoolKeywordNum());
        if (params.encryptionParams == null) {
            params.encryptionParams = CapeCPirNativeUtils.generateEncryptionParams(
                params.getPolyModulusDegree(), params.getPlainModulus(), params.getCoeffModulusBits()
            );
        }
        List<byte[]> keyPair = CapeCPirNativeUtils.keyGen(params.encryptionParams);
        MathPreconditions.checkEqual("keyPair.size", "4", keyPair.size(), 4);
        secretKey = keyPair.get(CapeCPirNativeUtils.SECRET_KEY_INDEX);
        publicKey = keyPair.get(CapeCPirNativeUtils.PUBLIC_KEY_INDEX);
        relinKeys = keyPair.get(CapeCPirNativeUtils.RELIN_KEYS_INDEX);
        galoisKeys = keyPair.get(CapeCPirNativeUtils.GALOIS_KEYS_INDEX);
        lweSecretKey = generateBinaryLweSecretKey();
        lweToRgswKey = CapeCPirNativeUtils.generateLweToRgswKey(params.encryptionParams, publicKey, lweSecretKey);
        LOGGER.info(
            "{} client init setup bytes: publicKeyBytes={}, relinKeysBytes={}, galoisKeysBytes={}, "
                + "lweToRgswKeyBytes={} (offline), lweToRgswKeyItemCount={}",
            CHECKPOINT_PREFIX, publicKey.length, relinKeys.length, galoisKeys.length, byteLength(lweToRgswKey),
            lweToRgswKey.size()
        );
        lastQueries = new ArrayList<>();
        initState();
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        logStepInfo(PtoState.INIT_STEP, 1, 1, initTime);
        logPhaseInfo(PtoState.INIT_END);
    }

    public void sendPublicKeysAndReceiveSeed() throws MpcAbortException {
        checkInitialized();
        if (lweToRgswKey == null || lweToRgswKey.isEmpty()) {
            throw new IllegalStateException("CAPE_C LWE-to-RGSW setup key is not initialized");
        }
        sendOtherPartyPayload(PtoStep.CLIENT_SEND_BFV_KEYS.ordinal(), List.of(publicKey, relinKeys, galoisKeys));
        sendOtherPartyPayload(PtoStep.CLIENT_SEND_ANCHOR_EVAL_KEY_META.ordinal(), List.of(encodeSetupKeyMeta(
            lweToRgswKey.size(), byteLength(lweToRgswKey)
        )));
        for (byte[] keyItem : lweToRgswKey) {
            sendOtherPartyPayload(PtoStep.CLIENT_SEND_ANCHOR_EVAL_KEY_CHUNK.ordinal(), List.of(keyItem));
        }
        // The RPC layer owns an independent copy after send. The client never uses the server-side
        // evaluation key again, so release the serialized source before the server registers its native handle.
        lweToRgswKey = null;
        List<byte[]> seedPayload = receiveOtherPartyPayload(PtoStep.SERVER_SEND_BFF_SEED.ordinal());
        MpcAbortPreconditions.checkArgument(seedPayload.size() == 2);
        bffSeed = BytesUtils.clone(seedPayload.get(0));
        params.applySerializedCapeCBloomParams(seedPayload.get(1));
    }

    public List<byte[]>[] pir(ArrayList<List<T>> queries) throws MpcAbortException {
        checkInitialized();
        MathPreconditions.checkPositiveInRangeClosed("batch_num", queries.size(), maxBatchNum);
        if (!config.getQueryMethod().equals(CapePirQueryMethod.AND)) {
            throw new UnsupportedOperationException("CAPE_C currently only supports AND queries");
        }
        logPhaseInfo(PtoState.PTO_BEGIN);
        lastQueries = new ArrayList<>(queries.size());
        @SuppressWarnings("unchecked")
        List<byte[]>[] entries = new List[queries.size()];
        for (int i = 0; i < queries.size(); i++) {
            stopWatch.start();
            CapeCPirQuery query = generateCapeCQuery(queries.get(i));
            lastQueries.add(query);
            sendOtherPartyPayload(PtoStep.CLIENT_SEND_QUERY.ordinal(), query.getServerPayload());
            stopWatch.stop();
            long queryTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 1, 2, queryTime, "Client generates CAPE_C query");

            stopWatch.start();
            List<byte[]> responsePayload = receiveOtherPartyPayload(PtoStep.SERVER_SEND_RESPONSE.ordinal());
            MpcAbortPreconditions.checkArgument(responsePayload.size() == params.getExpectedPackedResultCiphertextCount());
            entries[i] = decodePackedResultResponse(query, new CapeCPirResponse(responsePayload));
            stopWatch.stop();
            long decodeTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 2, 2, decodeTime, "Client handles CAPE_C reply");
        }
        logPhaseInfo(PtoState.PTO_END);
        return entries;
    }

    CapeCPirQuery generateCapeCQuery(List<T> queryKeywords) {
        CapeCPirQueryParts parts = generateCapeCQueryParts(queryKeywords);
        List<byte[]> encryptedPackedBloomQuery = generatePackedBloomQueryCiphertexts(parts.queryBloomBits);
        return finishCapeCQuery(parts, encryptedPackedBloomQuery);
    }

    CapeCPirQuery generateCapeCQueryForTest(List<T> queryKeywords, List<byte[]> encryptedPackedBloomQuery) {
        return finishCapeCQuery(generateCapeCQueryParts(queryKeywords), encryptedPackedBloomQuery);
    }

    private CapeCPirQueryParts generateCapeCQueryParts(List<T> queryKeywords) {
        checkInitialized();
        if (!config.getQueryMethod().equals(CapePirQueryMethod.AND)) {
            throw new UnsupportedOperationException("CAPE_C currently only supports AND queries");
        }
        MathPreconditions.checkEqual(
            "queryKeywords.size", "bool_keyword_num", queryKeywords.size(), config.getBoolKeywordNum()
        );
        if (bffSeed == null) {
            throw new IllegalStateException("BFF seed is not initialized");
        }
        T anchorKeyword = queryKeywords.get(0);
        List<T> remainingKeywords = queryKeywords.subList(1, queryKeywords.size());
        byte[] anchorKeywordBytes = CapeCPirUtils.keywordToByteArray(anchorKeyword);
        int[] positions = CapeCPirUtils.getHashPositionsFromKeywordBytes(anchorKeywordBytes, keywordNum, bffSeed, params);
        int[] rows = new int[positions.length];
        int[] cols = new int[positions.length];
        for (int i = 0; i < positions.length; i++) {
            rows[i] = positions[i] % params.getMatrixRowNum();
            cols[i] = positions[i] / params.getMatrixRowNum();
        }
        CapeCCompressedAnchorQuery compressedAnchorQuery = CapeCPirUtils.generateCompressedAnchorQuery(
            rows, cols, params.getMatrixRowNum(), params.getMatrixColNum(), params.getBffHashNum(), lweSecretKey
        );
        CapeCPirUtils.QueryBloomFilter queryBloomFilter = CapeCPirUtils.buildQueryBloomFilter(remainingKeywords, params);
        return new CapeCPirQueryParts(anchorKeywordBytes, compressedAnchorQuery, queryBloomFilter.toLongBitVector(),
            queryBloomFilter.countOnes());
    }

    private CapeCPirQuery finishCapeCQuery(CapeCPirQueryParts parts, List<byte[]> encryptedPackedBloomQuery) {
        long compressedAnchorQueryBytes = parts.compressedAnchorQuery.toByteArray().length;
        long packedBloomQueryBytes = byteLength(encryptedPackedBloomQuery);
        long totalOnlineQueryBytes = compressedAnchorQueryBytes + packedBloomQueryBytes;
        lastCompressedAnchorQueryBytes = compressedAnchorQueryBytes;
        lastPackedBloomQueryBytes = packedBloomQueryBytes;
        lastTotalOnlineQueryBytes = totalOnlineQueryBytes;
        LOGGER.info(
            "{} compressedAnchorQueryBytes={}, packedBloomQueryCiphertextCount={}, packedBloomQueryBytes={}, "
                + "totalOnlineQueryBytes={}, setupEvaluationKeyBytes=offline",
            QUERY_PREFIX, compressedAnchorQueryBytes, encryptedPackedBloomQuery.size(), packedBloomQueryBytes,
            totalOnlineQueryBytes
        );
        return new CapeCPirQuery(
            parts.anchorKeywordBytes, parts.compressedAnchorQuery.toByteArray(), encryptedPackedBloomQuery,
            parts.bloomOneCount, config.getBoolKeywordNum()
        );
    }

    private List<byte[]> generatePackedBloomQueryCiphertexts(long[] queryBloomBits) {
        if (queryBloomBits.length != params.getBloomBitLength()) {
            throw new IllegalArgumentException("CAPE_C query Bloom bit length mismatch");
        }
        int capacity = params.getPolyModulusDegree();
        int groupNum = params.getPackedQueryBloomCiphertextNum();
        List<byte[]> chunks = new ArrayList<>(groupNum);
        for (int groupIndex = 0; groupIndex < groupNum; groupIndex++) {
            long[] chunk = new long[Math.min(capacity, queryBloomBits.length - groupIndex * capacity)];
            int groupOffset = groupIndex * capacity;
            for (int blockOffset = 0; blockOffset < chunk.length; blockOffset++) {
                int bitIndex = groupOffset + blockOffset;
                if (bitIndex < queryBloomBits.length) {
                    chunk[blockOffset] = queryBloomBits[bitIndex];
                }
            }
            chunks.add(CapeCPirNativeUtils.generateEncryptedCoeffBloomFilter(
                params.encryptionParams, publicKey, secretKey, chunk
            ));
        }
        return chunks;
    }

    List<byte[]> decodePackedResultResponseForTest(CapeCPirQuery query, CapeCPirResponse response) {
        return decodePackedResultResponse(query, response);
    }

    private List<byte[]> decodePackedResultResponse(CapeCPirQuery query, CapeCPirResponse response) {
        if (response.getPackedResultCiphertexts().size() != params.getExpectedPackedResultCiphertextCount()) {
            throw new IllegalStateException("CAPE_C packed result response ciphertext count mismatch");
        }
        long[] resultCoeffs = new long[params.getTotalResultCoeffNum()];
        int copiedCoeffNum = 0;
        for (byte[] packedResultCiphertext : response.getPackedResultCiphertexts()) {
            long[] coeffs = CapeCPirNativeUtils.decryptCoeffReply(params.encryptionParams, secretKey, packedResultCiphertext);
            int copyLength = Math.min(params.getPolyModulusDegree(), resultCoeffs.length - copiedCoeffNum);
            if (copyLength <= 0) {
                break;
            }
            System.arraycopy(coeffs, 0, resultCoeffs, copiedCoeffNum, copyLength);
            copiedCoeffNum += copyLength;
        }
        if (copiedCoeffNum < resultCoeffs.length) {
            throw new IllegalStateException("CAPE_C packed result response does not contain enough coefficients");
        }
        long[] scores = new long[params.getMaxValueNumPerKeyword()];
        System.arraycopy(resultCoeffs, params.getScoreOffset(), scores, 0, scores.length);
        long inversePackedScoreScale = inverseMod(params.getPolyModulusDegree() % params.getPlainModulus(),
            params.getPlainModulus());
        List<byte[]> candidateValues = decodeValueOnlyPayload(
            query.getAnchorKeywordBytes(), Arrays.copyOf(resultCoeffs, params.getValuePayloadCoeffNum())
        );
        List<byte[]> results = new ArrayList<>();
        for (int i = 0; i < scores.length; i++) {
            long score = Math.floorMod(scores[i] * inversePackedScoreScale, params.getPlainModulus());
            if (score == query.getBloomOneCount() && i < candidateValues.size()) {
                results.add(candidateValues.get(i));
            }
        }
        return results;
    }

    @SuppressWarnings("unchecked")
    private List<byte[]> decodeValueOnlyPayload(byte[] anchorKeywordBytes, long[] coeffs) {
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
            if (cause instanceof Error error) {
                throw error;
            }
            throw new IllegalStateException("CAPE value-only decoder failed", cause);
        }
    }

    CapeCPirParams getCapeCParams() {
        return params;
    }

    void setBffSeed(byte[] bffSeed) {
        this.bffSeed = BytesUtils.clone(bffSeed);
    }

    void setBffSeedAndBloomParamsForTest(byte[] bffSeed, byte[] serializedBloomParams) {
        this.bffSeed = BytesUtils.clone(bffSeed);
        params.applySerializedCapeCBloomParams(serializedBloomParams);
    }

    byte[] getPublicKey() {
        return Arrays.copyOf(publicKey, publicKey.length);
    }

    byte[] getSecretKey() {
        return Arrays.copyOf(secretKey, secretKey.length);
    }

    byte[] getRelinKeys() {
        return Arrays.copyOf(relinKeys, relinKeys.length);
    }

    byte[] getGaloisKeys() {
        return Arrays.copyOf(galoisKeys, galoisKeys.length);
    }

    long[] getLweSecretKey() {
        return Arrays.copyOf(lweSecretKey, lweSecretKey.length);
    }

    List<byte[]> getLweToRgswKey() {
        return lweToRgswKey.stream().map(BytesUtils::clone).toList();
    }

    void setStateForTest(int keywordNum, byte[] bffSeed, long[] lweSecretKey) {
        this.keywordNum = keywordNum;
        this.maxBatchNum = 1;
        this.bffSeed = BytesUtils.clone(bffSeed);
        this.lweSecretKey = Arrays.copyOf(lweSecretKey, lweSecretKey.length);
        initState();
    }

    List<CapeCPirQuery> getLastQueries() {
        return lastQueries;
    }

    long getLastCompressedAnchorQueryBytes() {
        return lastCompressedAnchorQueryBytes;
    }

    long getLastPackedBloomQueryBytes() {
        return lastPackedBloomQueryBytes;
    }

    long getLastTotalOnlineQueryBytes() {
        return lastTotalOnlineQueryBytes;
    }

    private static long[] generateBinaryLweSecretKey() {
        SecureRandom secureRandom = new SecureRandom();
        long[] secretKey = new long[CapeCPirUtils.LWE_DIMENSION];
        for (int i = 0; i < CapeCPirUtils.LWE_DIMENSION; i++) {
            secretKey[i] = secureRandom.nextBoolean() ? 1L : 0L;
        }
        return secretKey;
    }

    private static long byteLength(List<byte[]> payload) {
        return payload.stream().mapToLong(bytes -> bytes.length).sum();
    }

    static byte[] encodeSetupKeyMeta(int itemCount, long totalBytes) {
        return ByteBuffer.allocate(Integer.BYTES + Long.BYTES)
            .putInt(itemCount)
            .putLong(totalBytes)
            .array();
    }

    private static long inverseMod(long value, long modulus) {
        long t = 0;
        long newT = 1;
        long r = modulus;
        long newR = Math.floorMod(value, modulus);
        while (newR != 0) {
            long quotient = r / newR;
            long nextT = t - quotient * newT;
            t = newT;
            newT = nextT;
            long nextR = r - quotient * newR;
            r = newR;
            newR = nextR;
        }
        if (r != 1) {
            throw new IllegalStateException("packed score scale is not invertible modulo plaintext modulus");
        }
        return Math.floorMod(t, modulus);
    }

    private record CapeCPirQueryParts(byte[] anchorKeywordBytes, CapeCCompressedAnchorQuery compressedAnchorQuery,
                                     long[] queryBloomBits, int bloomOneCount) {
    }
}
