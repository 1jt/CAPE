package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.PtoState;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.AbstractStdKwPirClient;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir.FusePirStdKwPirNativeUtils.*;
import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir.FusePirStdKwPirPtoDesc.PtoStep;
import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir.FusePirStdKwPirPtoDesc.getInstance;

/**
 * FUSE_PIR standard keyword PIR client.
 *
 * <p>The Java framework and encoding utilities are in place. The online protocol requires the native BlindRotate
 * implementation and is intentionally not exposed as a partial, incorrect protocol.</p>
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class FusePirStdKwPirClient<T> extends AbstractStdKwPirClient<T> {
    /**
     * prototype LWE dimension for compressed row-bit queries.
     */
    private static final int LWE_DIMENSION = 32;
    /**
     * prototype LWE modulus marker. The current compressed-row path uses integer phases so that setup-time
     * RGSW(s_i) evaluation keys can linearly recover an RGSW encryption of each row bit.
     */
    private static final long LWE_MODULUS = 1L << 32;
    /**
     * message scale for encrypted bits under {@link #LWE_MODULUS}.
     */
    private static final long DELTA_BIT = 1L;
    /**
     * params
     */
    private final FusePirStdKwPirParams params;
    /**
     * secret key
     */
    private byte[] secretKey;
    /**
     * public key
     */
    private byte[] publicKey;
    /**
     * BFF seed
     */
    private byte[] bffSeed;
    /**
     * prototype binary LWE secret key.
     */
    private long[] lweSecretKey;

    public FusePirStdKwPirClient(Rpc clientRpc, Party serverParty, FusePirStdKwPirConfig config) {
        super(getInstance(), clientRpc, serverParty, config);
        params = new FusePirStdKwPirParams(config.getParams());
    }

    @Override
    public void init(int n, int l, int maxBatchNum) throws MpcAbortException {
        logPhaseInfo(PtoState.INIT_BEGIN);
        stopWatch.start();
        setInitInput(n, l, maxBatchNum);
        params.initPirParams(n);
        List<byte[]> keyPair = FusePirStdKwPirNativeUtils.keyGen(params.encryptionParams);
        MpcAbortPreconditions.checkArgument(keyPair.size() == 2);
        secretKey = keyPair.get(SECRET_KEY_INDEX);
        publicKey = keyPair.get(PUBLIC_KEY_INDEX);
        lweSecretKey = generateBinaryLweSecretKey();
        List<byte[]> lweToRgswKey = FusePirStdKwPirNativeUtils.generateLweToRgswKey(
            params.encryptionParams, publicKey, lweSecretKey
        );
        List<byte[]> publicKeyPayload = new ArrayList<>(1 + lweToRgswKey.size());
        publicKeyPayload.add(publicKey);
        publicKeyPayload.addAll(lweToRgswKey);
        sendOtherPartyPayload(PtoStep.CLIENT_SEND_PUBLIC_KEYS.ordinal(), publicKeyPayload);
        // MemoryRpc owns independent receiver-side arrays after send returns. Release the serialized
        // evaluation-key source while the server preprocesses instead of retaining two full copies.
        publicKeyPayload.clear();
        lweToRgswKey.clear();
        System.gc();
        List<byte[]> seedPayload = receiveOtherPartyPayload(PtoStep.SERVER_SEND_BFF_SEED.ordinal());
        MpcAbortPreconditions.checkArgument(seedPayload.size() == 1);
        bffSeed = seedPayload.get(0);
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        logStepInfo(PtoState.INIT_STEP, 1, 1, initTime);
        logPhaseInfo(PtoState.INIT_END);
    }

    @Override
    public byte[][] pir(ArrayList<T> keys) throws MpcAbortException {
        logPhaseInfo(PtoState.PTO_BEGIN);
        setPtoInput(keys);
        byte[][] entries = new byte[batchNum][];
        for (int i = 0; i < batchNum; i++) {
            stopWatch.start();
            List<byte[]> queryPayload = generateQuery(keys.get(i));
            sendOtherPartyPayload(PtoStep.CLIENT_SEND_QUERY.ordinal(), queryPayload);
            stopWatch.stop();
            long queryTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 1, 2, queryTime, "Client generates FUSE_PIR query");

            stopWatch.start();
            List<byte[]> responsePayload = receiveOtherPartyPayload(PtoStep.SERVER_SEND_RESPONSE.ordinal());
            long[][] coeffs = FusePirStdKwPirNativeUtils.decryptReply(params.encryptionParams, secretKey, responsePayload);
            entries[i] = decodeResponse(keys.get(i), coeffs);
            stopWatch.stop();
            long decodeTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 2, 2, decodeTime, "Client handles FUSE_PIR reply");
        }
        logPhaseInfo(PtoState.PTO_END);
        return entries;
    }

    private List<byte[]> generateQuery(T key) {
        int[] positions = FusePirStdKwPirUtils.getHashPositions(key, n, bffSeed, params);
        List<byte[]> queryPayload = new ArrayList<>();
        List<byte[]> columnQueries = new ArrayList<>(positions.length);
        List<byte[]> rowBitQueries = new ArrayList<>();
        long columnQueryBytes = 0L;
        long compressedRowBitBytes = 0L;
        int compressedRowBitNum = 0;
        for (int position : positions) {
            int[] rowCol = FusePirStdKwPirUtils.getRowColFromBffIndex(position, params);
            byte[] columnQuery = FusePirStdKwPirNativeUtils.generateColumnQuery(
                params.encryptionParams, publicKey, secretKey,
                rowCol[1] * params.getBlocksPerPackedMatrix(),
                params.getMatrixColNum() * params.getBlocksPerPackedMatrix()
            );
            columnQueries.add(columnQuery);
            columnQueryBytes += columnQuery.length;
            byte[] compressedRowBits = generateCompressedRowBitQuery(rowCol[0], params.getMatrixRowNum())
                .toByteArray();
            rowBitQueries.add(compressedRowBits);
            compressedRowBitBytes += compressedRowBits.length;
            compressedRowBitNum += ceilLog2(params.getMatrixRowNum());
        }
        queryPayload.addAll(columnQueries);
        queryPayload.addAll(rowBitQueries);
        long rgswRowBitBytes = 0L;
        long clearRowIndexBytes = 0L;
        info(
            "FUSE_PIR query breakdown: columnQueryBytes={}, rgswRowBitBytes={}, compressedRowBitBytes={}, "
                + "clearRowIndexBytes={}, totalQueryBytes={}, columnQueryNum={}, compressedRowBitNum={}",
            columnQueryBytes, rgswRowBitBytes, compressedRowBitBytes, clearRowIndexBytes,
            columnQueryBytes + rgswRowBitBytes + compressedRowBitBytes + clearRowIndexBytes,
            positions.length, compressedRowBitNum
        );
        return queryPayload;
    }

    private FusePirCompressedLweBitQuery generateCompressedRowBitQuery(int rowIndex, int rowNum) {
        return FusePirLwePrgUtils.generateCompressedRowBitQuery(rowIndex, rowNum, lweSecretKey, LWE_MODULUS, DELTA_BIT);
    }

    private static long[] generateBinaryLweSecretKey() {
        SecureRandom secureRandom = new SecureRandom();
        long[] secretKey = new long[LWE_DIMENSION];
        for (int i = 0; i < LWE_DIMENSION; i++) {
            secretKey[i] = secureRandom.nextBoolean() ? 1L : 0L;
        }
        return secretKey;
    }

    private static int ceilLog2(int n) {
        return FusePirLwePrgUtils.ceilLog2(n);
    }

    private byte[] decodeResponse(T key, long[][] coeffs) {
        int groupsPerReply = params.getPolyModulusDegree() / params.getBlocksPerPackedMatrix();
        if (groupsPerReply <= 0) {
            throw new IllegalArgumentException("FUSE_PIR response packing capacity must be positive");
        }
        int blocksPerReply = groupsPerReply * params.getBlocksPerPackedMatrix();
        long[] payloadCoeffs = new long[params.getPayloadBlockNum()];
        int blockIndex = 0;
        for (long[] responseCoeffs : coeffs) {
            int copyBlockNum = Math.min(blocksPerReply, params.getPayloadBlockNum() - blockIndex);
            if (copyBlockNum <= 0) {
                break;
            }
            System.arraycopy(responseCoeffs, 0, payloadCoeffs, blockIndex, copyBlockNum);
            blockIndex += copyBlockNum;
        }
        if (blockIndex < params.getPayloadBlockNum()) {
            throw new IllegalArgumentException("FUSE_PIR response does not contain enough packed payload blocks");
        }
        List<byte[]> values = FusePirStdKwPirUtils.decodePackedPayloadCoefficients(key, payloadCoeffs, params);
        return values.isEmpty() ? new byte[0] : FusePirStdKwPirUtils.serializeValueSet(values, params);
    }
}
