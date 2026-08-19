package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.PtoState;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.AbstractStdKwPirServer;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir.FusePirStdKwPirPtoDesc.PtoStep;
import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir.FusePirStdKwPirPtoDesc.getInstance;

/**
 * FUSE_PIR standard keyword PIR server.
 *
 * <p>The Java framework and encoding utilities are in place. The online protocol requires the native BlindRotate
 * implementation and is intentionally not exposed as a partial, incorrect protocol.</p>
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class FusePirStdKwPirServer<T> extends AbstractStdKwPirServer<T> {
    /**
     * params
     */
    private final FusePirStdKwPirParams params;
    /**
     * public key
     */
    private byte[] publicKey;
    /**
     * setup-time LWE-to-RGSW evaluation key.
     */
    private List<byte[]> lweToRgswKey;
    /**
     * encoded matrices
     */
    private List<byte[]> encodedMatrices;

    public FusePirStdKwPirServer(Rpc serverRpc, Party clientParty, FusePirStdKwPirConfig config) {
        super(getInstance(), serverRpc, clientParty, config);
        params = new FusePirStdKwPirParams(config.getParams());
    }

    @Override
    public void init(Map<T, byte[]> keyValueMap, int l, int maxBatchNum) throws MpcAbortException {
        logPhaseInfo(PtoState.INIT_BEGIN);
        List<byte[]> publicKeysPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_PUBLIC_KEYS.ordinal());
        stopWatch.start();
        MpcAbortPreconditions.checkArgument(publicKeysPayload.size() > 1);
        publicKey = publicKeysPayload.get(0);
        lweToRgswKey = new ArrayList<>(publicKeysPayload.subList(1, publicKeysPayload.size()));
        setInitInput(keyValueMap, l, maxBatchNum);
        params.initPirParams(n);
        Map<T, List<byte[]>> keywordValueMap = new LinkedHashMap<>(keyValueMap.size());
        keyValueMap.forEach((key, valueSetPayload) ->
            keywordValueMap.put(key, FusePirStdKwPirUtils.deserializeValueSet(valueSetPayload, params))
        );
        long bffStartTime = System.nanoTime();
        byte[] bffSeed;
        long[][][] matrices;
        if (params.getPayloadBlockNum() == 1) {
            FusePirStdKwPirUtils.BinaryFuseFilterData bffData = FusePirStdKwPirUtils.buildBinaryFuseFilters(
                keywordValueMap, params, new SecureRandom()
            );
            bffSeed = bffData.getSeed();
            matrices = FusePirStdKwPirUtils.matrixizePackedBff(bffData.getStorage(), params);
        } else {
            FusePirStdKwPirUtils.BinaryFuseMatrixData bffData = FusePirStdKwPirUtils.buildBinaryFuseMatrices(
                keywordValueMap, params, new SecureRandom()
            );
            bffSeed = bffData.getSeed();
            matrices = bffData.getMatrices();
        }
        long bffPreprocessTime = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - bffStartTime);
        long nativeStartTime = System.nanoTime();
        encodedMatrices = FusePirStdKwPirNativeUtils.preprocessDatabase(
            params.encryptionParams, matrices, params.getMatrixColNum(), params.getBlocksPerPackedMatrix()
        );
        matrices = null;
        long nativePreprocessTime = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - nativeStartTime);
        info(
            "[FUSE_PIR-INIT] keywordNum={}, payloadBlockNum={}, packedMatrixGroupNum={}, matrixRowNum={}, matrixColNum={}, "
                + "bffPreprocessMs={}, nativePreprocessMs={}",
            n, params.getPayloadBlockNum(), params.getPackedMatrixGroupNum(), params.getMatrixRowNum(),
            params.getMatrixColNum(), bffPreprocessTime, nativePreprocessTime
        );
        sendOtherPartyPayload(PtoStep.SERVER_SEND_BFF_SEED.ordinal(), Collections.singletonList(bffSeed));
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        logStepInfo(PtoState.INIT_STEP, 1, 1, initTime);
        logPhaseInfo(PtoState.INIT_END);
    }

    @Override
    public void pir(int batchNum) throws MpcAbortException {
        logPhaseInfo(PtoState.PTO_BEGIN);
        setPtoInput(batchNum);
        for (int i = 0; i < batchNum; i++) {
            List<byte[]> queryPayload = receiveOtherPartyPayload(PtoStep.CLIENT_SEND_QUERY.ordinal());
            stopWatch.start();
            MpcAbortPreconditions.checkArgument(queryPayload.size() == params.getBffHashNum() * 2);
            List<byte[]> columnQueries = queryPayload.subList(0, params.getBffHashNum());
            List<FusePirLweCiphertext> recoveredLweBits = new ArrayList<>();
            for (int positionIndex = 0; positionIndex < params.getBffHashNum(); positionIndex++) {
                FusePirCompressedLweBitQuery compressedQuery = FusePirCompressedLweBitQuery.fromByteArray(
                    queryPayload.get(params.getBffHashNum() + positionIndex)
                );
                recoveredLweBits.addAll(FusePirLwePrgUtils.recoverLweBitCiphertexts(compressedQuery));
            }
            long[][] aArray = new long[recoveredLweBits.size()][];
            long[] bArray = new long[recoveredLweBits.size()];
            for (int bitIndex = 0; bitIndex < recoveredLweBits.size(); bitIndex++) {
                aArray[bitIndex] = recoveredLweBits.get(bitIndex).getA();
                bArray[bitIndex] = recoveredLweBits.get(bitIndex).getB();
            }
            List<byte[]> rowBits = FusePirStdKwPirNativeUtils.convertCompressedRowBitsToRgsw(
                params.encryptionParams, publicKey, lweToRgswKey, aArray, bArray
            );
            List<byte[]> responsePayload = FusePirStdKwPirNativeUtils.generateReply(
                params.encryptionParams, publicKey, columnQueries, rowBits, encodedMatrices,
                params.getPayloadBlockNum(), params.getMatrixRowNum(), params.getMatrixColNum(),
                params.getBlocksPerPackedMatrix()
            );
            stopWatch.stop();
            long replyTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            sendOtherPartyPayload(PtoStep.SERVER_SEND_RESPONSE.ordinal(), responsePayload);
            logStepInfo(PtoState.PTO_STEP, 1, 1, replyTime,
                "Server converts compressed FUSE_PIR row bits and generates reply");
        }
        logPhaseInfo(PtoState.PTO_END);
    }
}
