package edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.PtoState;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractTwoPartyPto;
import edu.alibaba.mpc4j.common.tool.MathPreconditions;
import edu.alibaba.mpc4j.common.tool.utils.ObjectUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir.BkPirNativeUtils.*;
import static edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir.BkPirPtoDesc.PtoStep;
import static edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir.BkPirPtoDesc.getInstance;

/**
 * BKPIR client.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class BkPirClient<T> extends AbstractTwoPartyPto {
    /**
     * config.
     */
    private final BkPirConfig config;
    /**
     * params.
     */
    private final BkPirParams params;
    /**
     * keyword num.
     */
    private int keywordNum;
    /**
     * value space size.
     */
    private int valueSpaceSize;
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
     * value byte length.
     */
    private int valueByteLength;

    public BkPirClient(Rpc clientRpc, Party serverParty, BkPirConfig config) {
        super(getInstance(), clientRpc, serverParty, config);
        this.config = config;
        params = config.getParams();
    }

    public void init(int keywordNum, int valueSpaceSize, int valueByteLength, int maxBatchNum)
        throws MpcAbortException {
        MathPreconditions.checkPositive("keyword_num", keywordNum);
        MathPreconditions.checkPositive("value_space_size", valueSpaceSize);
        MathPreconditions.checkPositive("value_byte_length", valueByteLength);
        MathPreconditions.checkPositive("max_batch_num", maxBatchNum);
        this.keywordNum = keywordNum;
        this.valueSpaceSize = valueSpaceSize;
        this.valueByteLength = valueByteLength;
        this.maxBatchNum = maxBatchNum;
        logPhaseInfo(PtoState.INIT_BEGIN);

        stopWatch.start();
        params.initPirParams(keywordNum, valueSpaceSize, valueByteLength);
        List<byte[]> keyPair = BkPirNativeUtils.keyGen(params.encryptionParams);
        MpcAbortPreconditions.checkArgument(keyPair.size() == 4);
        secretKey = keyPair.get(SECRET_KEY_INDEX);
        publicKey = keyPair.get(PUBLIC_KEY_INDEX);
        List<byte[]> publicKeysPayload = new ArrayList<>(3);
        publicKeysPayload.add(publicKey);
        publicKeysPayload.add(keyPair.get(RELIN_KEYS_INDEX));
        publicKeysPayload.add(keyPair.get(GALOIS_KEYS_INDEX));
        sendOtherPartyPayload(PtoStep.CLIENT_SEND_PUBLIC_KEYS.ordinal(), publicKeysPayload);
        initState();
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        logStepInfo(PtoState.INIT_STEP, 1, 1, initTime);

        logPhaseInfo(PtoState.INIT_END);
    }

    public void init(int keywordNum, List<byte[]> valueSpace, int maxBatchNum) throws MpcAbortException {
        MathPreconditions.checkPositive("value_space_size", valueSpace.size());
        int valueByteLength = valueSpace.get(0).length;
        valueSpace.forEach(value ->
            MathPreconditions.checkEqual("value.length", "valueByteLength", value.length, valueByteLength)
        );
        init(keywordNum, valueSpace.size(), valueByteLength, maxBatchNum);
    }

    @SuppressWarnings("unchecked")
    public List<byte[]>[] pir(ArrayList<List<T>> queries) throws MpcAbortException {
        checkInitialized();
        MathPreconditions.checkPositiveInRangeClosed("batch_num", queries.size(), maxBatchNum);
        if (!config.getQueryMethod().equals(BkPirQueryMethod.AND)) {
            throw new UnsupportedOperationException("BKPIR currently only supports AND queries");
        }
        List<byte[]>[] results = new List[queries.size()];
        logPhaseInfo(PtoState.PTO_BEGIN);

        for (int batchIndex = 0; batchIndex < queries.size(); batchIndex++) {
            List<T> query = queries.get(batchIndex);
            MathPreconditions.checkEqual("query.size()", "bool_keyword_num", query.size(), config.getBoolKeywordNum());
            MathPreconditions.checkGreaterOrEqual("query.size()", query.size(), 2);

            stopWatch.start();
            List<byte[]> queryPayload = new ArrayList<>(query.size());
            for (T keyword : query) {
                queryPayload.add(generateQuery(keyword));
            }
            sendOtherPartyPayload(PtoStep.CLIENT_SEND_QUERY.ordinal(), queryPayload);
            stopWatch.stop();
            long queryTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 1, 2, queryTime, "Client generates boolean query");

            stopWatch.start();
            List<byte[]> responsePayload = receiveOtherPartyPayload(PtoStep.SERVER_SEND_RESPONSE.ordinal());
            MpcAbortPreconditions.checkArgument(responsePayload.size() == params.payloadPlaintextNum);
            long[][] coeffs = new long[params.payloadPlaintextNum][];
            for (int blockIndex = 0; blockIndex < params.payloadPlaintextNum; blockIndex++) {
                coeffs[blockIndex] = BkPirNativeUtils.decryptReply(
                    params.encryptionParams, secretKey, responsePayload.get(blockIndex)
                );
            }
            results[batchIndex] = decodeResponse(coeffs);
            stopWatch.stop();
            long decodeTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 2, 2, decodeTime, "Client handles boolean reply");
        }

        logPhaseInfo(PtoState.PTO_END);
        return results;
    }

    public int getKeywordNum() {
        return keywordNum;
    }

    public int getValueSpaceSize() {
        return valueSpaceSize;
    }

    private byte[] generateQuery(T keyword) {
        byte[] keywordBytes = ObjectUtils.objectToByteArray(keyword);
        long[] queryCodeword = BkPirUtils.cwEncode(
            BkPirUtils.hashKeywordToBigInteger(keywordBytes), params.getCodewordLength(), params.getCwWeight()
        );
        return BkPirNativeUtils.generateQuery(params.encryptionParams, publicKey, secretKey, queryCodeword);
    }

    private List<byte[]> decodeResponse(long[][] coeffs) {
        return BkPirUtils.decodeAndResultPayload(coeffs, valueSpaceSize, valueByteLength, params);
    }
}
