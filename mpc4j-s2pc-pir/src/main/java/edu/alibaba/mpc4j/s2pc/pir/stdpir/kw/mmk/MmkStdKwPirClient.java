package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk;

import edu.alibaba.mpc4j.common.rpc.*;
import edu.alibaba.mpc4j.common.tool.utils.ObjectUtils;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.AbstractStdKwPirClient;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk.MmkStdKwPirNativeUtils.*;
import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk.MmkStdKwPirPtoDesc.PtoStep;
import static edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk.MmkStdKwPirPtoDesc.getInstance;

/**
 * MMK standard keyword PIR client.
 *
 * @author Weiran Liu
 * @date 2026/06/04
 */
public class MmkStdKwPirClient<T> extends AbstractStdKwPirClient<T> {
    /**
     * params
     */
    private final MmkStdKwPirParams params;
    /**
     * secret key
     */
    private byte[] secretKey;
    /**
     * public key
     */
    private byte[] publicKey;

    public MmkStdKwPirClient(Rpc clientRpc, Party serverParty, MmkStdKwPirConfig config) {
        super(getInstance(), clientRpc, serverParty, config);
        params = config.getParams();
    }

    @Override
    public void init(int n, int l, int maxBatchNum) throws MpcAbortException {
        assert maxBatchNum <= params.maxRetrievalSize();
        setInitInput(n, l, maxBatchNum);
        logPhaseInfo(PtoState.INIT_BEGIN);

        stopWatch.start();
        params.initPirParams(n, l);
        List<byte[]> keyPair = MmkStdKwPirNativeUtils.keyGen(params.encryptionParams);
        MpcAbortPreconditions.checkArgument(keyPair.size() == 4);
        secretKey = keyPair.get(SECRET_KEY_INDEX);
        publicKey = keyPair.get(PUBLIC_KEY_INDEX);
        List<byte[]> publicKeysPayload = new ArrayList<>(3);
        publicKeysPayload.add(publicKey);
        publicKeysPayload.add(keyPair.get(RELIN_KEYS_INDEX));
        publicKeysPayload.add(keyPair.get(GALOIS_KEYS_INDEX));
        sendOtherPartyPayload(PtoStep.CLIENT_SEND_PUBLIC_KEYS.ordinal(), publicKeysPayload);
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        logStepInfo(PtoState.INIT_STEP, 1, 1, initTime);

        logPhaseInfo(PtoState.INIT_END);
    }

    @Override
    public byte[][] pir(ArrayList<T> keys) throws MpcAbortException {
        setPtoInput(keys);
        logPhaseInfo(PtoState.PTO_BEGIN);

        byte[][] entries = new byte[batchNum][];
        for (int i = 0; i < batchNum; i++) {
            stopWatch.start();
            byte[] queryPayload = generateQuery(keys.get(i));
            sendOtherPartyPayload(PtoStep.CLIENT_SEND_QUERY.ordinal(), Collections.singletonList(queryPayload));
            stopWatch.stop();
            long queryTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 1, 2, queryTime, "Client generates query");

            stopWatch.start();
            List<byte[]> responsePayload = receiveOtherPartyPayload(PtoStep.SERVER_SEND_RESPONSE.ordinal());
            MpcAbortPreconditions.checkArgument(responsePayload.size() == params.payloadPlaintextNum);
            long[][] coeffs = new long[params.payloadPlaintextNum][];
            for (int blockIndex = 0; blockIndex < params.payloadPlaintextNum; blockIndex++) {
                coeffs[blockIndex] = MmkStdKwPirNativeUtils.decryptReply(
                    params.encryptionParams, secretKey, responsePayload.get(blockIndex)
                );
            }
            entries[i] = decodeResponse(coeffs);
            stopWatch.stop();
            long decodeTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
            stopWatch.reset();
            logStepInfo(PtoState.PTO_STEP, 2, 2, decodeTime, "Client handles reply");
        }

        logPhaseInfo(PtoState.PTO_END);
        return entries;
    }

    private byte[] generateQuery(T key) {
        byte[] keywordBytes = ObjectUtils.objectToByteArray(key);
        long[] queryCodeword = MmkStdKwPirUtils.cwEncode(
            MmkStdKwPirUtils.hashKeywordToBigInteger(keywordBytes), params.getCodewordLength(), params.getCwWeight()
        );
        return MmkStdKwPirNativeUtils.generateQuery(params.encryptionParams, publicKey, secretKey, queryCodeword);
    }

    private byte[] decodeResponse(long[][] coeffs) {
        for (long[] coeffBlock : coeffs) {
            for (long coeff : coeffBlock) {
                if (coeff != 0L) {
                    return MmkStdKwPirUtils.decodePayload(coeffs, byteL, params);
                }
            }
        }
        return new byte[0];
    }
}
