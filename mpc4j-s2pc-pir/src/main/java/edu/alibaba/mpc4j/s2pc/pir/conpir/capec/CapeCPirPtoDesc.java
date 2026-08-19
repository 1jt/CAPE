package edu.alibaba.mpc4j.s2pc.pir.conpir.capec;

import edu.alibaba.mpc4j.common.rpc.desc.PtoDesc;
import edu.alibaba.mpc4j.common.rpc.desc.PtoDescManager;

/**
 * CAPE_C PIR protocol description.
 *
 * @author Weiran Liu
 * @date 2026/07/07
 */
public class CapeCPirPtoDesc implements PtoDesc {
    /**
     * protocol ID.
     */
    private static final int PTO_ID = Math.abs((int) 6077077985750834719L);
    /**
     * protocol name.
     */
    private static final String PTO_NAME = "CAPE_C_CON_PIR";

    /**
     * protocol step.
     */
    enum PtoStep {
        /**
         * client sends BFV public / relin / Galois keys.
         */
        CLIENT_SEND_BFV_KEYS,
        /**
         * client sends compressed-anchor setup key metadata.
         */
        CLIENT_SEND_ANCHOR_EVAL_KEY_META,
        /**
         * client sends one compressed-anchor setup key chunk.
         */
        CLIENT_SEND_ANCHOR_EVAL_KEY_CHUNK,
        /**
         * server sends BFF seed and Bloom params.
         */
        SERVER_SEND_BFF_SEED,
        /**
         * client sends CAPE_C formal query.
         */
        CLIENT_SEND_QUERY,
        /**
         * server sends packed result response.
         */
        SERVER_SEND_RESPONSE,
    }

    /**
     * singleton mode.
     */
    private static final CapeCPirPtoDesc INSTANCE = new CapeCPirPtoDesc();

    private CapeCPirPtoDesc() {
        // empty
    }

    public static PtoDesc getInstance() {
        return INSTANCE;
    }

    static {
        PtoDescManager.registerPtoDesc(getInstance());
    }

    @Override
    public int getPtoId() {
        return PTO_ID;
    }

    @Override
    public String getPtoName() {
        return PTO_NAME;
    }
}
