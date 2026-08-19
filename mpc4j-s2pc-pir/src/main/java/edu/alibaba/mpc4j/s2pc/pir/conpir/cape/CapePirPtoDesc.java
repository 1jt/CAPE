package edu.alibaba.mpc4j.s2pc.pir.conpir.cape;

import edu.alibaba.mpc4j.common.rpc.desc.PtoDesc;
import edu.alibaba.mpc4j.common.rpc.desc.PtoDescManager;

/**
 * CAPE PIR protocol description.
 *
 * @author Weiran Liu
 * @date 2026/06/06
 */
public class CapePirPtoDesc implements PtoDesc {
    /**
     * protocol ID.
     */
    private static final int PTO_ID = Math.abs((int) 4128437719342105689L);
    /**
     * protocol name.
     */
    private static final String PTO_NAME = "CAPE_CON_PIR";

    /**
     * protocol step.
     */
    enum PtoStep {
        /**
         * client sends BFV public / relin / Galois keys.
         */
        CLIENT_SEND_BFV_KEYS,
        /**
         * client sends LWE-to-RGSW setup key chunk metadata.
         */
        CLIENT_SEND_LWE_TO_RGSW_KEY_META,
        /**
         * client sends one LWE-to-RGSW setup key chunk.
         */
        CLIENT_SEND_LWE_TO_RGSW_KEY_CHUNK,
        /**
         * server sends BFF seed.
         */
        SERVER_SEND_BFF_SEED,
        /**
         * client sends query.
         */
        CLIENT_SEND_QUERY,
        /**
         * server sends response.
         */
        SERVER_SEND_RESPONSE,
    }

    /**
     * singleton mode.
     */
    private static final CapePirPtoDesc INSTANCE = new CapePirPtoDesc();

    private CapePirPtoDesc() {
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
