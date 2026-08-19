package edu.alibaba.mpc4j.s2pc.pir.conpir.bkpir;

import edu.alibaba.mpc4j.common.rpc.desc.PtoDesc;
import edu.alibaba.mpc4j.common.rpc.desc.PtoDescManager;

/**
 * BKPIR protocol description.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class BkPirPtoDesc implements PtoDesc {
    /**
     * protocol ID.
     */
    private static final int PTO_ID = Math.abs((int) 3119583744261968458L);
    /**
     * protocol name.
     */
    private static final String PTO_NAME = "BK_CON_PIR";

    /**
     * protocol step.
     */
    enum PtoStep {
        /**
         * client sends public keys.
         */
        CLIENT_SEND_PUBLIC_KEYS,
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
    private static final BkPirPtoDesc INSTANCE = new BkPirPtoDesc();

    private BkPirPtoDesc() {
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
