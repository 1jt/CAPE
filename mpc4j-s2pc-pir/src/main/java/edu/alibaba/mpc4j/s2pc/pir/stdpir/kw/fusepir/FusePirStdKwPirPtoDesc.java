package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import edu.alibaba.mpc4j.common.rpc.desc.PtoDesc;
import edu.alibaba.mpc4j.common.rpc.desc.PtoDescManager;

/**
 * FUSE_PIR standard keyword PIR protocol description.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class FusePirStdKwPirPtoDesc implements PtoDesc {
    /**
     * protocol ID
     */
    private static final int PTO_ID = Math.abs((int) 915846237912734155L);
    /**
     * protocol name
     */
    private static final String PTO_NAME = "FUSE_PIR_STD_KW_PIR";

    /**
     * protocol step
     */
    enum PtoStep {
        /**
         * client sends public keys
         */
        CLIENT_SEND_PUBLIC_KEYS,
        /**
         * server sends BFF seed
         */
        SERVER_SEND_BFF_SEED,
        /**
         * client sends query
         */
        CLIENT_SEND_QUERY,
        /**
         * server sends response
         */
        SERVER_SEND_RESPONSE,
    }

    /**
     * singleton mode
     */
    private static final FusePirStdKwPirPtoDesc INSTANCE = new FusePirStdKwPirPtoDesc();

    /**
     * private constructor.
     */
    private FusePirStdKwPirPtoDesc() {
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
