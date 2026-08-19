package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc;

import edu.alibaba.mpc4j.common.rpc.desc.PtoDesc;
import edu.alibaba.mpc4j.common.rpc.desc.PtoDescManager;

/**
 * FUSE_PIR_C standard keyword PIR protocol description.
 *
 * @author Weiran Liu
 * @date 2026/06/16
 */
public class FusePirCStdKwPirPtoDesc implements PtoDesc {
    /**
     * protocol ID.
     */
    private static final int PTO_ID = Math.abs((int) 8127394281765029163L);
    /**
     * protocol name.
     */
    private static final String PTO_NAME = "FUSE_PIR_C_STD_KW_PIR";

    /**
     * protocol step.
     */
    enum PtoStep {
        /**
         * client sends public keys.
         */
        CLIENT_SEND_PUBLIC_KEYS,
        /**
         * server sends BFF seed.
         */
        SERVER_SEND_BFF_SEED,
        /**
         * client sends compressed query.
         */
        CLIENT_SEND_COMPRESSED_QUERY,
        /**
         * server sends response.
         */
        SERVER_SEND_RESPONSE,
    }

    /**
     * singleton mode.
     */
    private static final FusePirCStdKwPirPtoDesc INSTANCE = new FusePirCStdKwPirPtoDesc();

    private FusePirCStdKwPirPtoDesc() {
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
