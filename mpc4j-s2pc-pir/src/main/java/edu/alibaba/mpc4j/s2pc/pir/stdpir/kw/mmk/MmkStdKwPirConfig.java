package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.mmk;

import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractMultiPartyPtoConfig;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.StdKwPirConfig;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.StdKwPirFactory;

/**
 * MMK standard keyword PIR config.
 *
 * @author Weiran Liu
 * @date 2026/06/04
 */
public class MmkStdKwPirConfig extends AbstractMultiPartyPtoConfig implements StdKwPirConfig {
    /**
     * params
     */
    private final MmkStdKwPirParams params;

    private MmkStdKwPirConfig(Builder builder) {
        super(SecurityModel.MALICIOUS);
        params = builder.params;
    }

    @Override
    public StdKwPirFactory.StdKwPirType getPtoType() {
        return StdKwPirFactory.StdKwPirType.MMK;
    }

    public MmkStdKwPirParams getParams() {
        return params;
    }

    public static class Builder implements org.apache.commons.lang3.builder.Builder<MmkStdKwPirConfig> {
        /**
         * params
         */
        private MmkStdKwPirParams params;

        public Builder() {
            params = MmkStdKwPirParams.DEFAULT_PARAMS;
        }

        public Builder setParams(MmkStdKwPirParams params) {
            this.params = params;
            return this;
        }

        @Override
        public MmkStdKwPirConfig build() {
            return new MmkStdKwPirConfig(this);
        }
    }
}
