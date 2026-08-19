package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc;

import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractMultiPartyPtoConfig;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.StdKwPirConfig;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.StdKwPirFactory;

/**
 * FUSE_PIR_C standard keyword PIR config.
 *
 * @author Weiran Liu
 * @date 2026/06/16
 */
public class FusePirCStdKwPirConfig extends AbstractMultiPartyPtoConfig implements StdKwPirConfig {
    /**
     * params.
     */
    private final FusePirCStdKwPirParams params;

    private FusePirCStdKwPirConfig(Builder builder) {
        super(SecurityModel.SEMI_HONEST);
        params = new FusePirCStdKwPirParams(builder.params);
    }

    public FusePirCStdKwPirParams getParams() {
        return params;
    }

    @Override
    public StdKwPirFactory.StdKwPirType getPtoType() {
        return StdKwPirFactory.StdKwPirType.FUSE_PIR_C;
    }

    public static class Builder implements org.apache.commons.lang3.builder.Builder<FusePirCStdKwPirConfig> {
        /**
         * params.
         */
        private FusePirCStdKwPirParams params;

        public Builder() {
            params = FusePirCStdKwPirParams.DEFAULT_PARAMS;
        }

        public Builder setParams(FusePirCStdKwPirParams params) {
            this.params = new FusePirCStdKwPirParams(params);
            return this;
        }

        public Builder setParams(int fingerprintBitLength, int valueByteLength, int maxValueNumPerKeyword,
                                 boolean enablePayloadSplit) {
            params = new FusePirCStdKwPirParams(
                fingerprintBitLength, valueByteLength, maxValueNumPerKeyword, enablePayloadSplit
            );
            return this;
        }

        @Override
        public FusePirCStdKwPirConfig build() {
            return new FusePirCStdKwPirConfig(this);
        }
    }
}
