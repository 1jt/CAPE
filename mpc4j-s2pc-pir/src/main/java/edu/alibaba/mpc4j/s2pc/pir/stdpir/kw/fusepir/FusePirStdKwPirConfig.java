package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepir;

import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.rpc.pto.AbstractMultiPartyPtoConfig;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.StdKwPirConfig;
import edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.StdKwPirFactory;

/**
 * FUSE_PIR standard keyword PIR config.
 *
 * @author Weiran Liu
 * @date 2026/06/05
 */
public class FusePirStdKwPirConfig extends AbstractMultiPartyPtoConfig implements StdKwPirConfig {
    /**
     * params
     */
    private final FusePirStdKwPirParams params;
    private FusePirStdKwPirConfig(Builder builder) {
        super(SecurityModel.SEMI_HONEST);
        params = new FusePirStdKwPirParams(builder.params);
    }

    public FusePirStdKwPirParams getParams() {
        return params;
    }

    @Override
    public StdKwPirFactory.StdKwPirType getPtoType() {
        return StdKwPirFactory.StdKwPirType.FUSE_PIR;
    }

    public static class Builder implements org.apache.commons.lang3.builder.Builder<FusePirStdKwPirConfig> {
        /**
         * params
         */
        private FusePirStdKwPirParams params;
        public Builder() {
            params = FusePirStdKwPirParams.DEFAULT_PARAMS;
        }

        public Builder setParams(FusePirStdKwPirParams params) {
            this.params = new FusePirStdKwPirParams(params);
            return this;
        }

        public Builder setParams(int fingerprintBitLength, int valueByteLength, int maxValueNumPerKeyword,
                                 boolean enablePayloadSplit) {
            params = new FusePirStdKwPirParams(
                fingerprintBitLength, valueByteLength, maxValueNumPerKeyword, enablePayloadSplit
            );
            return this;
        }

        @Override
        public FusePirStdKwPirConfig build() {
            return new FusePirStdKwPirConfig(this);
        }
    }
}
