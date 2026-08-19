package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc;

import edu.alibaba.mpc4j.common.tool.MathPreconditions;

/**
 * FUSE_PIR_C circuit bootstrapping parameters.
 *
 * @author Weiran Liu
 * @date 2026/06/16
 */
public class FusePirCCircuitBootstrapParams {
    /**
     * Raw correctness parameters. These are not secure.
     */
    static final FusePirCCircuitBootstrapParams RAW_CORRECTNESS = new FusePirCCircuitBootstrapParams(
        16, 65537L, 3, 256L, 0.1, FusePirCRgswComponentOrder.BODY_FIRST,
        "correctness only, not secure"
    );
    /**
     * Paper-aligned 128-bit candidate. Estimator validation is pending.
     */
    public static final FusePirCCircuitBootstrapParams CMUX_128_CANDIDATE = new FusePirCCircuitBootstrapParams(
        2048, 18014398509404161L, 5, 64L, 3.2, FusePirCRgswComponentOrder.BODY_FIRST,
        "paper-aligned 128-bit candidate, estimator pending"
    );
    /**
     * Layout fairness candidate. Estimator validation is pending.
     */
    public static final FusePirCCircuitBootstrapParams LAYOUT_16384_CANDIDATE = new FusePirCCircuitBootstrapParams(
        16384, 18014398508400641L, 4, 65536L, 3.2, FusePirCRgswComponentOrder.BODY_FIRST,
        "layout fairness candidate, estimator pending"
    );
    /**
     * default params.
     */
    public static final FusePirCCircuitBootstrapParams DEFAULT_PARAMS = CMUX_128_CANDIDATE;
    /**
     * raw RLWE degree.
     */
    private final int rawRlweDegree;
    /**
     * raw RLWE modulus.
     */
    private final long rawRlweModulus;
    /**
     * gadget length.
     */
    private final int gadgetLength;
    /**
     * gadget base.
     */
    private final long gadgetBase;
    /**
     * raw RLWE Gaussian sigma.
     */
    private final double rawRlweSigma;
    /**
     * RGSW component order.
     */
    private final FusePirCRgswComponentOrder componentOrder;
    /**
     * security label.
     */
    private final String securityLabel;

    public FusePirCCircuitBootstrapParams(int rawRlweDegree, long rawRlweModulus, int gadgetLength, long gadgetBase,
                                       double rawRlweSigma, FusePirCRgswComponentOrder componentOrder,
                                       String securityLabel) {
        MathPreconditions.checkPositive("raw_rlwe_degree", rawRlweDegree);
        MathPreconditions.checkGreater("raw_rlwe_modulus", rawRlweModulus, 1L);
        MathPreconditions.checkPositive("gadget_length", gadgetLength);
        MathPreconditions.checkGreater("gadget_base", gadgetBase, 1L);
        MathPreconditions.checkGreater("raw_rlwe_sigma", rawRlweSigma, 0.0);
        this.rawRlweDegree = rawRlweDegree;
        this.rawRlweModulus = rawRlweModulus;
        this.gadgetLength = gadgetLength;
        this.gadgetBase = gadgetBase;
        this.rawRlweSigma = rawRlweSigma;
        this.componentOrder = componentOrder;
        this.securityLabel = securityLabel;
        validate();
    }

    public FusePirCCircuitBootstrapParams(FusePirCCircuitBootstrapParams params) {
        this(params.rawRlweDegree, params.rawRlweModulus, params.gadgetLength, params.gadgetBase,
            params.rawRlweSigma, params.componentOrder, params.securityLabel);
    }

    private void validate() {
        if ((rawRlweModulus & 1L) == 0L) {
            throw new IllegalArgumentException("FUSE_PIR_C raw RLWE modulus must be odd");
        }
        if (gcd(rawRlweDegree, rawRlweModulus) != 1L) {
            throw new IllegalArgumentException("FUSE_PIR_C raw RLWE degree and modulus must be coprime");
        }
        if (rawRlweModulus % (2L * rawRlweDegree) != 1L) {
            throw new IllegalArgumentException("FUSE_PIR_C raw RLWE modulus must satisfy Q mod 2N = 1");
        }
        if (securityLabel != null && securityLabel.contains("candidate")) {
            return;
        }
        long covered = 1L;
        for (int i = 0; i < gadgetLength; i++) {
            if (covered >= rawRlweModulus) {
                return;
            }
            if (covered > Long.MAX_VALUE / gadgetBase) {
                return;
            }
            covered *= gadgetBase;
        }
        if (covered < rawRlweModulus) {
            throw new IllegalArgumentException("FUSE_PIR_C gadget length is insufficient for exact decomposition");
        }
    }

    private static long gcd(long a, long b) {
        long x = Math.abs(a);
        long y = Math.abs(b);
        while (y != 0) {
            long t = x % y;
            x = y;
            y = t;
        }
        return x;
    }

    public int getRawRlweDegree() {
        return rawRlweDegree;
    }

    public long getRawRlweModulus() {
        return rawRlweModulus;
    }

    public int getGadgetLength() {
        return gadgetLength;
    }

    public long getGadgetBase() {
        return gadgetBase;
    }

    public double getRawRlweSigma() {
        return rawRlweSigma;
    }

    public FusePirCRgswComponentOrder getComponentOrder() {
        return componentOrder;
    }

    public String getSecurityLabel() {
        return securityLabel;
    }

    enum FusePirCRgswComponentOrder {
        /**
         * body digits first, key digits second.
         */
        BODY_FIRST,
    }
}
