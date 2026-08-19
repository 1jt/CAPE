package edu.alibaba.mpc4j.s2pc.pir.stdpir.kw.fusepirc;

import edu.alibaba.mpc4j.common.tool.MathPreconditions;

/**
 * FUSE_PIR_C LWE parameters.
 *
 * @author Weiran Liu
 * @date 2026/06/16
 */
public class FusePirCLweParams {
    /**
     * Debug-only small parameters. Must not be connected to the protocol default path.
     */
    static final FusePirCLweParams DEBUG_SMALL = new FusePirCLweParams(32, 1L << 32, 3.2, 1L << 31, false);
    /**
     * Raw correctness parameters. These are for primitive tests only and are not secure.
     */
    static final FusePirCLweParams RAW_CORRECTNESS = new FusePirCLweParams(3, 128, 0.1, 64, false);
    /**
     * Paper-aligned 128-bit candidate. Estimator validation is still pending, so this constant must not be
     * interpreted as a completed 128-bit security claim.
     */
    public static final FusePirCLweParams CMUX_128_CANDIDATE = new FusePirCLweParams(571, 1024, 3.2, 512, true);
    /**
     * Layout fairness candidate with the same LWE side as CMUX_128_CANDIDATE.
     */
    public static final FusePirCLweParams LAYOUT_16384_CANDIDATE = new FusePirCLweParams(571, 1024, 3.2, 512, true);
    /**
     * dimension.
     */
    private final int dimension;
    /**
     * modulus.
     */
    private final long modulus;
    /**
     * Gaussian sigma.
     */
    private final double sigma;
    /**
     * bit encoding delta.
     */
    private final long delta;
    /**
     * whether this is the formal protocol parameter set.
     */
    private final boolean protocolDefault;

    public FusePirCLweParams(int dimension, long modulus, double sigma, long delta, boolean protocolDefault) {
        MathPreconditions.checkPositive("dimension", dimension);
        MathPreconditions.checkGreater("modulus", modulus, 1L);
        MathPreconditions.checkGreater("sigma", sigma, 0.0);
        MathPreconditions.checkPositive("delta", delta);
        this.dimension = dimension;
        this.modulus = modulus;
        this.sigma = sigma;
        this.delta = delta;
        this.protocolDefault = protocolDefault;
    }

    public FusePirCLweParams(FusePirCLweParams params) {
        this(params.dimension, params.modulus, params.sigma, params.delta, params.protocolDefault);
    }

    public int getDimension() {
        return dimension;
    }

    public long getModulus() {
        return modulus;
    }

    public double getSigma() {
        return sigma;
    }

    public long getDelta() {
        return delta;
    }

    public boolean isProtocolDefault() {
        return protocolDefault;
    }
}
