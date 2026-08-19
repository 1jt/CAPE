#include "gadget.h"

#include <limits>
#include <stdexcept>

using namespace std;

namespace seal {
    namespace fusepirc {
        namespace {
            uint64_t mul_uint_mod(uint64_t a, uint64_t b, uint64_t modulus) {
                return static_cast<uint64_t>((static_cast<__uint128_t>(a) * b) % modulus);
            }

            uint64_t add_uint_mod(uint64_t a, uint64_t b, uint64_t modulus) {
                return static_cast<uint64_t>((static_cast<__uint128_t>(a) + b) % modulus);
            }

            uint64_t signed_to_mod(int64_t value, uint64_t modulus) {
                if (value >= 0) {
                    return static_cast<uint64_t>(value) % modulus;
                }
                uint64_t magnitude = static_cast<uint64_t>(-value) % modulus;
                return magnitude == 0 ? 0 : modulus - magnitude;
            }

            int64_t mod_to_centered(uint64_t value, uint64_t modulus) {
                value %= modulus;
                uint64_t half = modulus / 2;
                if (value <= half) {
                    return static_cast<int64_t>(value);
                }
                return -static_cast<int64_t>(modulus - value);
            }

            uint64_t pow_base_mod(uint64_t base, uint32_t exponent, uint64_t modulus) {
                uint64_t result = 1 % modulus;
                for (uint32_t i = 0; i < exponent; i++) {
                    result = mul_uint_mod(result, base, modulus);
                }
                return result;
            }

            uint64_t round_div_u128(__uint128_t numerator, uint64_t denominator) {
                return static_cast<uint64_t>((numerator + denominator / 2) / denominator);
            }

            int64_t round_div_signed(int64_t numerator, uint64_t denominator) {
                if (denominator == 0) {
                    throw invalid_argument("division by zero in signed rounding");
                }
                if (numerator >= 0) {
                    return static_cast<int64_t>((static_cast<__uint128_t>(numerator) + denominator / 2)
                        / denominator);
                }
                uint64_t magnitude = static_cast<uint64_t>(-numerator);
                return -static_cast<int64_t>((static_cast<__uint128_t>(magnitude) + denominator / 2)
                    / denominator);
            }

            vector<uint64_t> low_bits_gadget_values(const GadgetParams &params) {
                vector<uint64_t> values(params.length);
                for (uint32_t j = 0; j < params.length; j++) {
                    values[j] = pow_base_mod(params.base, j, params.modulus);
                }
                return values;
            }

            vector<uint64_t> torus_approx_high_gadget_values(const GadgetParams &params) {
                if (params.length == 0) {
                    throw invalid_argument("torus approximate high gadget length must be positive");
                }
                vector<uint64_t> values(params.length);
                __uint128_t denominator = 2;
                for (uint32_t j = 0; j < params.length; j++) {
                    uint64_t value = round_div_u128(params.modulus, static_cast<uint64_t>(denominator));
                    if (value == 0) {
                        throw invalid_argument("torus approximate high gadget value rounded to zero");
                    }
                    values[j] = value % params.modulus;
                    denominator *= params.base;
                }
                return values;
            }

            bool base_power_covers_modulus(uint64_t base, uint32_t length, uint64_t modulus) {
                __uint128_t value = 1;
                for (uint32_t i = 0; i < length; i++) {
                    value *= base;
                    if (value >= modulus) {
                        return true;
                    }
                }
                return false;
            }
        }

        void validate_gadget_params(const GadgetParams &params) {
            if (!params.exact) {
                throw invalid_argument("only exact gadget decomposition is implemented");
            }
            if (params.base <= 1) {
                throw invalid_argument("gadget base must be greater than 1");
            }
            if (params.baseBitLength == 0 || params.baseBitLength > 63) {
                throw invalid_argument("gadget base bit length must be in [1,63]");
            }
            if (params.length == 0) {
                throw invalid_argument("gadget length must be positive");
            }
            if (params.modulus <= 1) {
                throw invalid_argument("gadget modulus must be greater than 1");
            }
            if ((UINT64_C(1) << params.baseBitLength) != params.base) {
                throw invalid_argument("exact gadget base must equal 2^baseBitLength");
            }
            if (params.scaleMode == GadgetParams::ScaleMode::LOW_BITS_EXACT
                && !base_power_covers_modulus(params.base, params.length, params.modulus)) {
                throw invalid_argument("exact gadget base^length must cover modulus");
            }
            if (params.modulus > static_cast<uint64_t>(numeric_limits<int64_t>::max())) {
                throw invalid_argument("exact balanced gadget decomposition requires modulus fitting int64");
            }
            if (params.base > static_cast<uint64_t>(numeric_limits<int64_t>::max())) {
                throw invalid_argument("exact balanced gadget base must fit int64");
            }
            if (params.scaleMode == GadgetParams::ScaleMode::TORUS_APPROX_HIGH) {
                (void) torus_approx_high_gadget_values(params);
            }
        }

        GadgetSpec make_gadget_spec(const GadgetParams &params) {
            validate_gadget_params(params);
            return GadgetSpec{
                params.modulus,
                params.base,
                params.length,
                params.scaleMode,
                gadget_values(params)
            };
        }

        vector<uint64_t> gadget_values(const GadgetParams &params) {
            validate_gadget_params(params);
            switch (params.scaleMode) {
                case GadgetParams::ScaleMode::LOW_BITS_EXACT:
                    return low_bits_gadget_values(params);
                case GadgetParams::ScaleMode::TORUS_APPROX_HIGH:
                    return torus_approx_high_gadget_values(params);
            }
            throw invalid_argument("unknown gadget scale mode");
        }

        vector<TorusPoly> gadget_decompose(const TorusPoly &poly, const GadgetParams &params) {
            switch (params.scaleMode) {
                case GadgetParams::ScaleMode::LOW_BITS_EXACT:
                    return gadget_decompose_exact(poly, params);
                case GadgetParams::ScaleMode::TORUS_APPROX_HIGH:
                    return gadget_decompose_torus_scaled(poly, params);
            }
            throw invalid_argument("unknown gadget scale mode");
        }

        vector<TorusPoly> gadget_decompose_exact(const TorusPoly &poly, const GadgetParams &params) {
            validate_torus_poly(poly);
            validate_gadget_params(params);
            if (poly.modulus != params.modulus) {
                throw invalid_argument("gadget polynomial modulus mismatch");
            }
            vector<TorusPoly> digits(params.length, zero_poly(poly.degree, poly.modulus));
            for (uint32_t coeff_index = 0; coeff_index < poly.degree; coeff_index++) {
                int64_t value = mod_to_centered(poly.coeffs[coeff_index], poly.modulus);
                int64_t base = static_cast<int64_t>(params.base);
                int64_t half_base = base / 2;
                for (uint32_t digit_index = 0; digit_index < params.length; digit_index++) {
                    int64_t digit = value % base;
                    value = (value - digit) / base;
                    if (digit > half_base) {
                        digit -= base;
                        value += 1;
                    } else if (digit < -half_base) {
                        digit += base;
                        value -= 1;
                    }
                    digits[digit_index].coeffs[coeff_index] = signed_to_mod(digit, poly.modulus);
                }
                if (value != 0) {
                    throw invalid_argument("gadget length did not cover coefficient");
                }
            }
            return digits;
        }

        vector<TorusPoly> gadget_decompose_torus_scaled(const TorusPoly &poly, const GadgetParams &params) {
            validate_torus_poly(poly);
            validate_gadget_params(params);
            if (params.scaleMode != GadgetParams::ScaleMode::TORUS_APPROX_HIGH) {
                throw invalid_argument("torus approximate high gadget decomposition requires TORUS_APPROX_HIGH mode");
            }
            if (poly.modulus != params.modulus) {
                throw invalid_argument("torus approximate high gadget polynomial modulus mismatch");
            }
            vector<uint64_t> values = torus_approx_high_gadget_values(params);
            vector<TorusPoly> digits(params.length, zero_poly(poly.degree, poly.modulus));
            int64_t half_base = static_cast<int64_t>(params.base / 2);
            for (uint32_t coeff_index = 0; coeff_index < poly.degree; coeff_index++) {
                int64_t residual = mod_to_centered(poly.coeffs[coeff_index], poly.modulus);
                for (uint32_t digit_index = 0; digit_index < params.length; digit_index++) {
                    int64_t digit;
                    digit = round_div_signed(residual, values[digit_index]);
                    if (digit > half_base) {
                        digit = half_base;
                    } else if (digit < -half_base) {
                        digit = -half_base;
                    }
                    residual -= static_cast<int64_t>(static_cast<__int128>(digit) * values[digit_index]);
                    digits[digit_index].coeffs[coeff_index] = signed_to_mod(digit, poly.modulus);
                }
            }
            return digits;
        }

        TorusPoly gadget_compose_exact(const vector<TorusPoly> &digits, const GadgetParams &params) {
            validate_gadget_params(params);
            if (digits.size() != params.length) {
                throw invalid_argument("gadget digit length mismatch");
            }
            if (digits.empty()) {
                throw invalid_argument("empty gadget digits");
            }
            validate_torus_poly(digits[0]);
            if (digits[0].modulus != params.modulus) {
                throw invalid_argument("gadget digit modulus mismatch");
            }
            TorusPoly out = zero_poly(digits[0].degree, digits[0].modulus);
            for (uint32_t digit_index = 0; digit_index < params.length; digit_index++) {
                validate_same_ring(digits[0], digits[digit_index]);
                uint64_t weight = pow_base_mod(params.base, digit_index, params.modulus);
                for (uint32_t coeff_index = 0; coeff_index < out.degree; coeff_index++) {
                    int64_t signed_digit = mod_to_centered(digits[digit_index].coeffs[coeff_index],
                        params.modulus);
                    if (signed_digit > static_cast<int64_t>(params.base / 2)
                        || signed_digit < -static_cast<int64_t>(params.base / 2)) {
                        throw invalid_argument("balanced gadget digit coefficient exceeds base/2");
                    }
                    uint64_t digit_mod = signed_to_mod(signed_digit, params.modulus);
                    uint64_t term = mul_uint_mod(digit_mod, weight, params.modulus);
                    out.coeffs[coeff_index] = add_uint_mod(out.coeffs[coeff_index], term, params.modulus);
                }
            }
            return out;
        }

        TorusPoly gadget_compose(const vector<TorusPoly> &digits, const GadgetParams &params) {
            validate_gadget_params(params);
            if (digits.size() != params.length) {
                throw invalid_argument("gadget digit length mismatch");
            }
            if (digits.empty()) {
                throw invalid_argument("empty gadget digits");
            }
            validate_torus_poly(digits[0]);
            if (digits[0].modulus != params.modulus) {
                throw invalid_argument("gadget digit modulus mismatch");
            }
            vector<uint64_t> values = gadget_values(params);
            TorusPoly out = zero_poly(digits[0].degree, digits[0].modulus);
            for (uint32_t digit_index = 0; digit_index < params.length; digit_index++) {
                validate_same_ring(digits[0], digits[digit_index]);
                for (uint32_t coeff_index = 0; coeff_index < out.degree; coeff_index++) {
                    uint64_t term = mul_uint_mod(digits[digit_index].coeffs[coeff_index],
                        values[digit_index], params.modulus);
                    out.coeffs[coeff_index] = add_uint_mod(out.coeffs[coeff_index], term, params.modulus);
                }
            }
            return out;
        }

        RawRlweGadgetDecomposition gadget_decompose_rlwe(const RawRlweCipher &ct, const GadgetParams &params) {
            if (ct.isNttForm) {
                throw invalid_argument("raw RLWE gadget decomposition requires coefficient form");
            }
            return RawRlweGadgetDecomposition{
                gadget_decompose(ct.a, params),
                gadget_decompose(ct.b, params)
            };
        }
    }
}
