#pragma once
#include <cmath>
#include <cstdint>
#include <vector>

struct targetP {
    static constexpr size_t l_ = 7;       // legacy Onion / no-context layout only.
    static constexpr size_t digits = 420; // legacy Onion / no-context layout only.
    static constexpr size_t Bgbit = 60;   // SEAL-backed RGSW derives digit count from the active context.
    static constexpr uint64_t Bg = 1ULL << Bgbit;
};
