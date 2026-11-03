# Fault-resilient NTT for ML-KEM (twiddle-pointer faults)

Code for the paper "Fault-Resilient Number Theoretic Transform for ML-KEM".

- `ftcm_pqm4/`: C1, C2 and RATS integrated into pqm4 ML-KEM-768 (m4fspeed), tools and benchmarks
- `results/`: QEMU results and STM32F4 Discovery measurements

## Build (pqm4)
    git clone --recursive https://github.com/mupq/pqm4.git
    python3 ftcm_pqm4/tools/make_variants.py pqm4
    cd pqm4 && make PLATFORM=stm32f4discovery \
      IMPLEMENTATION_PATH=crypto_kem/ml-kem-768/m4fspeed-ftcm-allu \
      bin/crypto_kem_ml-kem-768_m4fspeed-ftcm-allu_ftbench.bin
