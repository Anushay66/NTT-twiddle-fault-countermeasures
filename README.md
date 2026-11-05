# Fault-resilient NTT for ML-KEM: countermeasures against twiddle-pointer faults

Code and data for the paper "Fault-Resilient Number Theoretic Transform for
ML-KEM (CRYSTALS-Kyber) Using Algorithmic Countermeasures Against
Twiddle-Factor Fault Injection".

## Contents

- `ntt_fault_lab/`: Python model of the ML-KEM incomplete NTT, the three countermeasures (C1, C2, RATS), the Monte Carlo experiments and the key/message-recovery attacks.
- `ftcm_pqm4/`: C1, C2 and RATS integrated into the pqm4 ML-KEM-768 `m4fspeed` implementation, with benchmark firmware and tools.
- `results/`: QEMU results and the cycle counts measured on the STM32F4 Discovery board.

## Requirements

- Python 3 with `numpy` and `matplotlib`
- For pqm4: `arm-none-eabi-gcc` (14.2.1 was used), `make`, `python3`, `unzip`, `qemu-system-arm` (10.2.1), `gdb-multiarch`, `libglib2.0-dev`, `pkg-config`
- Ubuntu 26.04 LTS under WSL2 was used for building and for the QEMU experiments.

## 1. Python model

    pip install -r ntt_fault_lab/requirements.txt
    cd ntt_fault_lab && python3 experiments.py all    # about 12 minutes

Results are written to `results/*.json` and the figures to `figures/*.pdf`.

## 2. Build the pqm4 variants and run them in QEMU

    git clone --recursive https://github.com/mupq/pqm4.git
    python3 ftcm_pqm4/tools/make_variants.py pqm4
    cd pqm4
    make -j4 PLATFORM=mps2-an386 \
      IMPLEMENTATION_PATH=crypto_kem/ml-kem-768/m4fspeed-ftcm-allu \
      elf/crypto_kem_ml-kem-768_m4fspeed-ftcm-allu_ftbench.elf
    timeout 60 qemu-system-arm -M mps2-an386 -nographic -semihosting \
      -kernel elf/crypto_kem_ml-kem-768_m4fspeed-ftcm-allu_ftbench.elf

Under QEMU only the `FAULT` and `INLINE` lines are meaningful; the `BENCH`
numbers are not cycle counts.

Variants (folder suffix after `m4fspeed`): `-ftcm-c1` (C1), `-ftcm-c2` (C2),
`-ftcm-rats` (RATS, SHA-256), `-ftcm-ratsu` (RATS, universal hash),
`-ftcm-ratsh` (RATS, HMAC-SHA-256), `-ftcm-all` (C1+C2+RATS, SHA-256),
`-ftcm-allu` (C1+C2+RATS, universal hash). See
`ftcm_pqm4/tools/make_variants.py`.

## 3. Cycle counts on the board

Hardware: STM32F4DISCOVERY (STM32F407G-DISC1, rev. MB997D, STM32F407VGT6),
core clock 24 MHz with zero flash wait states (the pqm4 benchmark clock),
cycles read from SysTick.

1. Build the firmware for the board:

        make -j4 PLATFORM=stm32f4discovery \
          IMPLEMENTATION_PATH=crypto_kem/ml-kem-768/m4fspeed-ftcm-allu \
          bin/crypto_kem_ml-kem-768_m4fspeed-ftcm-allu_ftbench.bin

   Use `_speed.bin` instead of `_ftbench.bin` for the KEM-level cycle counts.
2. Flash the `.bin` file with STM32CubeProgrammer over ST-LINK at address `0x08000000`.
3. Connect a 3.3 V USB-to-serial adapter: board PA2 to adapter RX, board PA3 to adapter TX, GND to GND.
4. Open the adapter's COM port in a terminal (we used Hercules SETUP utility 3.2.8) with 38400 baud, 8 data bits, no parity, handshake off.
5. Press the black RESET button. The program prints once and then stops; close the port after the line containing `#`.

`ftbench` prints `BENCH ... min ... avg ...` lines. Subtract the
`empty (timer overhead)` line from each to get net cycles. The `_speed`
programs print `keypair cycles`, `encaps cycles` and `decaps cycles`.

## License

MIT (see `LICENSE`). Files derived from pqm4 or PQClean keep their own licenses.
