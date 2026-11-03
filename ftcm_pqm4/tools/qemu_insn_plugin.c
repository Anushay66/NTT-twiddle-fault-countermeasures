/*
 * qemu_insn_plugin.c -- count guest instructions executed between two marker
 * functions (ftcm_mark_begin / ftcm_mark_end in ftbench.c).
 *
 * Build (QEMU 8.x headers):
 *   gcc -shared -fPIC -O2 $(pkg-config --cflags glib-2.0) -I. \
 *       -o libftcminsn.so qemu_insn_plugin.c
 * Run:
 *   B=$(arm-none-eabi-nm ftbench.elf | awk '/ ftcm_mark_begin$/{print $1}')
 *   E=$(arm-none-eabi-nm ftbench.elf | awk '/ ftcm_mark_end$/{print $1}')
 *   qemu-system-arm -M mps2-an386 -nographic -semihosting \
 *      -plugin ./libftcminsn.so,begin=0x$B,end=0x$E -d plugin -kernel ftbench.elf
 * Each measured region prints "REGION <instructions>".  Instruction counts are
 * NOT cycle counts; on Cortex-M4 most data-processing instructions take one
 * cycle but loads, multi-register transfers and taken branches take more.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "qemu-plugin.h"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t count;
static uint64_t start;
static uint64_t begin_addr, end_addr, toggle_addr, last;

static void on_begin(unsigned int vcpu, void *u) { start = count; }
static void on_end(unsigned int vcpu, void *u) {
    char buf[64];
    snprintf(buf, sizeof(buf), "REGION %" PRIu64 "\n", count - start);
    qemu_plugin_outs(buf);
}

/* toggle mode: print the instruction count since the previous hit of the
 * marker address (used with toggle=<hal_get_time> on pqm4's speed.c) */
static void on_toggle(unsigned int vcpu, void *u) {
    char buf[64];
    snprintf(buf, sizeof(buf), "DELTA %" PRIu64 "\n", count - last);
    qemu_plugin_outs(buf);
    last = count;
}

static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t va = qemu_plugin_insn_vaddr(insn);
        if (va == begin_addr) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, on_begin, QEMU_PLUGIN_CB_NO_REGS, NULL);
        }
        if (toggle_addr && va == toggle_addr) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, on_toggle, QEMU_PLUGIN_CB_NO_REGS, NULL);
        }
        if (va == end_addr) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, on_end, QEMU_PLUGIN_CB_NO_REGS, NULL);
        }
        qemu_plugin_register_vcpu_insn_exec_inline(insn, QEMU_PLUGIN_INLINE_ADD_U64, &count, 1);
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "begin=", 6) == 0) begin_addr = strtoull(argv[i] + 6, NULL, 0) & ~1ull;
        if (strncmp(argv[i], "end=", 4) == 0) end_addr = strtoull(argv[i] + 4, NULL, 0) & ~1ull;
        if (strncmp(argv[i], "toggle=", 7) == 0) toggle_addr = strtoull(argv[i] + 7, NULL, 0) & ~1ull;
    }
    if (!(begin_addr && end_addr) && !toggle_addr) {
        fprintf(stderr, "ftcm plugin: need begin=/end= or toggle= addresses\n");
        return -1;
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans);
    return 0;
}
