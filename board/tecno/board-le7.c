//
// SPDX-FileCopyrightText: 2026 Your name <your.email@example.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
#define VOLUME_DOWN 17

#include <board_ops.h>

void spoof_lock_state(void) {
    uint32_t addr = 0;
// When we spoof the lock state to appear "locked", fastboot starts rejecting 
    // commands with "not support on security" and "not allowed in locked state" 
    // errors. This is annoying since the device is actually unlocked underneath, 
    // the security checks are just being overly paranoid.
    //
    // This patch removes both security gates so fastboot commands work regardless
    // of what the spoofed lock state reports.
//0x4c426814
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x4FF0, 0xB0A7, 0xAA1C);
    if (addr) {
        printf("Found fastboot command processor at 0x%08X\n", addr);
        
        // NOP the error message calls
        NOP(addr + 0x6B8, 2);  // "not support on security" call   //0x4c426ecc
        NOP(addr + 0x6F8, 2);  // "not allowed in locked state" call  //4c426f0c
        
        // Jump directly to command handler
        PATCH_MEM(addr + 0x14A,
            0xE00B, // b 0x4c42cf9c
            0xBF00  // nop
        );
    }
   int spoofing = is_spoofing_enabled();
   fastboot_publish("is-spoofing", spoofing ? "1" : "0");

    if (!spoofing) {
        printf("Bootloader lock status spoofing disabled.\n");
        return;
    }
   // AVB adds device state info to the kernel cmdline, but it keeps showing
     // "unlocked" even when we want it to say "locked". This patch forces
    // the cmdline to always use the "locked" string instead of checking
    // the actual device state.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x4FF0, 0x4691, 0xF102);
    if (addr) {
        printf("Found AVB cmdline function at 0x%08X\n", addr);
       
        // Find where in libavb the device state is first fetched and then stored,
        // then Nop out the code that checks the actual device state.
        // This forces libavb to always use the "locked" string.
        NOP(addr + 0x9C, 4);
    }
    printf("Bootloader lock status spoofing enabled, applying patches.\n");

    // Need to spoof the LKS_STATE as "locked" for certain scenarios, but still
    // return success so other parts of the system don't freak out. This makes
    // seccfg_get_lock_state always report lock_state=1 and return 2.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB1D0, 0xB510, 0x4604, 0xF7FF, 0xFFDD);
    if (addr) {
        printf("Found seccfg_get_lock_state at 0x%08X\n", addr);
        PATCH_MEM(addr + 6, 
            0x2301,  // movs r3, #1
            0x6023,  // str r3, [r4, #0]
            0x2002,  // movs r0, #2
            0xbd10   // pop {r4, pc}
        );
    }
    // Force the secure boot state to ATTR_SBOOT_ENABLE (0x11). This controls whether
    // secure boot verification is enabled and is separate from the LKS_STATE above.
    // Setting it to 0x11 indicates secure boot is properly enabled.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB510, 0x4604, 0x2001, 0xF7FF);
    if (addr) {
        printf("Found get_sboot_state at 0x%08X\n", addr);
        PATCH_MEM(addr,
            0x2311,  // movs r3, #0x11   - set value to 0x11
            0x6003,  // str r3, [r0,#0]  - store to *param_1
            0x2000,  // movs r0, #0      - return 0
            0x4770   // bx lr            - return
        );
    }


}

void board_early_init(void) {
    printf("Entering early init for tecno pova 2\n");
    uint32_t addr = 0;
    // Regardless of whether spoofing is enabled, we always need to
    // disable image authentication. The user may just be using this
    // custom LK to unlock their device, or they may be spoofing
    // where the locked state would enforce verification.
    //
    // Forcing get_vfy_policy to return 0 skips certificate
    // verification for all partitions and firmware images (boot,
    // recovery, dtbo, SCP, etc.) so the device can boot with
    // modified or unsigned images.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF, 0xFF75, 0xF3C0);
    if (addr) {
        printf("Found get_vfy_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
    // Same idea but for download policy, forcing get_dl_policy to return
    // 0 ensures no partition is marked as download-forbidden, so flashing
    // via fastboot works for all partitions.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB508, 0xF7FF, 0xFF6f, 0xF000);
    if (addr) {
        printf("Found get_dl_policy at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
    // The environment area isn't initialized yet when board_early_init
    // runs, so any get_env calls would return NULL at this stage. We
    // hook a printf call in platform_init that runs right after env
    // initialization completes, it's a convenient entry point since
    // the call itself is non-essential and we need the env to be ready
    // before applying our lock state patches.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xF02F, 0xFDB2, 0xFFC5, 0xF7FD);
    if (addr) {
        printf("Found env_init_done at 0x%08X\n", addr);
        PATCH_CALL(addr, (void*)spoof_lock_state, TARGET_THUMB);
    }

    // When we spoof the lock state to appear "locked", fastboot starts rejecting 
    // commands with "not support on security" and "not allowed in locked state" 
    // errors. This is annoying since the device is actually unlocked underneath, 
    // the security checks are just being overly paranoid.
    //
    // This patch removes both security gates so fastboot commands work regardless
    // of what the spoofed lock state reports.
//0x4c426814
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xE92D, 0x4FF0, 0xB0A7, 0xAA1C);
    if (addr) {
        printf("Found fastboot command processor at 0x%08X\n", addr);
        
        // NOP the error message calls
        NOP(addr + 0x6B8, 2);  // "not support on security" call   //0x4c426ecc ok
        NOP(addr + 0x6F8, 2);  // "not allowed in locked state" call  //4c426f0c ok
        
        // Jump directly to command handler
        PATCH_MEM(addr + 0x14A, //  4C42695E ok
            0xE006 // b 4C43481A maybe ok
           // 0xBF00  // nop wtf is this?
        );
    }

    fastboot_register("oem bldr_spoof", cmd_spoof_bootloader_lock, 0);
}

void board_late_init(void) {
    printf("Entering late init for tecno pova 2\n");
    uint32_t addr = 0;

    // Suppresses the bootloader unlock warning shown during boot on
    // unlocked devices. In addition to the visual warning, it also
    // introduces an unnecessary 5-second delay.
    // 
    // This patch get rid of the delay and the warning by forcing the
    // function that holds the logic to always return 0 and therefore
    // not executing the code that shows the warning.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0xB510, 0xB082, 0x4C07, 0X4670, 0XF240);
    if (addr) {
        printf("Found orange_state_warning at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
    // Disables the dm-verity corruption warning shown during boot when
    // the device is unlocked. Without this patch, the user gets a scary
    // "Your device is corrupt" screen that waits for a power button
    // press and powers off after 5 seconds if ignored.
    addr = SEARCH_PATTERN(LK_START, LK_END, 0x2802, 0xD000, 0x4770, 0xB538);
    if (addr) {
        printf("Found dm_verity_corruption at 0x%08X\n", addr);
        FORCE_RETURN(addr, 0);
    }
    // - Volume down → Fastboot
    if (mtk_detect_key(VOLUME_DOWN)) {
        set_bootmode(BOOTMODE_FASTBOOT);
	show_bootmode(BOOTMODE_FASTBOOT);
    }

}
