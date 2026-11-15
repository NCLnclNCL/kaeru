//
// SPDX-FileCopyrightText: 2026 Your name <nanvanu@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
//

#include <board_ops.h>

#define VOLUME_UP 17
#define VOLUME_DOWN 1
#define POWER_KEY 8

void board_early_init(void) {
    printf("Entering early init for rmx2176\n");
    FORCE_RETURN(0x4c47a8ac, 0);
    dprintf("unlock_verify_ok Patched\n");
    FORCE_RETURN(0x4c4568c0, 0);
    dprintf("Orange_State Patched\n");
    // - Volume Up → Recovery
    // - Volume Down → Fastboot
    if (mtk_detect_key(VOLUME_UP)) {
        set_bootmode(BOOTMODE_RECOVERY);
    } else if (mtk_detect_key(VOLUME_DOWN)) {
        set_bootmode(BOOTMODE_FASTBOOT);
    }
}

void board_late_init(void) {
    printf("Entering late init for rmx2176\n");


 show_bootmode(get_bootmode());
}
