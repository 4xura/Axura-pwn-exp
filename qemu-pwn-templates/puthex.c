#pragma once
#include <unistd.h>

void puthex(size_t val) {
    char buf[17];
    const char *hex = "0123456789abcdef";

    for (int i = 15; i >= 0; --i) {
        buf[i] = hex[val & 0xF];
        val >>= 4;
    }
    write(1, buf, 16);
}
