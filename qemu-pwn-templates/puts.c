#pragma once
#include <unistd.h>
#include <stddef.h>

void puts(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    write(1, s, len);
}
