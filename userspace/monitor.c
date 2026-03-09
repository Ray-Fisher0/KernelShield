// monitor.c — polls /proc/rootkit_alerts and prints new entries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROC_PATH "/proc/rootkit_alerts"
#define POLL_SEC  3

int main(void)
{
    char prev[8192] = {0};
    printf("Rootkit Alert Monitor — watching %s\n", PROC_PATH);
    printf("Press Ctrl+C to stop.\n\n");

    while (1) {
        FILE *f = fopen(PROC_PATH, "r");
        if (!f) { perror("fopen"); sleep(POLL_SEC); continue; }

        char cur[8192] = {0};
        fread(cur, 1, sizeof(cur) - 1, f);
        fclose(f);

        if (strcmp(cur, prev) != 0) {
            printf("=== ALERT UPDATE ===\n%s\n", cur);
            strncpy(prev, cur, sizeof(prev) - 1);
        }
        sleep(POLL_SEC);
    }
    return 0;
}