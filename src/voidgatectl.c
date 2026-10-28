
/* SPDX-License-Identifier: Apache-2.0 */

#include "bpf/voidgate.h"

#include <sw/sock.h>

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


/* bounds connect() too: a voidgate that never accepts or answers */
#define VG_CTL_TIMEOUT_MS  5000


int
main(int argc, char **argv)
{
    char cmd[256], buf[8192], err[256];
    int fd, i, failed = 0, replied = 0;
    ssize_t n;

    if (argc < 2) {
        fprintf(stderr, "usage: voidgatectl status|stats|drops|arm|"
                "disarm|drop <cidr> [ttl=<sec>]|undrop <cidr>|reload\n");
        return 1;
    }

    cmd[0] = 0;

    for (i = 1; i < argc; i++) {
        if (i > 1) {
            strncat(cmd, " ", sizeof(cmd) - strlen(cmd) - 1);
        }

        strncat(cmd, argv[i], sizeof(cmd) - strlen(cmd) - 1);
    }

    strncat(cmd, "\n", sizeof(cmd) - strlen(cmd) - 1);

    fd = sw_sock_connect(VG_SOCK_PATH, VG_CTL_TIMEOUT_MS, err, sizeof(err));

    if (fd < 0) {
        fprintf(stderr, "voidgatectl: %s\n", err);
        return 1;
    }

    if (sw_sock_send_all(fd, cmd, strlen(cmd)) < 0) {
        perror("voidgatectl: send");
        close(fd);
        return 1;
    }

    shutdown(fd, SHUT_WR);
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = 0;

        /* Scripts need a refused command to fail. */
        if (!replied && strncmp(buf, "error", 5) == 0) {
            failed = 1;
        }

        replied = 1;
        fputs(buf, stdout);
    }
    close(fd);

    return failed || !replied;
}
