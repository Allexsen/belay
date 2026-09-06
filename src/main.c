#define _GNU_SOURCE
#include "session.h"
#include "fork.h"

#include <limits.h>

int main (int argc, char *argv[]) {
    char curr_sesh_dir[PATH_MAX];
    if (construct_sesh_dir(curr_sesh_dir, sizeof curr_sesh_dir) == -1) {
        return 1;
    }
    
    if (create_sesh_layout(curr_sesh_dir) == -1) {
        return 1;
    }

    int rcode = forkp(curr_sesh_dir);
    if (rcode != 0)
        return rcode;

    return 0;
}