#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <assert.h>

int main() {
    uid_t uid1, uid2;

    // 1. Call getuid() twice — should be consistent
    uid1 = getuid();
    uid2 = getuid();
    assert(uid1 == uid2);

    // 2. UID should be non-negative
    assert(uid1 >= 0);

    // 3. Compare with geteuid() in normal (non-setuid) case
    uid_t euid = geteuid();
    if (uid1 != euid) {
        printf("Note: real UID (%d) != effective UID (%d) (setuid context?)\n",
               uid1, euid);
    }

    printf("getuid() test passed (uid=%d)\n", uid1);
    return 0;
}
