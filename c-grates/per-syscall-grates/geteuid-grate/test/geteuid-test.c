#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <assert.h>

int main() {
    uid_t euid1, euid2;

    // 1. Multiple calls should be consistent
    euid1 = geteuid();
    euid2 = geteuid();
    assert(euid1 == euid2);

    // 2. EUID should be non-negative
    assert(euid1 >= 0);

    // 3. Save original IDs
    uid_t ruid = getuid();
    uid_t orig_euid = euid1;

    // 4. Try changing effective UID (may fail if not permitted)
    if (seteuid(ruid) == 0) {
        uid_t new_euid = geteuid();
        assert(new_euid == ruid);

        // Restore original effective UID
        int ret = seteuid(orig_euid);
        assert(ret == 0);

        // Verify restoration
        assert(geteuid() == orig_euid);
    } else {
        // If we can't change EUID, just note it
        printf("Skipping seteuid() test (insufficient permissions)\n");
    }

    printf("geteuid() test passed (euid=%d)\n", orig_euid);
    return 0;
}
