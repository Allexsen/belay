#include "schema/iflags.h"

#include "capture/fsops.h"      /* belay_iflags_locking */

bool iflags_change_counts(const struct iflags_side *b, const struct iflags_side *a) {
    if (!b->present && !a->present) return false;
    if (!b->present || !a->present) {                               /* IF-3 */
        const struct iflags_side *one = b->present ? b : a;
        return one->has && (one->flags & belay_iflags_locking) != 0;
    }
    if (b->type != a->type)                                         /* IF-4: a type change, as before */
        return b->has != a->has || (b->has && b->flags != a->flags);
    if (!b->has || !a->has) return false;                           /* IF-5 */
    if (b->flags == a->flags) return false;
    if (b->dir && a->dir)                                           /* IF-2 */
        return ((b->flags ^ a->flags) & belay_iflags_locking) != 0;
    return true;                                                    /* IF-4 */
}
