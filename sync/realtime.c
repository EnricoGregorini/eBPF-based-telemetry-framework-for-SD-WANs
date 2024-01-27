#include <stdio.h>
#include <time.h>

int main() {
    struct timespec ts;
    double mn_ts = 0;
    clock_gettime(CLOCK_REALTIME, &ts);
    mn_ts = ts.tv_sec + (double)(ts.tv_nsec/1e9);
    printf("REALTIME_CLOCK: %f\n", mn_ts);
    return mn_ts;
}
