/* testhi.c: test program for Extended Memory Interface Library
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "hi.h"

main()
{
  int i;
  unsigned int hand;
  long cnt;
  long test;
  printf("Testing interface library...\n\n");

  if (! pinghi()) {
    fprintf(stderr, "HIMEM not installed.\n");
    exit(1);
  }
  /* Initialize library */
  hiinit();

  /* Report contiguous and total amount of memory available */
  printf("%lu contiguous bytes available\n", hicontig());
  printf("%lu bytes available\n", himemavl());

  /* Allocate 4K of extended memory */
  hand = himalloc(1024L * sizeof(long));
  if (! hand) {
    printf("Memory not available\n");
    exit(-1);
  }

  /* Count to 1024, putting the counts into extended memory */
  for (cnt = 0; cnt < 1024L; cnt++) {
    int ret = real2hi(hand, cnt << 2, &cnt, sizeof(long));
    if (! ret) {
      printf("real2hi returned 0 at cnt = %d\n", cnt);
      exit(1);
    }
  }

  /* Read the counts back from extended memory, verifying */
  /* that they agree with what was put there */
  for (cnt = 0; cnt < 1024L; cnt++) {
    int ret = hi2real(&test, hand, cnt << 2, sizeof(long));
    if (! ret) {
      printf("hi2real returned 0 at cnt = %d\n", cnt);
      exit(1);
    }
    if (cnt != test)
      printf("No good at cnt = %ld, test = %ld\n", cnt, test);
  }

  /* Free the extended memory */
  hifree(hand);

  printf("Extended Memory Interface Library tested okay\n");
  return 0;
}
