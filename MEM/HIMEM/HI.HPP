/* hi.hpp: Header file for HIMEM support code
 * This file is for C++ programmers to include.  The "C" qualifier
 * prevents the C++ compiler from mangling the function name.
 */

extern "C" {

/* Return nonzero if HIMEM is installed */
int far cdecl pinghi(void);

/* Initialize stuff.  Call once before anything else. */
void far cdecl hiinit(void);

/* Allocate extended memory.  Returns handle to memory
 * allocated, or 0 if HIMEM could not allocate it.
 */
unsigned int far cdecl himalloc(unsigned long size);

/* Free extended memory. */
void far cdecl hifree(unsigned int handle);

/* hicontig returns the size of the largest contiguous block of
 * extended memory.  himemavl returns the total extended memory
 * available.
 */
unsigned long far cdecl hicontig(void);
unsigned long far cdecl himemavl(void);

/* hilock locks (write-protects) the given handle.
 * hiunlock unprotects a previously locked handle.
 */
int far cdecl hilock(unsigned handle);
int far cdecl hiunlock(unsigned handle);

/* hi2real copies from extended memory to DOS memory;
 * real2hi copies from DOS memory to extended memory.
 * DOS memory is specified as a normal far pointer.
 * Extended memory is specified as a handle and a 32-bit
 * offset from that handle.
 *
 * Both functions return 1 if successful and 0 if not.
 */
int far cdecl hi2real(void far *dest,
		      unsigned src,
		      unsigned long offset,
		      unsigned count);

int far cdecl real2hi(unsigned dest,
		      unsigned long offset,
		      void far *src,
		      unsigned count);

}	/* extern "C" */
