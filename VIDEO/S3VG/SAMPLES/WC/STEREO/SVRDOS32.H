#ifndef _SVRDOS32_H_
#define _SVRDOS32_H_

// Header file for SVRDOS32.LIB v2.1 or later
// SimulEyes VR driver for DOS 32-bit extenders.

/*
 *-----------------------------------------------------------
 * Definitions for all the necessary data types and macros
 *-----------------------------------------------------------
 */

#ifndef NULL
#define NULL                0
#endif

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

#ifndef FAR
#define FAR                 far
#endif

#ifndef NEAR
#define NEAR                near
#endif

#ifndef VOID
#define VOID                void
#endif

#ifndef BOOL
typedef int                 BOOL;
#endif

#ifndef BYTE
typedef unsigned char       BYTE;
#endif

#ifndef WORD
typedef unsigned short      WORD;
#endif

#ifndef DWORD
typedef unsigned long       DWORD;
#endif

/*****
#ifndef PBYTE
typedef unsigned char *     PBYTE;
#endif

#ifndef LPBYTE
typedef unsigned char far * LPBYTE;
#endif
*****/

#define SVRDOS32_VERSION        0x0250

// function result code definitions
#define	SVR_OK		1
#define	SVR_ERROR	0

// video mode definitions for SVRDOS32
// (may be different from definitions for SVRDOS)
#define SVR_320_200     0x13            // 1 page  320x200
#define SVR_320_200_X   0x14            // 4 pages 320x200
#define SVR_320_400_X   0x15            // 2 pages 320x400
#define SVR_320_240_X   0x16            // 2 pages 320x240
#define SVR_320_480_X   0x17            // 1 page  320x480

#define SVR_640_400     0x0100          // 4 pages 640x400
#define SVR_640_480     0x0101          // 2 pages 640x480

#define SVR_TEXT        0x03            // 80x25 text
#define SVR_ORIGINAL    0xFF            // original mode
#define SVR_PREVIOUS    0xFE            // previous mode

#define SVR_LINE_ALT    0x8000          // line-alternate format
#define SVR_HALF_RES    0x4000          // half-resolution format

// left/right stereo image buffer definitions
#define	SVR_LEFT        0               // left eye image
#define	SVR_RIGHT	1               // right eye image
#define SVR_ALT         2               // composite image

/*****
#define LEFT            SVR_LEFT
#define RIGHT           SVR_RIGHT
*****/

/*
 *-------------------------------------------------------
 * data structure definitions
 *-------------------------------------------------------
 */

// identifying information structure for SVRDOS32
typedef struct SVRDos32Info {
    DWORD       hardware_version;   // hardware version
    DWORD       driver_version;     // driver version
    DWORD       video_mode;         // graphics mode
} SVRDos32Info_t;

// options data structure for SVRDOS32 run-time service routine
typedef struct SVRDos32Option {
    DWORD	calls_far;      // SVR function calls near or far ?
    DWORD	pixels_modex;   // pixel data ordering linear or mode-X ?
    DWORD	pixels_width;   // pixel data width gaps in pixel buffer
    DWORD	debug_port;     // port for debugging ISR activity
    DWORD       pal_protect;    // protect palette during video mode set ?
    DWORD	line_alternate; // pixel data linear or line-alternate ?
    DWORD	high_refresh;   // standard video refresh rate or higher ?
    DWORD	lock_flip;      // SVR ISR polls for vertical retrace ?
    DWORD	delay_flip;     // SVR ISR flip delay after vertical retrace
    DWORD	fast_intr;      // SVR ISR interrupt rate doubler
    DWORD       chipset_support;// support special hardware chipset
} SVRDos32Option_t;

/*
 *-----------------------------------------------------------
 * External procedure definitions
 *-----------------------------------------------------------
 */

#ifdef __cplusplus
extern "C" {
#endif

int SVRDos32Init (void);
int SVRDos32Exit (void);
int SVRDos32SetMode (WORD mode);
int SVRDos32GetMode (void);
int SVRDos32GetInfo (SVRDos32Info_t far * lpInfo);
int SVRDos32SetImage (BOOL eye, WORD x0, WORD y0, WORD xd, WORD yd, unsigned char far * buf);
int SVRDos32GetImage (BOOL eye, WORD x0, WORD y0, WORD xd, WORD yd, unsigned char far * buf);
int SVRDos32GetRegistration (void);
int SVRDos32SetRegistration (int active);
int SVRDos32SetBlackCode (BYTE color);
int SVRDos32SetWhiteCode (BYTE color);
int SVRDos32Sync (void);
int SVRDos32SetOptions (SVRDos32Option_t far * lpOptions);
int SVRDos32GetOptions (SVRDos32Option_t far * lpOptions);
int SVRDos32ShowImages (void);
int SVRDos32ClearImages (void);
int SVRDos32SetFlip (int active, unsigned long mode);
int SVRDos32UpdateFlip (unsigned char * left, unsigned char * right);
int SVRDos32SetCallback (void far * lpCallback);

#ifdef __cplusplus
}
#endif

#endif
