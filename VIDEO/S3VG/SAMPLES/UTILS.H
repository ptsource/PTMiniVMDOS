/*==========================================================================
 *
 * Copyright (C) 1996 S3 Incorporated. All Rights Reserved.
 *
 ***************************************************************************/

#ifndef UTILS_H
#define UTILS_H

#ifdef	WIN32
/* comment this line if you are not using DirectDraw */
#define	USEDIRECTDRAW
#endif

#define UP          (0x48 | 0x80)
#define DOWN        (0x50 | 0x80)
#define LEFT        (0x4b | 0x80)
#define RIGHT       (0x4d | 0x80)
#define PGUP        (0x49 | 0x80)
#define PGDN        (0x51 | 0x80)
#define HOME        (0x47 | 0x80)
#define END         (0x4f | 0x80)
#define ESC         0x1b

#ifndef WIN32
#include "S3TYPE.H"
#else
#include <windows.h>
#ifdef	USEDIRECTDRAW
#include "ddraw.h"
#endif
#endif
#include "..\\h\\S3DTK.H"

#ifdef __cplusplus
extern "C" {
#endif


/***************************************************************************
 * 
 *  Memory management routines
 *
 ***************************************************************************/
ULONG linearToPhysical(ULONG linear);
void allocInit(S3DTK_LPFUNCTIONLIST pS3DTK_Funct);
#ifdef	USEDIRECTDRAW
BOOL allocSurf(S3DTK_SURFACE *surf, LPDIRECTDRAWSURFACE *lplpDDS, ULONG width, ULONG height, ULONG bpp, ULONG format);
#else
BOOL allocSurf(S3DTK_SURFACE *surf, ULONG width, ULONG height, ULONG bpp, ULONG format);
#endif


/***************************************************************************
 * 
 *  BMP Loading utilities
 *
 ***************************************************************************/
int BMP_Open(char *filename, char *palette, ULONG *width, ULONG *height, ULONG *byteperpixel);
void BMP_Close(int bmpfile);
int BMP_Readline(int bmpfile, unsigned char *ptr, ULONG width);
void BMP_Convert(ULONG         width,
                 ULONG         wDestBytePerPixel,
                 unsigned char *bufptr,
                 RGBQUAD       *palette,
                 unsigned char *outbuf,
                 ULONG         wSrcBytePerPixel);
#ifdef	USEDIRECTDRAW
BOOL bmpLoadSurface(S3DTK_SURFACE *surf, LPDIRECTDRAWSURFACE *lplpDDS, const char *theFilename, ULONG theBpp, ULONG theFormat);
#else
BOOL bmpLoadSurface(S3DTK_SURFACE *surf, const char *theFilename, ULONG theBpp, ULONG theFormat);
#endif


/***************************************************************************
 * 
 *  S3d Texture Loading utilities
 *
 ***************************************************************************/
int TextureOpen(char *filename, ULONG *width, ULONG *height, ULONG *bpp, ULONG *level, ULONG *format);
void TextureClose(int bmpfile);
int TextureReadline(int bmpfile, unsigned char *ptr, ULONG width);
#ifdef	USEDIRECTDRAW
BOOL LoadTexture(S3DTK_SURFACE *surf, LPDIRECTDRAWSURFACE *lplpDDS, char *theFilename, ULONG *levels);
#else
BOOL LoadTexture(S3DTK_SURFACE *surf, char *theFilename, ULONG *levels);
#endif
ULONG getTextureBpp(S3DTK_SURFACE *surf);
ULONG getNonTextureBpp(S3DTK_SURFACE *surf);


/***************************************************************************
 * 
 *  Misc. utilities
 *
 ***************************************************************************/
int getKey(void);
int getScreenWidth(unsigned int wMode);
int getScreenHeight(unsigned int wMode);
int getScreenBpp(unsigned int wMode);


#ifdef __cplusplus
};
#endif

#endif


