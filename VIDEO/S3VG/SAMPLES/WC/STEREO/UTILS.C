/*==========================================================================
 *
 * Copyright (C) 1996 S3 Incorporated. All Rights Reserved.
 *
 ***************************************************************************/

#include <stdio.h>
#include <conio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <io.h>
#ifdef __GNUC__
#include <unistd.h>
#endif

#include "utils.h"


#ifdef USEDIRECTDRAW
extern LPDIRECTDRAW     lpDD;           /* DirectDraw object                        */
extern HRESULT          ddrval;         /* Holds result of DD calls                 */
#endif

/***************************************************************************
 * 
 *  Memory management routines
 *
 ***************************************************************************/

#ifndef USEDIRECTDRAW
ULONG totalMemory;                  /* frame buffer size                           */
ULONG memoryUsed;                   /* frame buffer allocated                      */
#endif
char *frameBufferLinear;            /* linear address of frame buffer starts at    */
ULONG frameBufferPhysical;          /* physical address of frame buffer starts at  */

ULONG linearToPhysical(ULONG linear)
{
    ULONG low12bits;
    low12bits = linear & 0x00000fff;
    return(S3DTK_LinearToPhysical(linear & 0xfffff000) + low12bits);
}

void allocInit(S3DTK_LPFUNCTIONLIST pS3DTK_Funct)
{
#ifndef USEDIRECTDRAW
    memoryUsed = 0;
    /* find out the frame buffer size */
    pS3DTK_Funct->S3DTK_GetState(pS3DTK_Funct, S3DTK_VIDEOMEMORYSIZE, (ULONG)(&totalMemory));
#endif
    /* find out where the frame buffer is located, this is the linear address */
    pS3DTK_Funct->S3DTK_GetState(pS3DTK_Funct, S3DTK_VIDEOMEMORYADDRESS, (ULONG)(&frameBufferLinear));
    /* this is the physical address */
    frameBufferPhysical = linearToPhysical((ULONG)frameBufferLinear);
}

#ifdef  USEDIRECTDRAW
BOOL allocSurf(S3DTK_SURFACE *surf, LPDIRECTDRAWSURFACE *lplpDDS, ULONG width, ULONG height, ULONG bpp, ULONG format)
{
    DDSURFACEDESC       ddsd;
    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS | 
                   DDSD_HEIGHT | 
                   DDSD_WIDTH;

    surf->sfWidth = width;                          /* surface's width                         */
    surf->sfHeight = height;                        /* surface's height                        */
    surf->sfFormat = format;                        /* surface's format                        */
    if (format & S3DTK_SYSTEM)
     {  /* allocate surface in system memory */
        ddsd.ddsCaps.dwCaps = DDSCAPS_SYSTEMMEMORY;
     }
    else
     {  /* allocate surface in video memory */
        ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_VIDEOMEMORY;
     }
    ddsd.dwHeight =height;
    ddsd.dwWidth = width;
    ddrval = lpDD->lpVtbl->CreateSurface(lpDD, &ddsd, lplpDDS, NULL);
    if( ddrval != DD_OK )
        return(FALSE);
    (*lplpDDS)->lpVtbl->Lock(*lplpDDS, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
    (*lplpDDS)->lpVtbl->Unlock(*lplpDDS, NULL);
    if (format & S3DTK_SYSTEM)
     {  // linear address of surface
        surf->sfOffset = (ULONG)ddsd.lpSurface; 
     }
    else
     {  // offset of surface in frame buffer
        surf->sfOffset = linearToPhysical((ULONG)ddsd.lpSurface) - frameBufferPhysical; 
     }
    return(TRUE);
}
#else   /* not define USEDIRECTDRAW */
BOOL allocSurf(S3DTK_SURFACE *surf, ULONG width, ULONG height, ULONG bpp, ULONG format)
{
    ULONG bufsize;
    bufsize = ((width * bpp + 7) & 0xfffffff8);     /* make sure the line is quad word aligned */
    bufsize = bufsize * height;                     /* so bufsize should be quad word aligned  */ 
    surf->sfWidth = width;                          /* surface's width                         */
    surf->sfHeight = height;                        /* surface's height                        */
    surf->sfFormat = format;                        /* surface's format                        */
    if (format & S3DTK_SYSTEM)
     {  /* allocate surface in system memory */
        if ((surf->sfOffset = (ULONG)malloc(bufsize)) == NULL)
         {
            printf("error : Allocating system memory of %dx%dx%d\n", 
                            (int)width, (int)height, (int)bpp);
            return(FALSE);
         }
     }
    else
     {  /* allocate surface in video memory */
        if (memoryUsed + bufsize > totalMemory)
         {
             printf("error : Allocating video memory of %dx%dx%d\n",
                            (int)width, (int)height, (int)bpp);
             return(FALSE);
         }
        surf->sfOffset = memoryUsed;
        memoryUsed += bufsize;
     }
    return(TRUE);
}
#endif  /* not define USEDIRECTDRAW */


/***************************************************************************
 * 
 *  BMP Loading utilities
 *
 ***************************************************************************/

#define USE1555                     /* define 16 bit color format */

/*
 * Open the bitmap file and return the properties of the bitmap
 * If file is successfully opened, the file pointer is pointed to the beginning
 * of the bitmap in the file.
 */
int BMP_Open(char *filename, char *palette, ULONG *width, ULONG *height, ULONG *byteperpixel)
{
    int bmpfile;
    BITMAPFILEHEADER bmpfilehdr;
    BITMAPINFOHEADER bmpinfohdr;
    
    if ((bmpfile = open(filename, O_BINARY | O_RDONLY)) == -1)
        return(-1);              /* error */

#ifdef __GNUC__
    /* need special handling for structures in __GNUC__ */
    if (read(bmpfile, &(bmpfilehdr.bfType), sizeof(WORD)) != sizeof(WORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpfilehdr.bfSize), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpfilehdr.bfReserved1), sizeof(WORD)) != sizeof(WORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpfilehdr.bfReserved2), sizeof(WORD)) != sizeof(WORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpfilehdr.bfOffBits), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
#else
    if (read(bmpfile, &bmpfilehdr, sizeof(BITMAPFILEHEADER)) != sizeof(BITMAPFILEHEADER))
     {
        close(bmpfile);
        return(-1);
     }            
#endif

#ifdef __GNUC__
    /* need special handling for structures in __GNUC__ */
    if (read(bmpfile, &(bmpinfohdr.biSize), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biWidth), sizeof(LONG)) != sizeof(LONG))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biHeight), sizeof(LONG)) != sizeof(LONG))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biPlanes), sizeof(WORD)) != sizeof(WORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biBitCount), sizeof(WORD)) != sizeof(WORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biCompression), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biSizeImage), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biXPelsPerMeter), sizeof(LONG)) != sizeof(LONG))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biYPelsPerMeter), sizeof(LONG)) != sizeof(LONG))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biClrUsed), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biClrImportant), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
#else
    if (read(bmpfile, &bmpinfohdr, sizeof(BITMAPINFOHEADER)) != sizeof(BITMAPINFOHEADER))
     {
        close(bmpfile);
        return(-1);
     }
#endif

    if ((bmpinfohdr.biBitCount != 8 &&
        bmpinfohdr.biBitCount != 24) ||
        bmpinfohdr.biCompression != 0)
     {
         close(bmpfile);
         return(-1);
     }

    *height = bmpinfohdr.biHeight;
    *width = bmpinfohdr.biWidth;
    *byteperpixel = bmpinfohdr.biBitCount / 8;
    
    if (*byteperpixel == 1)                             /* 8 bits per pixel */
     {
        if (read(bmpfile, palette, 1024) != 1024)       /* need to read the palette */
         {
             close(bmpfile);
             return(-1);
         }
     }

    lseek(bmpfile, bmpfilehdr.bfOffBits, SEEK_SET);

    return(bmpfile);
}

void BMP_Close(int bmpfile)
{
    if (bmpfile != -1)
        close(bmpfile);
}

/*
 * Read one line of pixels from the current file pointer
 */
int BMP_Readline(int bmpfile, unsigned char *ptr, ULONG width)
{
    if (read(bmpfile, (char*)ptr, width) != (long)width)
        return(0);
    else
     {
        width = width % 4;
        if (width)  
         {
            char tempbuf[4];
            read(bmpfile, tempbuf, 4-width);
         }
        return(1);
     }
}

/*
 * Convert a line of pixels from the source format to the required format
 */
void BMP_Convert(ULONG         width,
                 ULONG         wDestBytePerPixel,
                 unsigned char *bufptr,
                 RGBQUAD       *palette,
                 unsigned char *outbuf,
                 ULONG         wSrcBytePerPixel)
{
    ULONG x;
    if (wDestBytePerPixel != 1)
     {
        for (x=0; x<width; x++)
         {
            unsigned char R, G, B;
            if (wSrcBytePerPixel == 1)
             {
                WORD palIndex;
                palIndex = (WORD)(*bufptr);
                B = palette[palIndex].rgbBlue;
                G = palette[palIndex].rgbGreen;
                R = palette[palIndex].rgbRed;
                bufptr++;
             }
            else        /* it must be 24 bits per pixel */
             {
                B = *bufptr++;
                G = *bufptr++;
                R = *bufptr++;
             }

            switch (wDestBytePerPixel)
             {
#ifdef USE1555
                case 2 :        /* 16 bits (555) */
                    if (R & 0x07 > 3 && R & 0xF8 != 0xF8)
                        R = R + 4;
                    if (G & 0x07 > 3 && G & 0xF8 != 0xF8)
                        G = G + 4;
                    if (B & 0x07 > 3 && B & 0xF8 != 0xF8)
                        B = B + 4;
                    *outbuf++ = (B >> 3) + ((G & 0x38) << 2);
                    *outbuf++ = (G >> 6) + ((R & 0xF8) >> 1);
                    break;
#else
                case 2 :        /* 16 bits (565) */
                    if (R & 0x07 > 3 && R & 0xF8 != 0xF8)
                        R = R + 4;
                    if (G & 0x03 > 1 && G & 0xFC != 0xFC)
                        G = G + 2;
                    if (B & 0x07 > 3 && B & 0xF8 != 0xF8)
                        B = B + 4;
                    *outbuf++ = (B >> 3) + ((G & 0x1C) << 3);
                    *outbuf++ = (G >> 5) + (R & 0xF8);
                    break;
#endif
                case 3 :        /* 24 bits */
                    *outbuf++ = B;
                    *outbuf++ = G;
                    *outbuf++ = R;
                    break;
                case 4 :        /* 32 bits */
                    *outbuf++ = B;
                    *outbuf++ = G;
                    *outbuf++ = R;
                    *outbuf++ = 0;
                    break;
                default :
                    break;
             }
         }
     }
    else
     {
        for (x=0; x<width; x++)
         {
            *outbuf++ = *bufptr++;
         }
     }
}

/*
 * Load the surface with a bitmap file.  The surface will be created with
 * the size of the bitmap, the specified bpp and the specified format.
 * The format has a flag specifying whether the surface should be created
 * in system memory (S3DTK_SYSTEM) or in video memory (S3DTK_VIDEO).
 */
#ifdef  USEDIRECTDRAW
BOOL bmpLoadSurface(S3DTK_SURFACE *surf, LPDIRECTDRAWSURFACE *lplpDDS, const char *theFilename, ULONG theBpp, ULONG theFormat) 
#else
BOOL bmpLoadSurface(S3DTK_SURFACE *surf, const char *theFilename, ULONG theBpp, ULONG theFormat) 
#endif
{
/* This function loads the bitmap file into the specified surface.            */
    ULONG theWidth, theHeight, theSrcBPP, theSrcBPL, theDstBPP, theDstBPL, stride;
    char thePalette[256*4];
    char *theRawImage;          /* Holds raw bitmap data               */
    char *theImage;             /* Holds bitmap data of desired format */
    char *theBits;              /* pointer pointing to the surface     */
    int theFile;
    int i;
#ifdef  USEDIRECTDRAW
    DDSURFACEDESC       ddsd;
#endif

    if (theBpp < 1 || theBpp > 4)
        return FALSE;
    theFile = BMP_Open((char*)theFilename, (char*)thePalette, &theWidth, &theHeight, &theSrcBPP);
    if (theFile == -1)
     {
        BMP_Close(theFile);
        return FALSE;
     }
    /* cannot convert RGB to indexed color */
    if (theBpp == 1 && theSrcBPP != 1)
     {
        BMP_Close(theFile);
        return FALSE;
     }
    /* allocate surface */
#ifdef  USEDIRECTDRAW
    if (!allocSurf(surf, lplpDDS, theWidth, theHeight, theBpp, theFormat))
#else
    if (!allocSurf(surf, theWidth, theHeight, theBpp, theFormat))
#endif
     {
        BMP_Close(theFile);
        return FALSE;
     }
    /* allocate buffer for one line of raw pixels */
    theSrcBPL = theWidth * theSrcBPP;
    theRawImage = (unsigned char *)malloc(theSrcBPL);
    if (theRawImage == NULL)
        return FALSE;
    /* allocate buffer for one line of pixels of required format */
    theDstBPP = theBpp;
    theDstBPL = theWidth * theDstBPP;
    theImage = (unsigned char *)malloc(theDstBPL);
    if (theImage == NULL)
        return FALSE;                                                                   
    /* Read the image bits and copy to the surface */
#ifdef  USEDIRECTDRAW
    ddsd.dwSize = sizeof(ddsd);
    (*lplpDDS)->lpVtbl->Lock(*lplpDDS, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
    stride = (ULONG)ddsd.lPitch;
    theBits = (LPSTR)((DWORD)(ddsd.lpSurface) + (theHeight - 1) * stride);
#else
    stride = (theDstBPL + 7) & 0xfffffff8;      /* make sure stride is quad word aligned */
    if (theFormat & S3DTK_SYSTEM)
        theBits = (char *)(surf->sfOffset + (theHeight-1) * stride);
    else
        theBits = frameBufferLinear + surf->sfOffset + (theHeight-1) * stride;
#endif
    for (i = 0; i < (int)theHeight; i++)
     {
        BMP_Readline(theFile, theRawImage, theSrcBPL);
        BMP_Convert(theWidth, theDstBPP, theRawImage, (RGBQUAD *)thePalette, theImage, theSrcBPP);
        memcpy(theBits, theImage, theDstBPL);
        theBits = theBits - stride;
     }
#ifdef  USEDIRECTDRAW
    (*lplpDDS)->lpVtbl->Unlock(*lplpDDS, NULL);
#endif
    BMP_Close(theFile);
    /*
    if (theDstBPP == 1)
     {
        SetPalette(thePalette);
     }
    */
    free(theRawImage);
    free(theImage);
    return TRUE;
}


/***************************************************************************
 * 
 *  S3d Texture Loading utilities
 *
 ***************************************************************************/

/*
 * Open a texture file and return the properties of the texture.
 * If *level returns 0, the file is not a mipmapped file.
 * If file is successfully opened, the file pointer is pointed to the beginning
 * of the bitmap in the file.
 */
int TextureOpen(char *filename, ULONG *width, ULONG *height, ULONG *bpp, ULONG *level, ULONG *format)
{
    int bmpfile;
    BITMAPFILEHEADER bmpfilehdr;
    BITMAPINFOHEADER bmpinfohdr;

    if ((bmpfile = open(filename, O_BINARY | O_RDONLY)) == -1)
        return(-1);              /* error */

#ifdef __GNUC__
    /* need special handling for structures in __GNUC__ */
    if (read(bmpfile, &(bmpfilehdr.bfType), sizeof(WORD)) != sizeof(WORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpfilehdr.bfSize), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpfilehdr.bfReserved1), sizeof(WORD)) != sizeof(WORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpfilehdr.bfReserved2), sizeof(WORD)) != sizeof(WORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpfilehdr.bfOffBits), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
#else
    if (read(bmpfile, &bmpfilehdr, sizeof(BITMAPFILEHEADER)) != sizeof(BITMAPFILEHEADER))
     {
        close(bmpfile);
        return(-1);
     }
#endif

#ifdef __GNUC__
    /* need special handling for structures in __GNUC__ */
    if (read(bmpfile, &(bmpinfohdr.biSize), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biWidth), sizeof(LONG)) != sizeof(LONG))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biHeight), sizeof(LONG)) != sizeof(LONG))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biPlanes), sizeof(WORD)) != sizeof(WORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biBitCount), sizeof(WORD)) != sizeof(WORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biCompression), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biSizeImage), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biXPelsPerMeter), sizeof(LONG)) != sizeof(LONG))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biYPelsPerMeter), sizeof(LONG)) != sizeof(LONG))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biClrUsed), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
    if (read(bmpfile, &(bmpinfohdr.biClrImportant), sizeof(DWORD)) != sizeof(DWORD))
     {
        close(bmpfile);
        return(-1);
     }
#else
    if (read(bmpfile, &bmpinfohdr, sizeof(BITMAPINFOHEADER)) != sizeof(BITMAPINFOHEADER))
     {
        close(bmpfile);
        return(-1);
     }
#endif

    *height = (ULONG)bmpinfohdr.biHeight;
    *width = (ULONG)bmpinfohdr.biWidth;

    if (bmpfilehdr.bfReserved1)     /* check if this is an S3d texture file */
     {
        /* get the texture format */
        switch (bmpfilehdr.bfReserved1 & 0x00ff)
         {
            case 0 :
                *format = S3DTK_TEXARGB8888 | S3DTK_TEXTURE;
                *bpp = 4;
                break;
            case 1:
                *format = S3DTK_TEXARGB4444 | S3DTK_TEXTURE;
                *bpp = 2;
                break;
            case 2:
                *format = S3DTK_TEXARGB1555 | S3DTK_TEXTURE;
                *bpp = 2;
                break;
            default :
                *format = S3DTK_TEXPALETTIZED8 | S3DTK_TEXTURE;
                *bpp = 1;
                break;
         }
        /* get mipmap levels */
        if (bmpfilehdr.bfReserved1 & 0x8000)    /* mipmapped */
            *level = (ULONG)((bmpfilehdr.bfReserved1 & 0x0f00) >> 8);
        else
            *level = 0;
     }
    else    /* not S3d texture file format */
     {
        close(bmpfile);
        return(-1);
     }

    /* points to the beginning of the bitmap */
    lseek(bmpfile, bmpfilehdr.bfOffBits, SEEK_SET);

    return(bmpfile);
}

void TextureClose(int bmpfile)
{
    if (bmpfile != -1)
        close(bmpfile);
}

/*
 * Read one line of pixels from the current file pointer
 */
int TextureReadline(int bmpfile, unsigned char *ptr, ULONG width)
{
    if (read(bmpfile, (char*)ptr, width) != (long)width)
        return(0);
    else
     {
        width = width % 4;
        if (width)  
         {
            char tempbuf[4];
            read(bmpfile, tempbuf, 4-width);
         }
        return(1);
     }
}

/*
 * Load the surface with the specified texture file.
 * On successful, *levels contain the number of mipmap levels defined in
 * this texture file. (*levels == 0 if the file contains only one level)
 */
#ifdef  USEDIRECTDRAW
BOOL LoadTexture(S3DTK_SURFACE *surf, LPDIRECTDRAWSURFACE *lplpDDS, char *theFilename, ULONG *levels) 
#else
BOOL LoadTexture(S3DTK_SURFACE *surf, char *theFilename, ULONG *levels) 
#endif
{
/* This function loads the bitmap file into the specified texture surface. */
    ULONG theWidth, theHeight, theFormat, theBPP, theBPL, stride;
    char *theTexture;           /* Holds texture data                  */
    char *theBits;              /* pointer pointing to the surface     */
    int theFile;
#ifdef  USEDIRECTDRAW
    DDSURFACEDESC       ddsd;
#endif

    theFile = TextureOpen((char*)theFilename, &theWidth, &theHeight, &theBPP, levels, &theFormat);
    if (theFile == -1)
     {
        TextureClose(theFile);
        return FALSE;
     }
    /* allocate surface */
#ifdef  USEDIRECTDRAW
    if (!allocSurf(surf, lplpDDS, theWidth, theHeight, theBPP, theFormat))
#else
    if (!allocSurf(surf, theWidth, theHeight, theBPP, theFormat))
#endif
     {
        TextureClose(theFile);
        return FALSE;
     }
    /* allocate buffer for one line of pixels */
    theBPL = (ULONG)(theWidth * theBPP);
    theTexture = (unsigned char *)malloc(theBPL);
    if (theTexture == NULL)
        return FALSE;
    /* Read the image bits and copy to the surface */
#ifdef  USEDIRECTDRAW
    ddsd.dwSize = sizeof(ddsd);
    (*lplpDDS)->lpVtbl->Lock(*lplpDDS, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
    stride = (ULONG)ddsd.lPitch;
    theBits = (LPSTR)((DWORD)(ddsd.lpSurface) + (theHeight - 1) * stride);
#else
    stride = (theBPL + 7) & 0xfffffff8;      /* make sure stride is quad word aligned */
    theBits = frameBufferLinear + surf->sfOffset + (theHeight-1) * stride;
#endif
    while (theHeight--)
     {
        TextureReadline(theFile, theTexture, theBPL);
        memcpy(theBits, theTexture, theBPL);
        theBits = theBits - stride;
     }
#ifdef  USEDIRECTDRAW
    (*lplpDDS)->lpVtbl->Unlock(*lplpDDS, NULL);
#endif
    TextureClose(theFile);

    free(theTexture);
    return TRUE;
}

ULONG getTextureBpp(S3DTK_SURFACE *surf)
{
    ULONG bpp = 0;
    switch (surf->sfFormat & 0x7fff)
     {
        case S3DTK_TEXARGB8888 :
            bpp = 4;
            break;
        case S3DTK_TEXARGB4444 :
        case S3DTK_TEXARGB1555 :
            bpp = 2;
            break;
        case S3DTK_TEXPALETTIZED8 :
            bpp = 1;
            break;
     }
    return(bpp);
}

ULONG getNonTextureBpp(S3DTK_SURFACE *surf)
{
    ULONG bpp = 0;
    switch (surf->sfFormat & 0x7fff)
     {
        case S3DTK_VIDEORGB24 :
            bpp = 3;
            break;
        case S3DTK_VIDEORGB15 :
        case S3DTK_Z16 :
            bpp = 2;
            break;
        case S3DTK_VIDEORGB8 :
            bpp = 1;
            break;
     }
    return(bpp);
}



