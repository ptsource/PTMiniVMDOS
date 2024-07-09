/*==========================================================================
 *
 * Copyright (C) 1995 S3 Incorporated. All Rights Reserved.
 *
 ***************************************************************************/

/***************************************************************************
 *
 * Compile this file with UTILS.C and link with S3DTK.LIB
 *
 ***************************************************************************/

/***************************************************************************
 *
 * This program loads a S3d texture file and display on the screen.
 * If the texture file contains more than one mipmap level, pressing
 * UP, DOWN, LEFT and RIGHT keys will switch the display to another level.
 *
 * S3d texture files are created by BMP2TEX.EXE on .BMP files.  For mipmapped
 * texture files, the width of the original .BMP must be the same as the 
 * height, and the dimension must be of power of 2.
 *
 ***************************************************************************/

#include <stdio.h>
#include <conio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <io.h>

#include "utils.h"

/*
 * Global variables
 */

/* S3D Toolkit function list */
S3DTK_LPFUNCTIONLIST pS3DTK_Funct;

/* determine whether we need to update screen */
BOOL bUpdateScreen=TRUE;

/* texture information, to be filled during initialization                         */
char *pTextureFile;                 /* pointer to the texture filename             */
S3DTK_SURFACE textureSurf;          /* surface to hold texture                     */
ULONG mipLevels=0;                  /* total number of mipmapped levels            */
ULONG displayLevel;                 /* current displaying mipmapped level          */
ULONG textureBpp;                   /* byte per pixel of each texel                */

/* physical properties of the display*/
ULONG mode=0x110;                   /* default mode is 640x480x15                  */
ULONG oldmode;                      /* save the original display mode              */
ULONG bpp;                          /* byte per pixel of current display mode      */
ULONG screenFormat;                 /* format of the surface as defined in S3DTK.H */
float width, height;                /* screen's dimension                          */
S3DTK_SURFACE displaySurf;          /* one for display buffer                        */


#ifdef USEDIRECTDRAW
#define PSWIDTH     640
#define PSHEIGHT    480
#define PSDDBD      16
/* surface definitions */
LPDIRECTDRAW            lpDD=NULL;          /* DirectDraw object                        */
LPDIRECTDRAWSURFACE     lpDDSPrimary=NULL;  /* DirectDraw primary surface               */
LPDIRECTDRAWSURFACE     lpDDSTexture=NULL;  /* surface containing the texture           */
HRESULT                 ddrval;             /* Holds result of DD calls                 */
#endif


/* define a rectangle for displaying texture */
#define NUMVERTEX       4
#define NUMTRIANGLE     2
#define LISTLENGTH      (NUMTRIANGLE+2)
#define TRISETMODE      S3DTK_TRIFAN
S3DTK_VERTEX_TEX s3dObjVtxList[NUMVERTEX];
S3DTK_LPVERTEX_TEX s3dObjTriList[LISTLENGTH];

/* Prototypes */
#ifdef USEDIRECTDRAW
extern ULONG frameBufferPhysical;
#endif

#ifdef  WIN32
extern HWND   gThisWnd;
extern HANDLE ghInst;
#endif

#ifdef  WIN32
BOOL getTextureFile(void);
#else
void showSyntax(void);
void processCmdLine(int argc, char *argv[]);
#endif
void processKey(int key);
void initScreen(void);
void restoreScreen(void);
BOOL initMemoryBuffer(void);
void initObject(void);
void nextLevel(void);
void previousLevel(void);
void updateScreen(void);
BOOL doInit(void);
void cleanUp(void);
BOOL initFail(void);
int getScreenWidth(unsigned int wMode);
int getScreenHeight(unsigned int wMode);
int getScreenBpp(unsigned int wMode);



/************************************************
 * Functions
 ************************************************/

#ifdef  WIN32

char szFile[256] = "\0";

BOOL getTextureFile(void)
{
    OPENFILENAME OpenFileName;

    szFile[0] = '\0';
    OpenFileName.lStructSize       = sizeof(OPENFILENAME);
    OpenFileName.hwndOwner         = gThisWnd;
    OpenFileName.hInstance         = (HANDLE) ghInst;
    OpenFileName.lpstrFilter       = "S3 Texture Files (*.tex)\0*.tex\0";
    OpenFileName.lpstrCustomFilter = (LPSTR) NULL;
    OpenFileName.nMaxCustFilter    = 0L;
    OpenFileName.nFilterIndex      = 1L;
    OpenFileName.lpstrFile         = szFile;
    OpenFileName.nMaxFile          = sizeof(szFile);
    OpenFileName.lpstrFileTitle    = NULL;
    OpenFileName.nMaxFileTitle     = 0;
    OpenFileName.lpstrInitialDir   = NULL;
    OpenFileName.lpstrTitle        = "Select texture file to view";
    OpenFileName.nFileOffset       = 0;
    OpenFileName.nFileExtension    = 0;
    OpenFileName.lpstrDefExt       = "tex";
    OpenFileName.lCustData         = 0;
    OpenFileName.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    if (GetOpenFileName(&OpenFileName))
     {
        strcpy(szFile, OpenFileName.lpstrFile);
        pTextureFile = &szFile[0];
     }
    else
        return(FALSE);

    return(TRUE);
}
#else
void showSyntax(void)
{
    printf("    /mxxxx : set display mode xxxx, default is 110\n");
    printf("    /?     : display this message\n");
}

void processCmdLine(int argc, char *argv[])
{
    int i;
    if (argc > 1)
     {
        int exitprogram=0;
        for (i=1; i<argc; i++)
            if (argv[i][0]=='/' || argv[i][0]=='-')
             {
                switch (argv[i][1])
                 {
                    case 'm' :
                    case 'M' :
                        sscanf(&(argv[i][2]), "%lx", &mode);
                        break;
                    case '?' :
                        exitprogram = 1;
                        break;
                    default :
                        printf("Unknown option : [%s]\n", argv[i]);
                        exitprogram = 1;
                 }
             }
            else
             {
                pTextureFile = argv[i];
             }
        if (exitprogram)
         {
            showSyntax();
            exit(1);
         }
     }
    else
     {
        printf("Please specify a S3d texture file.\n");
        exit(1);
     }
}
#endif

void processKey(int key)
{
    switch (key)
     {
        case UP :
        case LEFT :
            if (mipLevels && displayLevel<mipLevels-1)
             {
                displayLevel++;
                nextLevel();
                bUpdateScreen = TRUE;
                updateScreen();
             }
            break;
        case DOWN :
        case RIGHT :
            if (mipLevels && displayLevel>0)
             {
                displayLevel--;
                previousLevel();
                bUpdateScreen = TRUE;
                updateScreen();
             }
            break;
     }
}

void initScreen(void)
{
#ifdef  USEDIRECTDRAW
    RECT clientRect;
    /* Set exclusive mode */
    ddrval = lpDD->lpVtbl->SetCooperativeLevel(lpDD, gThisWnd, DDSCL_EXCLUSIVE | DDSCL_FULLSCREEN);
    /* Set display mode */
    ddrval = lpDD->lpVtbl->SetDisplayMode(lpDD, PSWIDTH, PSHEIGHT, PSDDBD);
    /* get the client area's dimension */
    GetClientRect(gThisWnd, &clientRect);
    width = (S3DTKVALUE)(clientRect.right - clientRect.left);   
    height = (S3DTKVALUE)(clientRect.bottom - clientRect.top);
    bpp = PSDDBD/8;                                 /* kclxxx need to be filled */
#else
    pS3DTK_Funct->S3DTK_GetState(pS3DTK_Funct, S3DTK_VIDEOMODE, (ULONG)(&oldmode));
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_VIDEOMODE, mode);
    width = (float)getScreenWidth(mode);
    height = (float)getScreenHeight(mode);
    bpp = getScreenBpp(mode);
#endif
    screenFormat = (bpp == 3) ? S3DTK_VIDEORGB24 :
                   ((bpp == 2) ? S3DTK_VIDEORGB15 : S3DTK_VIDEORGB8);
}

void restoreScreen(void)
{
#ifdef  USEDIRECTDRAW
    if (lpDD != NULL)
        lpDD->lpVtbl->RestoreDisplayMode(lpDD);
#else
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_VIDEOMODE, oldmode);       
#endif
}


BOOL initMemoryBuffer(void)
{
#ifdef  USEDIRECTDRAW
    DDSURFACEDESC       ddsd;

    allocInit(pS3DTK_Funct);

    /* Create the primary surface with no back buffer */
    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof( ddsd );
    ddsd.dwFlags = DDSD_CAPS;
    ddsd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE;
    ddrval = lpDD->lpVtbl->CreateSurface(lpDD, &ddsd, &lpDDSPrimary, NULL);
    if( ddrval != DD_OK )
        return(FALSE);
    /* setup S3D structures for display surface and its back buffer */
    ddsd.dwSize = sizeof(ddsd);
    lpDDSPrimary->lpVtbl->Lock(lpDDSPrimary, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
    lpDDSPrimary->lpVtbl->Unlock(lpDDSPrimary, NULL);
    displaySurf.sfWidth  = ddsd.dwWidth;
    displaySurf.sfHeight = ddsd.dwHeight;
    displaySurf.sfFormat = screenFormat;
    displaySurf.sfOffset = linearToPhysical((ULONG)ddsd.lpSurface) - frameBufferPhysical;

    /* Create the texture surface */
    if (!LoadTexture(&textureSurf, &lpDDSTexture, pTextureFile, &mipLevels))
     {
        printf("error : cannot load texture bitmap\n");
        return(FALSE);
     }
    else
        textureBpp = getTextureBpp(&textureSurf);

    return(TRUE);
#else
    allocInit(pS3DTK_Funct);

    /* allocate display surface */
    if (!allocSurf(&displaySurf, (ULONG)width, (ULONG)height, bpp, screenFormat))   
     {
        printf("error : cannot allocate display surface (%dx%dx%d)\n", (int)width, (int)height, (int)bpp);
        return(FALSE);
     }
    /* load a texture */
    if (!LoadTexture(&textureSurf, pTextureFile, &mipLevels))
     {
        printf("error : cannot load texture bitmap\n");
        return(FALSE);
     }
    else
        textureBpp = getTextureBpp(&textureSurf);
    return(TRUE);
#endif  /* not defined USEDIRECTDRAW */
}

void initObject(void)
{
    int i;

    /* setup the rectangle to display the texture */

    /* top left corner */
    s3dObjVtxList[0].U = s3dObjVtxList[0].X = (S3DTKVALUE)0.0;
    s3dObjVtxList[0].V = s3dObjVtxList[0].Y = (S3DTKVALUE)0.0;
    s3dObjVtxList[0].Z = (S3DTKVALUE)0.0;

    /* top right corner */
    s3dObjVtxList[1].U = s3dObjVtxList[1].X = textureSurf.sfWidth-(S3DTKVALUE)1.0;
    s3dObjVtxList[1].V = s3dObjVtxList[1].Y = (S3DTKVALUE)0.0;
    s3dObjVtxList[1].Z = (S3DTKVALUE)0.0;

    /* bottom right corner */
    s3dObjVtxList[2].U = s3dObjVtxList[2].X = textureSurf.sfWidth-(S3DTKVALUE)1.0;
    if (mipLevels)      /* height = width */
        s3dObjVtxList[2].V = s3dObjVtxList[2].Y = textureSurf.sfWidth-(S3DTKVALUE)1.0;
    else
        s3dObjVtxList[2].V = s3dObjVtxList[2].Y = textureSurf.sfHeight-(S3DTKVALUE)1.0;
    s3dObjVtxList[2].Z = (S3DTKVALUE)0.0;

    /* bottom left corner */
    s3dObjVtxList[3].U = s3dObjVtxList[3].X = (S3DTKVALUE)0.0;
    if (mipLevels)      /* height = width */
        s3dObjVtxList[3].V = s3dObjVtxList[3].Y = textureSurf.sfWidth-(S3DTKVALUE)1.0;
    else
        s3dObjVtxList[3].V = s3dObjVtxList[3].Y = textureSurf.sfHeight-(S3DTKVALUE)1.0;
    s3dObjVtxList[3].Z = (S3DTKVALUE)0.0;

    /* setup the triangle fan list */
    for (i=0; i<LISTLENGTH; i++)
        s3dObjTriList[i] = &(s3dObjVtxList[i]);

    /* setup the first display level */
    displayLevel = 0;
}

void nextLevel(void)
{
    ULONG textureSize;

    /* size of current mip level */
    textureSize = textureSurf.sfWidth * textureSurf.sfWidth * textureBpp;

    /* update texture information for new level */
    textureSurf.sfWidth /= 2;
    textureSurf.sfOffset += textureSize;

    /* top right corner */
    s3dObjVtxList[1].U = s3dObjVtxList[1].X = textureSurf.sfWidth-(S3DTKVALUE)1.0;

    /* bottom right corner */
    s3dObjVtxList[2].V = s3dObjVtxList[2].Y = 
    s3dObjVtxList[2].U = s3dObjVtxList[2].X = textureSurf.sfWidth-(S3DTKVALUE)1.0;
                     
    /* bottom left corner */
    s3dObjVtxList[3].V = s3dObjVtxList[3].Y = textureSurf.sfWidth-(S3DTKVALUE)1.0;
}

void previousLevel(void)
{
    ULONG textureSize;

    /* update texture information for new level */
    textureSurf.sfWidth *= 2;

    /* size of new mip level */
    textureSize = textureSurf.sfWidth * textureSurf.sfWidth * textureBpp;
    /* update texture offset */
    textureSurf.sfOffset -= textureSize;

    /* top right corner */
    s3dObjVtxList[1].U = s3dObjVtxList[1].X = textureSurf.sfWidth-(S3DTKVALUE)1.0;

    /* bottom right corner */
    s3dObjVtxList[2].V = s3dObjVtxList[2].Y = 
    s3dObjVtxList[2].U = s3dObjVtxList[2].X = textureSurf.sfWidth-(S3DTKVALUE)1.0;

    /* bottom left corner */
    s3dObjVtxList[3].V = s3dObjVtxList[3].Y = textureSurf.sfWidth-(S3DTKVALUE)1.0;
}

void updateScreen(void)
{   
    S3DTK_RECTAREA rect;

    if (!bUpdateScreen)
        return;

    /* clear the background */
    rect.top=0;
    rect.left=0;
    rect.right=(int)width;
    rect.bottom=(int)height;
    pS3DTK_Funct->S3DTK_RectFill(pS3DTK_Funct, &displaySurf, &rect, 0);

    /* setup the rendering surface */
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_DRAWSURFACE, (ULONG)(&displaySurf));

    /* setup rendering parameters */
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_RENDERINGTYPE, S3DTK_UNLITTEXTURE);
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_TEXFILTERINGMODE, S3DTK_TEX1TPP);
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_TEXBLENDINGMODE, S3DTK_TEXMODULATE);
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_TEXTUREACTIVE, (ULONG)(&textureSurf));

    /* display the rectangle with texture mapped */
    pS3DTK_Funct->S3DTK_TriangleSet(pS3DTK_Funct, (ULONG FAR *)(&(s3dObjTriList[0])), LISTLENGTH, TRISETMODE);

    /* setup the display surface */
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_DISPLAYSURFACE, (ULONG)(&displaySurf));

    /* no need to update screen until bUpdateScreen is TRUE */
    bUpdateScreen = FALSE;
}


void cleanupMemoryBuffer(void)
{
#ifdef USEDIRECTDRAW
    /* call DirectDraw member functions to release the surfaces */
    if( lpDD != NULL )
     {
        if( lpDDSPrimary != NULL )
         {
            lpDDSPrimary->lpVtbl->Release(lpDDSPrimary);
            lpDDSPrimary = NULL;
         }
        if( lpDDSTexture != NULL )
         {
            lpDDSTexture->lpVtbl->Release(lpDDSTexture);
            lpDDSTexture = NULL;
         }
     }
#else
    /* free the memory allocated if surface is in system memory */

    /*
     * nothing needed to be done
     */
#endif
}

#ifdef  USEDIRECTDRAW
BOOL initDirectDraw(void)
{
    /*
     * create the main DirectDraw object
     */
    ddrval = DirectDrawCreate( NULL, &lpDD, NULL );
    if( ddrval != DD_OK )
        return(FALSE);
    return(TRUE);
}

void exitDirectDraw(void)
{
    if (lpDD != NULL)
     {
        lpDD->lpVtbl->Release(lpDD);
        lpDD = NULL;
     }
}
#endif

BOOL doInit(void)
{
#ifdef  USEDIRECTDRAW
    if (!getTextureFile())
        return(initFail());
    if (!initDirectDraw())
        return(initFail());
#endif
    S3DTK_InitLib(S3DTK_INITPIO);
    S3DTK_CreateRenderer(0, (void * *)&pS3DTK_Funct);
    initScreen();
    if (!initMemoryBuffer())
        return(initFail());
    initObject();
    return(TRUE);
}

void cleanUp(void)
{
    cleanupMemoryBuffer();
    restoreScreen();
    S3DTK_DestroyRenderer((void * *)&pS3DTK_Funct);
    S3DTK_ExitLib();
#ifdef  USEDIRECTDRAW
    exitDirectDraw();
#endif
}

