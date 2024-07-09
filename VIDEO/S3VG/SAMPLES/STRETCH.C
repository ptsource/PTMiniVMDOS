/*==========================================================================
 *
 * Copyright (C) 1996 S3 Incorporated. All Rights Reserved.
 *
 ***************************************************************************/

/***************************************************************************
 *
 * Compile this file with UTILS.C and link with S3DTK.LIB
 *
 ***************************************************************************/

/***************************************************************************
 * This program draws a 3D object on the screen.  The background of the
 * screen is filled by bitbltting a bitmap from system memory to the frame
 * buffer.  The frame rate displayed on the top left corner of the screen
 * is done by transparent bltting the bitmap of the numbers to the screen.
 *
 * When this program is compiled for Win95, DirectDraw functions are used to 
 * create surfaces, set display mode and do page flipping.
 *
 *
 * Files required by the program to run
 * ---------------------------------------------
 * The background bitmap is read from BACK.BMP.
 * The number bitmap is read from NUM.BMP.
 * The texture is read from TEXTURE.TEX.
 * The checkmark is read from MARK.BMP.
 *
 *
 * This program demonstrates some of the S3D toolkit's functions :-
 *
 * - support triangle list, triangle fan and triangle strip
 *   (uncomment one of the triangle list types definition and recompile)
 * - z buffering
 * - page flipping
 * - bitblt from system memory to frame buffer
 * - transparent bitblt from frame buffer to frame buffer
 *
 *
 *   User can turn on or off the following hardware features during runtime
 *
 *   Feature                                                   Key   
 *   -------                                                   ---
 * - texture mapping                                            T
 * - lit texture mapping                                        L
 * - perspective correction on texture mapping                  P
 * - point sampling or bilinear filter on texture mapping       S
 * - fogging                                                    F
 * - texture alpha blending                                     A
 *
 *
 *   User can manipulate the object by the following key
 *
 *   Operation                                                 Key
 *   ---------                                                 ---
 * - rotate about the x axis                                   Up, Down
 * - rotate about the y axis                                   Left, Right
 * - rotate about the z axis                                   PgUp, PgDn
 * - move object in z direction                                Home, End
 * - move the screen of project in z direction (i.e. zooming)  -, +
 *   the z coordinate of the screen and camera is unchanged
 * - stop rotation                                             Z 
 *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <time.h>
#include <math.h>

#include "utils.h"

#define DELTA       (S3DTKVALUE)0.01     /* step of angle of rotation */
#define OBJZDELTA   (S3DTKVALUE)0.05     /* step of object movement in z direction */

typedef struct
{
    S3DTKVALUE   x;                      /* x coordinate */
    S3DTKVALUE   y;                      /* y coordinate */
    S3DTKVALUE   z;                      /* z coordinate */
} VERTEX;

typedef struct
{
    BYTE    r;
    BYTE    g;
    BYTE    b;
} COLOR;


/*
 * Global variables
 */

#ifdef  WIN32
extern HWND gThisWnd;
#endif

/* S3D Toolkit function list */
S3DTK_LPFUNCTIONLIST pS3DTK_Funct;

/* runtime user configurable features */
BOOL bitbltOn=TRUE;                 /* bitblt background image?                    */
BOOL litOn=FALSE;                   /* lit texture mapping?                        */
BOOL perspectiveOn=FALSE;           /* perspective corrected texture mapping?      */
BOOL textureOn=FALSE;               /* texture mapping?                            */
BOOL foggingOn=FALSE;               /* fogging effect?                             */
BOOL filteringOn=FALSE;             /* texture filtering?                          */
BOOL alphablendingOn=FALSE;         /* alpha texture blending?                     */
BOOL frameRateOn=FALSE;             /* display frame rate on the screen?           */

/* physical properties */
ULONG mode=0x110;                   /* default mode is 640x480x15                  */
ULONG oldmode;                      /* save the original display mode              */
ULONG bpp;                          /* byte per pixel of current display mode      */
ULONG screenFormat;                 /* format of the surface as defined in S3DTK.H */
S3DTKVALUE width, height;           /* screen's dimension                          */
S3DTKVALUE halfWidth, halfHeight;   /* half of the screen dimension                */
                                    /* for adjusting the origin                    */
S3DTKVALUE aspectRatio;             /* screen width as a ratio to height           */

#define PSWIDTH     640             /* primary surface width */
#define PSHEIGHT    480             /* primary surface height */
#define PSDDBD      8               /* primary surface color depth */
#define OSWIDTH     320             /* overlay surface width */
#define OSHEIGHT    480             /* overlay surface height */
#define OSDDBD      16              /* overlay surface color depth */
/* surface definitions */
LPDIRECTDRAW            lpDD=NULL;          /* DirectDraw object                        */
LPDIRECTDRAWSURFACE     lpDDSPrimary=NULL;  /* DirectDraw primary surface               */
LPDIRECTDRAWSURFACE     lpDDSZBuffer=NULL;  /* DirectDraw Z buffer surface              */
LPDIRECTDRAWSURFACE     lpDDSTexture=NULL;  /* surface containing the texture           */
LPDIRECTDRAWSURFACE     lpDDSBmp=NULL;      /* Offscreen surface holding background bmp */
LPDIRECTDRAWSURFACE     lpDDSNum=NULL;      /* surface containing the numerical char.   */
LPDIRECTDRAWSURFACE     lpDDSCheck=NULL;    /* surface containing the check mark        */
LPDIRECTDRAWSURFACE     lpDDSOverlay=NULL;  /* DirectDraw overlay surface               */
LPDIRECTDRAWSURFACE     lpDDSOvlBack=NULL;  /* DirectDraw overlay back surface          */
HRESULT                 ddrval;             /* Holds result of DD calls                 */

#define BGCOLOR     0               /* background color of the display surface       */
#define NUMSURF     2               /* number of display surfaces including back buf */

/* buffer definitions */
ULONG sizePriSurf=0;                /* size of Primary surface */
ULONG memUsedPriSurf=0;             /* number of bytes used in Primary surface */
int backBuffer;                     /* index of back buffer                          */
S3DTK_SURFACE displaySurf[NUMSURF]; /* one for front buffer and one for back buffer  */
S3DTK_SURFACE dummySurf;
S3DTK_SURFACE zBuffer;              /* z buffer                                      */
S3DTK_SURFACE bmpSurf;              /* surface that contains the background bitmap   */
S3DTK_SURFACE numSurf;              /* surface that contains the numbers' bitmap     */
S3DTK_SURFACE checkSurf;            /* surface that contains the checkmark bitmap    */
int numWidth, numHeight;            /* width and height of each character in numSurf */
S3DTK_RECTAREA bmpSrcRect;          /* rectangle of bitmap to be copied to screen as background */
S3DTK_RECTAREA bmpSrcFrRect;        /* rectangle in the src. surface where frame rate is displayed */
S3DTK_RECTAREA bmpSrcLOptRect;      /* rectangle in the src. surface where checkmarks */
                                    /* are displayed on the left side of the screen   */
S3DTK_RECTAREA bmpSrcROptRect;      /* rectangle in the src. surface where checkmarks */
                                    /* are displayed on the right side of the screen  */
S3DTK_RECTAREA bmpSrcObjRect[NUMSURF]; /* smallest rectangle in the src. surface which  */
                                       /* bounded the object                            */
S3DTK_RECTAREA bmpDestRect;         /* where the bitmap is copied to the screen as background */
S3DTK_RECTAREA bmpDestFrRect;       /* rectangle in the dest. surface where frame rate is displayed */
S3DTK_RECTAREA bmpDestLOptRect;     /* rectangle in the dest. surface where checkmarks */
                                    /* are displayed on the left side of the screen    */
S3DTK_RECTAREA bmpDestROptRect;     /* rectangle in the dest. surface where checkmarks */
                                    /* are displayed on the right side of the screen   */
S3DTK_RECTAREA bmpDestObjRect[NUMSURF]; /* image covered area in the dest. surface which */
                                        /* are occupied by the object                    */
S3DTK_RECTAREA fillDestObjRect[NUMSURF]; /* smallest rectangle in the dest. surface which */
                                         /* bounded the object                            */
                                         /* = bmpDestObjRect[] +                          */
                                         /*   area outside the bitmap occupied by object  */
BOOL bBltFrRect;
BOOL bBltROptRect;
BOOL bFillObjRect[NUMSURF];         
S3DTK_RECTAREA zBufferRect;         /* rectangle that covers the whole z buffer      */
S3DTK_SURFACE textureSurf;          /* surface to hold texture                       */
ULONG textureMipmapLevels=0;        /* number of mipmap level in the texture file    */

/* camera definitions */
/* screen height is assumed to be from -0.5 to +0.5, and              */
/* width will be from -aspectRatio/2 to +aspectRatio/2                */
/* so the height of screen will be 1 and width will be aspectRatio    */
S3DTKVALUE screenD=(S3DTKVALUE)1.0; /* distance of screen from camera */

/* object definitions */
/* object is located at the origin for the convenience of rotation,   */
/* after the transformation, the object is translated by objectZ      */
S3DTKVALUE angleX, angleY, angleZ;  /* rotation angle on the corresponding axis */
S3DTKVALUE objectZ=(S3DTKVALUE)5.0; /* z position of the object                 */

#ifdef  CUBE
#define NUMVERTEX       8
#define NUMTRIANGLE     12
#define LISTLENGTH      (NUMTRIANGLE*3)     /* number of vertices in the triangle list */
#define TRISETMODE      S3DTK_TRILIST
VERTEX objVtxList[NUMVERTEX] = {
                        { (S3DTKVALUE) 1.0, (S3DTKVALUE) 1.0, (S3DTKVALUE) 1.0 },
                        { (S3DTKVALUE) 1.0, (S3DTKVALUE) 1.0, (S3DTKVALUE)-1.0 },
                        { (S3DTKVALUE) 1.0, (S3DTKVALUE)-1.0, (S3DTKVALUE)-1.0 },
                        { (S3DTKVALUE) 1.0, (S3DTKVALUE)-1.0, (S3DTKVALUE) 1.0 },
                        { (S3DTKVALUE)-1.0, (S3DTKVALUE) 1.0, (S3DTKVALUE) 1.0 },
                        { (S3DTKVALUE)-1.0, (S3DTKVALUE) 1.0, (S3DTKVALUE)-1.0 },
                        { (S3DTKVALUE)-1.0, (S3DTKVALUE)-1.0, (S3DTKVALUE)-1.0 },
                        { (S3DTKVALUE)-1.0, (S3DTKVALUE)-1.0, (S3DTKVALUE) 1.0 },
                       };
/* index to the vertex list forming the triangle list */
int objTriList[LISTLENGTH] = {
                             0, 1, 2,
                             0, 2, 3,
                             1, 5, 6,
                             1, 6, 2,
                             5, 4, 7,
                             5, 7, 6,
                             4, 0, 3,
                             4, 3, 7,
                             5, 1, 0,
                             5, 0, 4,
                             7, 3, 2,
                             7, 2, 6, 
                          };
/* color of each vertex */
COLOR objVtxClrList[NUMVERTEX] = { /*  R    G    B    */
                                    { 255,   0,   0 },
                                    {   0, 255,   0 },
                                    {   0,   0, 255 },
                                    { 255, 255,   0 },
                                    {   0, 255, 255 },
                                    { 255,   0, 255 },
                                    { 255, 255, 255 },
                                    {  10,  10,  10 },
                                 };

S3DTK_VERTEX_TEX s3dObjVtxList[NUMVERTEX];
S3DTK_LPVERTEX_TEX s3dObjTriList[LISTLENGTH];
#endif

#ifdef  STRIP
#define NUMVERTEX       9
#define NUMTRIANGLE     7
#define LISTLENGTH      (NUMTRIANGLE+2)     /* number of vertices in the triangle strip */
#define TRISETMODE      S3DTK_TRISTRIP
VERTEX objVtxList[NUMVERTEX] = {
                        { (S3DTKVALUE)-2.0, (S3DTKVALUE)-1.0, (S3DTKVALUE) 0.2 },
                        { (S3DTKVALUE)-1.5, (S3DTKVALUE) 1.0, (S3DTKVALUE)-0.2 },
                        { (S3DTKVALUE)-1.0, (S3DTKVALUE)-1.0, (S3DTKVALUE)-0.2 },
                        { (S3DTKVALUE)-0.5, (S3DTKVALUE) 1.0, (S3DTKVALUE) 0.2 },
                        { (S3DTKVALUE) 0.0, (S3DTKVALUE)-1.0, (S3DTKVALUE)-0.2 },
                        { (S3DTKVALUE) 0.5, (S3DTKVALUE) 1.0, (S3DTKVALUE)-0.2 },
                        { (S3DTKVALUE) 1.0, (S3DTKVALUE)-1.0, (S3DTKVALUE) 0.2 },
                        { (S3DTKVALUE) 1.5, (S3DTKVALUE) 1.0, (S3DTKVALUE)-0.2 },
                        { (S3DTKVALUE) 2.0, (S3DTKVALUE)-1.0, (S3DTKVALUE)-0.2 },
                       };
/* index to the vertex list forming the triangle strip */
int objTriList[LISTLENGTH] = {
                                0,
                                1,
                                2,
                                3,
                                4,
                                5,
                                6,
                                7,
                                8
                               };
/* color of each vertex */
COLOR objVtxClrList[NUMVERTEX] = { /*  R    G    B    */
                                    { 255,   0,   0 },
                                    {   0, 255,   0 },
                                    {   0,   0, 255 },
                                    { 255, 255,   0 },
                                    {   0, 255, 255 },
                                    { 255,   0, 255 },
                                    { 255, 255, 255 },
                                    {  10,  10,  10 },
                                    {   0, 255,   0 },
                                 };

S3DTK_VERTEX_TEX s3dObjVtxList[NUMVERTEX];
S3DTK_LPVERTEX_TEX s3dObjTriList[LISTLENGTH];
#endif

#ifdef  FAN
#define NUMVERTEX       31
#define NUMTRIANGLE     29
#define LISTLENGTH      (NUMTRIANGLE+2)     /* number of vertices in the triangle fan */
#define TRISETMODE      S3DTK_TRIFAN
VERTEX objVtxList[NUMVERTEX] = {
                        { (S3DTKVALUE) 0.0, (S3DTKVALUE) 0.0, (S3DTKVALUE) 0.0  },
                        { (S3DTKVALUE)-0.2, (S3DTKVALUE)-0.7, (S3DTKVALUE)-0.70 },
                        { (S3DTKVALUE)-0.7, (S3DTKVALUE)-0.2, (S3DTKVALUE)-0.65 },
                        { (S3DTKVALUE)-0.7, (S3DTKVALUE) 0.2, (S3DTKVALUE)-0.60 },
                        { (S3DTKVALUE)-0.2, (S3DTKVALUE) 0.7, (S3DTKVALUE)-0.55 },
                        { (S3DTKVALUE) 0.2, (S3DTKVALUE) 0.7, (S3DTKVALUE)-0.50 },
                        { (S3DTKVALUE) 0.7, (S3DTKVALUE) 0.2, (S3DTKVALUE)-0.45 },
                        { (S3DTKVALUE) 0.7, (S3DTKVALUE)-0.2, (S3DTKVALUE)-0.40 },
                        { (S3DTKVALUE) 0.2, (S3DTKVALUE)-0.7, (S3DTKVALUE)-0.35 },
                        { (S3DTKVALUE)-0.2, (S3DTKVALUE)-0.7, (S3DTKVALUE)-0.30 },
                        { (S3DTKVALUE)-0.7, (S3DTKVALUE)-0.2, (S3DTKVALUE)-0.25 },
                        { (S3DTKVALUE)-0.7, (S3DTKVALUE) 0.2, (S3DTKVALUE)-0.20 },
                        { (S3DTKVALUE)-0.2, (S3DTKVALUE) 0.7, (S3DTKVALUE)-0.15 },
                        { (S3DTKVALUE) 0.2, (S3DTKVALUE) 0.7, (S3DTKVALUE)-0.10 },
                        { (S3DTKVALUE) 0.7, (S3DTKVALUE) 0.2, (S3DTKVALUE)-0.05 },
                        { (S3DTKVALUE) 0.7, (S3DTKVALUE)-0.2, (S3DTKVALUE) 0.0  },
                        { (S3DTKVALUE) 0.2, (S3DTKVALUE)-0.7, (S3DTKVALUE) 0.05 },
                        { (S3DTKVALUE)-0.2, (S3DTKVALUE)-0.7, (S3DTKVALUE) 0.10 },
                        { (S3DTKVALUE)-0.7, (S3DTKVALUE)-0.2, (S3DTKVALUE) 0.15 },
                        { (S3DTKVALUE)-0.7, (S3DTKVALUE) 0.2, (S3DTKVALUE) 0.20 },
                        { (S3DTKVALUE)-0.2, (S3DTKVALUE) 0.7, (S3DTKVALUE) 0.25 },
                        { (S3DTKVALUE) 0.2, (S3DTKVALUE) 0.7, (S3DTKVALUE) 0.30 },
                        { (S3DTKVALUE) 0.7, (S3DTKVALUE) 0.2, (S3DTKVALUE) 0.35 },
                        { (S3DTKVALUE) 0.7, (S3DTKVALUE)-0.2, (S3DTKVALUE) 0.40 },
                        { (S3DTKVALUE) 0.2, (S3DTKVALUE)-0.7, (S3DTKVALUE) 0.45 },
                        { (S3DTKVALUE)-0.2, (S3DTKVALUE)-0.7, (S3DTKVALUE) 0.50 },
                        { (S3DTKVALUE)-0.7, (S3DTKVALUE)-0.2, (S3DTKVALUE) 0.55 },
                        { (S3DTKVALUE)-0.7, (S3DTKVALUE) 0.2, (S3DTKVALUE) 0.60 },
                        { (S3DTKVALUE)-0.2, (S3DTKVALUE) 0.7, (S3DTKVALUE) 0.65 },
                        { (S3DTKVALUE) 0.2, (S3DTKVALUE) 0.7, (S3DTKVALUE) 0.70 },
                        { (S3DTKVALUE) 0.7, (S3DTKVALUE) 0.2, (S3DTKVALUE) 0.75 },
                       };
/* index to the vertex list forming the triangle fan */
int objTriList[LISTLENGTH] = {
                                0,
                                1,
                                2,
                                3,
                                4,
                                5,
                                6,
                                7,
                                8,
                                9,
                               10,
                               11,
                               12,
                               13,
                               14,
                               15,
                               16,
                               17,
                               18,
                               19,
                               20,
                               21,
                               22,
                               23,
                               24,
                               25,
                               26,
                               27,
                               28,
                               29,
                               30,
                             };
/* color of each vertex */
COLOR objVtxClrList[NUMVERTEX] = { /*  R    G    B    */
                                    {   0,   0,   0 },
                                    { 255,   0,   0 },
                                    {   0, 255,   0 },
                                    {   0,   0, 255 },
                                    { 255, 255,   0 },
                                    {   0, 255, 255 },
                                    { 255,   0, 255 },
                                    { 255, 255, 255 },
                                    { 255,   0,   0 },
                                    {   0, 255,   0 },
                                    {   0,   0, 255 },
                                    { 255, 255,   0 },
                                    {   0, 255, 255 },
                                    { 255,   0, 255 },
                                    { 255, 255, 255 },
                                    { 255,   0,   0 },
                                    {   0, 255,   0 },
                                    {   0,   0, 255 },
                                    { 255, 255,   0 },
                                    {   0, 255, 255 },
                                    { 255,   0, 255 },
                                    { 255, 255, 255 },
                                    { 255,   0,   0 },
                                    {   0, 255,   0 },
                                    {   0,   0, 255 },
                                    { 255, 255,   0 },
                                    {   0, 255, 255 },
                                    { 255,   0, 255 },
                                    { 255, 255, 255 },
                                    { 255,   0,   0 },
                                    {   0, 255,   0 },
                                 };

S3DTK_VERTEX_TEX s3dObjVtxList[NUMVERTEX];
S3DTK_LPVERTEX_TEX s3dObjTriList[LISTLENGTH];
#endif


/*
 * Prototypes
 */
void processKey(int key);
void initScreen(void);
void restoreScreen(void);
void displayFrameRate( void );
void displayOptionStatus(void);
BOOL initMemoryBuffer(void);
void cleanupMemoryBuffer(void);
void setupTexture(void);
void transformObject(VERTEX *vtxList, S3DTK_VERTEX_TEX *s3dVtxList, int vertexNum,
                     S3DTKVALUE rotateX, S3DTKVALUE rotateY, S3DTKVALUE rotateZ);
void initObject(void);
void drawObject(void);
void updateScreen(void);
BOOL doInit(void);
void cleanUp(void);
BOOL initFail(void);
void fillBackground(void);
void initBackground(void);


/************************************************
 * Functions
 ************************************************/

void processKey(int key)
{
    switch (key)
     {
        case 'a' :
        case 'A' :                      /* toggle alpha blending */
            alphablendingOn = !alphablendingOn; 
            if (textureOn)
                setupTexture();
            break;
        case 'b' :
        case 'B' :                      /* toggle displaying the background */
            bitbltOn = !bitbltOn;
            fillBackground();           /* refill the background */
            break;
        case 'f' :
        case 'F' :                      /* toggle fogging effect */
            foggingOn = !foggingOn;     
            if (foggingOn)
                pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_FOGCOLOR, 0x00ffffff);
            else
                pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_FOGCOLOR, 0xffffffff);
            break;
        case 'l' :
        case 'L' :                      /* toggle lit texture mapping */
            litOn = !litOn;
            if (textureOn)
                setupTexture();
            break;
        case 'p' :
        case 'P' :                      /* toggle perspective texture mapping */
            perspectiveOn = !perspectiveOn;
            if (textureOn)
                setupTexture();
            break;
        case 'r' :
        case 'R' :
            frameRateOn = !frameRateOn;
            break;
        case 's' :
        case 'S' :                      /* toggle point sampling or bilinear filtering */
            filteringOn = !filteringOn;
            if (textureOn)
                setupTexture();
            break;
        case 't' :
        case 'T' :                      /* toggle texture mapping or Gouraud shaded */
            textureOn = !textureOn;
            if (textureOn)
                setupTexture();
            else
             {
                pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_ALPHABLENDING, S3DTK_ALPHAOFF);
                pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_RENDERINGTYPE, S3DTK_GOURAUD);
             }
            break;
        case 'z' :  
        case 'Z' :                      /* stop the rotation of the object */
            angleX = (S3DTKVALUE)0.0;
            angleY = (S3DTKVALUE)0.0;
            angleZ = (S3DTKVALUE)0.0;
            break;  
        case UP :                       /* change the amount of rotation about x axis */
            angleX -= DELTA;
            break;
        case DOWN :                     /* change the amount of rotation about x axis */
            angleX += DELTA;
            break;
        case LEFT :                     /* change the amount of rotation about y axis */
            angleY += DELTA;
            break;
        case RIGHT :                    /* change the amount of rotation about y axis */
            angleY -= DELTA;
            break;
        case PGUP :                     /* change the amount of rotation about z axis */
            angleZ += DELTA;
            break;
        case PGDN :                     /* change the amount of rotation about z axis */
            angleZ -= DELTA;
            break;
        case HOME :                     /* change the z position of the object */
            objectZ -= OBJZDELTA;
            break;
        case END :                      /* change the z position of the object */
            objectZ += OBJZDELTA;
            break;
        case '+' :                      /* change the z position of the screen */
            screenD += DELTA;
            break;
        case '-' :                      /* change the z position of the screen */
            screenD -= DELTA;
            break;
     }
}

void initScreen(void)
{
    /* Set exclusive mode */
    ddrval = lpDD->lpVtbl->SetCooperativeLevel(lpDD, gThisWnd, DDSCL_EXCLUSIVE | DDSCL_FULLSCREEN);
    /* Set display mode */
    ddrval = lpDD->lpVtbl->SetDisplayMode(lpDD, PSWIDTH, PSHEIGHT, PSDDBD);
    width = (S3DTKVALUE)OSWIDTH;   
    height = (S3DTKVALUE)OSHEIGHT;
    bpp = OSDDBD/8;                                 /* kclxxx need to be filled */
    aspectRatio = width*(S3DTKVALUE)2.0/height;
    halfWidth = width/(S3DTKVALUE)2.0;
    halfHeight = height/(S3DTKVALUE)2.0;
    screenFormat = (bpp == 3) ? S3DTK_VIDEORGB24 :
                   ((bpp == 2) ? S3DTK_VIDEORGB15 : S3DTK_VIDEORGB8);
}

void restoreScreen(void)
{
    if (lpDD != NULL)
        lpDD->lpVtbl->RestoreDisplayMode(lpDD);
}


DWORD   dwFrameCount=0;
DWORD   dwFrames=0;
clock_t start;

/* define the coordinate where the frame rate is displayed */
#define FPS_X       0       
#define FPS_Y       0

/*
 * displayFrameRate
 */
void displayFrameRate( void )
{
    clock_t end;

    end = clock();
    if (dwFrameCount++ == 0)
     {  /* reset */
        start = end;
        return;
     }

    /* if more than 1 second has passed */
    if (end - start >= CLK_TCK)
     {
        /* calculate the frame rate */
        dwFrames = (dwFrameCount*CLK_TCK)/(end - start);
        /* reset the counter */
        dwFrameCount = 0;
        start = end;
     }

    /*
     * display the frame rate by transparent bitblt of the numbers' bitmap 
     * to the screen 
     */
    if (frameRateOn) 
     {
        WORD    digit;
        WORD    displayX;
        ULONG   dwTemp;
        dwTemp = dwFrames;
        /* display 3 digits */
        for (digit=100, displayX=FPS_X; digit>=1; digit=(WORD)(digit/10), displayX += numWidth)
         {
            S3DTK_RECTAREA scrnRect;
            S3DTK_RECTAREA numDigit;
            WORD num;
            num = (WORD)(dwTemp / digit);
            dwTemp = dwTemp % digit;
            /* destination rectangle */
            scrnRect.top = FPS_Y;
            scrnRect.left = displayX;
            scrnRect.right = scrnRect.left + numWidth;
            scrnRect.bottom = FPS_Y + numHeight;
            /* source rectangle */
            numDigit.top = 0;
            numDigit.left = num * numWidth;
            numDigit.right = numDigit.left + numWidth;
            numDigit.bottom = numDigit.top + numHeight;
            /* 
             * transparent blt a digit from the numSurf to the back buffer
             * transparent color is BLACK 
             */
            pS3DTK_Funct->S3DTK_BitBltTransparent(pS3DTK_Funct, &(displaySurf[backBuffer]), 
                                                &scrnRect, &numSurf, &numDigit, 0);
         }
     }
} 

#define MARK_XL     12/2
#define MARK_XR     332/2
#define MARK_Y      65
#define MARKLINEHT  19
void displayOptionStatus(void)
{
    S3DTK_RECTAREA srcRect, destRect;

    /* setup the checkmark rectangle */
    srcRect.top = 0;
    srcRect.left = 0;
    srcRect.right = (int)checkSurf.sfWidth;
    srcRect.bottom = (int)checkSurf.sfHeight;

    /* setup where it is going to copy to */

    /* left column */
    destRect.left = bmpDestRect.left + MARK_XL;
    destRect.right = destRect.left + srcRect.right;

    if (bitbltOn)
     {
        destRect.top = bmpDestRect.top + MARK_Y;
        destRect.bottom = destRect.top + srcRect.bottom;
        pS3DTK_Funct->S3DTK_BitBltTransparent(pS3DTK_Funct, &(displaySurf[backBuffer]), 
                                                &destRect, &checkSurf, &srcRect, 0);
     }

    if (textureOn)
     {
        destRect.top = bmpDestRect.top + MARK_Y + 1*MARKLINEHT;
        destRect.bottom = destRect.top + srcRect.bottom;
        pS3DTK_Funct->S3DTK_BitBltTransparent(pS3DTK_Funct, &(displaySurf[backBuffer]), 
                                                &destRect, &checkSurf, &srcRect, 0);
     }

    if (filteringOn)
     {
        destRect.top = bmpDestRect.top + MARK_Y + 2*MARKLINEHT;
        destRect.bottom = destRect.top + srcRect.bottom;
        pS3DTK_Funct->S3DTK_BitBltTransparent(pS3DTK_Funct, &(displaySurf[backBuffer]), 
                                                &destRect, &checkSurf, &srcRect, 0);
     }

    if (perspectiveOn)
     {
        destRect.top = bmpDestRect.top + MARK_Y + 3*MARKLINEHT;
        destRect.bottom = destRect.top + srcRect.bottom;
        pS3DTK_Funct->S3DTK_BitBltTransparent(pS3DTK_Funct, &(displaySurf[backBuffer]), 
                                                &destRect, &checkSurf, &srcRect, 0);
     }

    if (foggingOn)
     {
        destRect.top = bmpDestRect.top + MARK_Y + 4*MARKLINEHT;
        destRect.bottom = destRect.top + srcRect.bottom;
        pS3DTK_Funct->S3DTK_BitBltTransparent(pS3DTK_Funct, &(displaySurf[backBuffer]), 
                                                &destRect, &checkSurf, &srcRect, 0);
     }

    if (litOn)
     {
        destRect.top = bmpDestRect.top + MARK_Y + 5*MARKLINEHT;
        destRect.bottom = destRect.top + srcRect.bottom;
        pS3DTK_Funct->S3DTK_BitBltTransparent(pS3DTK_Funct, &(displaySurf[backBuffer]), 
                                                &destRect, &checkSurf, &srcRect, 0);
     }

    
    /* right column */
    destRect.left = bmpDestRect.left + MARK_XR;
    destRect.right = destRect.left + srcRect.right;

    if (alphablendingOn)
     {
        destRect.top = bmpDestRect.top + MARK_Y;
        destRect.bottom = destRect.top + srcRect.bottom;
        pS3DTK_Funct->S3DTK_BitBltTransparent(pS3DTK_Funct, &(displaySurf[backBuffer]), 
                                                &destRect, &checkSurf, &srcRect, 0);
     }

}


extern ULONG frameBufferPhysical;

/* limitation : initWidth must be multiple of finalWidth */
void sampleBuffer(ULONG initWidth, ULONG finalWidth, ULONG bytesPerPixel, unsigned char *buffer)
{
    ULONG i, ratio;
    unsigned char *inptr, *outptr;
    ratio = initWidth/finalWidth;
    inptr = outptr = buffer;
    for (i=0; i<finalWidth; i++)
    {
        ULONG bytes;
        /* copy a pixel */
        for (bytes=0; bytes<bytesPerPixel; bytes++)
        {   /* copy a byte of a pixel */
            *outptr++ = *inptr++;
        }
        /* skip these pixels */
        inptr += (ratio-1)*bytesPerPixel;
    }
}

/*
 * If the memory left in the Primary Surface is big enough for the bitmap, 
 * load it into the Primary Surface;
 * otherwise create a new surface for the bitmap.
 * The surface will be created with the size of the bitmap, the specified 
 * bpp and the specified format.
 * The format has a flag specifying whether the surface should be created
 * in system memory (S3DTK_SYSTEM) or in video memory (S3DTK_VIDEO).
 */
BOOL bmpLoadSurfaceHalf(S3DTK_SURFACE *surf, LPDIRECTDRAWSURFACE *lplpDDS, const char *theFilename, ULONG theBpp, ULONG theFormat) 
{
/* This function loads the bitmap file into the specified surface.            */
    ULONG theWidth, theHeight, theSrcBPP, theSrcBPL, theDstBPP, theDstBPL, stride;
    ULONG theDstHalfBPL, theBufferSize;
    char thePalette[256*4];
    char *theRawImage;          /* Holds raw bitmap data               */
    char *theImage;             /* Holds bitmap data of desired format */
    char *theBits;              /* pointer pointing to the surface     */
    int theFile;
    int i;
    DDSURFACEDESC       ddsd;

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
    theBufferSize = theWidth*theHeight*theBpp/2;
    if ((theFormat & S3DTK_SYSTEM) ||       /* allocating system memory */
        (sizePriSurf - memUsedPriSurf) < theBufferSize) /* memory left in primary surface is not big enough to hold the bitmap */
    {   
        /* allocate surface */
        if (!allocSurf(surf, lplpDDS, theWidth/2, theHeight, theBpp, theFormat))
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
        theDstHalfBPL = theDstBPL/2;
        theImage = (unsigned char *)malloc(theDstBPL);
        if (theImage == NULL)
            return FALSE;                                                                   
        /* Read the image bits and copy to the surface */
        ddsd.dwSize = sizeof(ddsd);
        (*lplpDDS)->lpVtbl->Lock(*lplpDDS, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
        stride = (ULONG)ddsd.lPitch;
        theBits = (LPSTR)((DWORD)(ddsd.lpSurface) + (theHeight - 1) * stride);
        for (i = 0; i < (int)theHeight; i++)
         {
            BMP_Readline(theFile, theRawImage, theSrcBPL);
            BMP_Convert(theWidth, theDstBPP, theRawImage, (RGBQUAD *)thePalette, theImage, theSrcBPP);
            sampleBuffer(theWidth, theWidth/2, theDstBPP, theImage);
            memcpy(theBits, theImage, theDstHalfBPL);
            theBits = theBits - stride;
         }
        (*lplpDDS)->lpVtbl->Unlock(*lplpDDS, NULL);
        free(theRawImage);
        free(theImage);
    }
    else
    {   /* use memory in Primary Surface */
        surf->sfWidth = theWidth/2;             /* surface's width   */
        surf->sfHeight = theHeight;             /* surface's height  */
        surf->sfFormat = theFormat;             /* surface's format  */
        surf->sfOffset = dummySurf.sfOffset + memUsedPriSurf;   /* surface's offset, base at the primary surface */
        *lplpDDS = NULL;                        /* no new surface is created */
        stride = theWidth/2*theBpp;
        /* allocate buffer for one line of raw pixels */
        theSrcBPL = theWidth * theSrcBPP;
        theRawImage = (unsigned char *)malloc(theSrcBPL);
        if (theRawImage == NULL)
            return FALSE;
        /* allocate buffer for one line of pixels of required format */
        theDstBPP = theBpp;
        theDstBPL = theWidth * theDstBPP;
        theDstHalfBPL = theDstBPL/2;
        theImage = (unsigned char *)malloc(theDstBPL);
        if (theImage == NULL)
            return FALSE;                                                                   
        /* Read the image bits and copy to the surface */
        ddsd.dwSize = sizeof(ddsd);
        lpDDSPrimary->lpVtbl->Lock(lpDDSPrimary, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
        theBits = (LPSTR)((DWORD)(ddsd.lpSurface) + memUsedPriSurf + (theHeight - 1) * stride);
        for (i = 0; i < (int)theHeight; i++)
         {
            BMP_Readline(theFile, theRawImage, theSrcBPL);
            BMP_Convert(theWidth, theDstBPP, theRawImage, (RGBQUAD *)thePalette, theImage, theSrcBPP);
            sampleBuffer(theWidth, theWidth/2, theDstBPP, theImage);
            memcpy(theBits, theImage, theDstHalfBPL);
            theBits = theBits - stride;
         }
        lpDDSPrimary->lpVtbl->Unlock(lpDDSPrimary, NULL);
        free(theRawImage);
        free(theImage);
        memUsedPriSurf += theBufferSize;    /* we have used some more memory in Pri. Surface */
    }
    BMP_Close(theFile);
    return TRUE;
}


/*
 * If the memory left in the Primary Surface is big enough for the texture, 
 * load the specified texture file into the Primary Surface;
 * otherwise create a new surface for the texture.
 * On successful, *levels contain the number of mipmap levels defined in
 * this texture file. (*levels == 0 if the file contains only one level)
 */
BOOL LoadTexturePri(S3DTK_SURFACE *surf, LPDIRECTDRAWSURFACE *lplpDDS, char *theFilename, ULONG *levels) 
{
/* This function loads the bitmap file into the specified texture surface. */
    ULONG theWidth, theHeight, theFormat, theBPP, theBPL, stride;
    ULONG theBufferSize;
    char *theTexture;           /* Holds texture data                  */
    char *theBits;              /* pointer pointing to the surface     */
    int theFile;
    DDSURFACEDESC       ddsd;

    theFile = TextureOpen((char*)theFilename, &theWidth, &theHeight, &theBPP, levels, &theFormat);
    if (theFile == -1)
     {
        TextureClose(theFile);
        return FALSE;
     }
    /* allocate surface */
    theBufferSize = theWidth*theHeight*theBPP;
    if ((sizePriSurf - memUsedPriSurf) < theBufferSize)
    {   /* memory left in primary surface is not big enough to hold the texture */
        if (!allocSurf(surf, lplpDDS, theWidth, theHeight, theBPP, theFormat))
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
        ddsd.dwSize = sizeof(ddsd);
        (*lplpDDS)->lpVtbl->Lock(*lplpDDS, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
        stride = (ULONG)ddsd.lPitch;
        theBits = (LPSTR)((DWORD)(ddsd.lpSurface) + (theHeight - 1) * stride);
        while (theHeight--)
         {
            TextureReadline(theFile, theTexture, theBPL);
            memcpy(theBits, theTexture, theBPL);
            theBits = theBits - stride;
         }
        (*lplpDDS)->lpVtbl->Unlock(*lplpDDS, NULL);
        free(theTexture);
    }
    else
    {   /* use memory in the Primary surface */
        surf->sfWidth = theWidth;               /* surface's width   */
        surf->sfHeight = theHeight;             /* surface's height  */
        surf->sfFormat = theFormat;             /* surface's format  */
        surf->sfOffset = dummySurf.sfOffset + memUsedPriSurf;   /* surface's offset, base at the primary surface */
        *lplpDDS = NULL;                        /* no new surface is created */
        stride = theWidth*theBPP;
        /* allocate buffer for one line of pixels */
        theBPL = (ULONG)(theWidth * theBPP);
        theTexture = (unsigned char *)malloc(theBPL);
        if (theTexture == NULL)
            return FALSE;
        /* Read the image bits and copy to the surface */
        ddsd.dwSize = sizeof(ddsd);
        lpDDSPrimary->lpVtbl->Lock(lpDDSPrimary, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
        theBits = (LPSTR)((DWORD)(ddsd.lpSurface) + memUsedPriSurf + (theHeight - 1) * stride);
        while (theHeight--)
         {
            TextureReadline(theFile, theTexture, theBPL);
            memcpy(theBits, theTexture, theBPL);
            theBits = theBits - stride;
         }
        lpDDSPrimary->lpVtbl->Unlock(lpDDSPrimary, NULL);
        free(theTexture);
        memUsedPriSurf += theBufferSize;    /* we have used some more memory in Pri. Surface */
    }
    TextureClose(theFile);

    return TRUE;
}

BOOL initMemoryBuffer(void)
{
    DDSURFACEDESC       ddsd;
    DDSCAPS             ddscaps;
    DDCOLORKEY          ddck;

    allocInit(pS3DTK_Funct);

    /* Create the primary surface with no back buffer */
    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof( ddsd );
    ddsd.dwFlags = DDSD_CAPS;
    ddsd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE;
    ddrval = lpDD->lpVtbl->CreateSurface(lpDD, &ddsd, &lpDDSPrimary, NULL);
    if( ddrval != DD_OK )
        return(FALSE);
    ddsd.dwSize = sizeof(ddsd);
    lpDDSPrimary->lpVtbl->Lock(lpDDSPrimary, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
    lpDDSPrimary->lpVtbl->Unlock(lpDDSPrimary, NULL);
    dummySurf.sfWidth  = ddsd.dwWidth/bpp;
    dummySurf.sfHeight = ddsd.dwHeight;
    dummySurf.sfFormat = screenFormat;
    dummySurf.sfOffset = linearToPhysical((ULONG)ddsd.lpSurface) - frameBufferPhysical;
    sizePriSurf = (ULONG)PSWIDTH * (ULONG)PSHEIGHT * ((ULONG)PSDDBD / 8);
    memUsedPriSurf = 0L;
    /* Create the overlay surface with 1 back buffer */
    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof( ddsd );
    ddsd.dwFlags = DDSD_CAPS |
                   DDSD_BACKBUFFERCOUNT |
                   DDSD_PIXELFORMAT |
                   DDSD_HEIGHT |
                   DDSD_WIDTH;
    ddsd.ddsCaps.dwCaps = DDSCAPS_OVERLAY |
                          DDSCAPS_FLIP |
                          DDSCAPS_COMPLEX;
    ddsd.dwHeight = OSHEIGHT;
    ddsd.dwWidth = OSWIDTH;
    ddsd.dwBackBufferCount = 1;
    // specify pixel format for the overlay surface
    ddsd.ddpfPixelFormat.dwSize = sizeof(DDPIXELFORMAT);
    ddsd.ddpfPixelFormat.dwFlags = DDPF_RGB;
    ddsd.ddpfPixelFormat.dwFourCC = 0;
    ddsd.ddpfPixelFormat.dwRGBBitCount = OSDDBD;
    ddsd.ddpfPixelFormat.dwRBitMask = 0x7C00;
    ddsd.ddpfPixelFormat.dwGBitMask = 0x03E0;
    ddsd.ddpfPixelFormat.dwBBitMask = 0x001F;
    ddsd.ddpfPixelFormat.dwRGBAlphaBitMask = 0x0000;
    ddrval = lpDD->lpVtbl->CreateSurface(lpDD, &ddsd, &lpDDSOverlay, NULL);
    if( ddrval != DD_OK )
        return(FALSE);
    ddscaps.dwCaps = DDSCAPS_BACKBUFFER;
    ddrval = lpDDSOverlay->lpVtbl->GetAttachedSurface(lpDDSOverlay, &ddscaps, &lpDDSOvlBack);
    if( ddrval != DD_OK )
        return(FALSE);
    /* setup S3D structures for display surface and its back buffer */
    ddsd.dwSize = sizeof(ddsd);
    lpDDSOverlay->lpVtbl->Lock(lpDDSOverlay, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
    lpDDSOverlay->lpVtbl->Unlock(lpDDSOverlay, NULL);
    displaySurf[0].sfWidth  = displaySurf[1].sfWidth  = ddsd.dwWidth;
    displaySurf[0].sfHeight = displaySurf[1].sfHeight = ddsd.dwHeight;
    displaySurf[0].sfFormat = displaySurf[1].sfFormat = screenFormat;
    displaySurf[0].sfOffset = linearToPhysical((ULONG)ddsd.lpSurface) - frameBufferPhysical;
    lpDDSOvlBack->lpVtbl->Lock(lpDDSOvlBack, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
    lpDDSOvlBack->lpVtbl->Unlock(lpDDSOvlBack, NULL);
    displaySurf[1].sfOffset = linearToPhysical((ULONG)ddsd.lpSurface) - frameBufferPhysical;
    backBuffer = 1;     

    /* Create Z buffer surface */
    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS |
                   DDSD_HEIGHT | 
                   DDSD_WIDTH |
                   DDSD_ZBUFFERBITDEPTH;
    ddsd.ddsCaps.dwCaps = DDSCAPS_ZBUFFER | DDSCAPS_VIDEOMEMORY;
    ddsd.dwHeight = displaySurf[0].sfHeight;
    ddsd.dwWidth  = displaySurf[0].sfWidth;
    ddsd.dwZBufferBitDepth = 16;
    /* now create z-buffer */
    ddrval = lpDD->lpVtbl->CreateSurface(lpDD, &ddsd, &lpDDSZBuffer, NULL);
    if( ddrval != DD_OK )
        return(FALSE);
    /* setup S3D structure for z buffer */
    zBuffer.sfWidth  = displaySurf[0].sfWidth;
    zBuffer.sfHeight = displaySurf[0].sfHeight;
    zBuffer.sfFormat = S3DTK_Z16;
    lpDDSZBuffer->lpVtbl->Lock(lpDDSZBuffer, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
    lpDDSZBuffer->lpVtbl->Unlock(lpDDSZBuffer, NULL);
    zBuffer.sfOffset = linearToPhysical((ULONG)ddsd.lpSurface) - frameBufferPhysical;
    zBufferRect.top = 0;
    zBufferRect.left = 0;
    zBufferRect.right = (long)zBuffer.sfWidth;
    zBufferRect.bottom = (long)zBuffer.sfHeight;

    /* Create the texture surface */
    if (!LoadTexturePri(&textureSurf, &lpDDSTexture, "texture.tex", &textureMipmapLevels))
     {
        printf("error : cannot load texture bitmap\n");
        return(FALSE);
     }

    /* load a bitmap to a surface in system memory */
    if (!bmpLoadSurfaceHalf(&bmpSurf, &lpDDSBmp, "back.bmp", bpp, screenFormat | S3DTK_SYSTEM))       
     {
        printf("error : cannot load background bitmap\n");
        return(FALSE);
     }
    /* try to put the bitmap on the middle of screen */
    if (bmpSurf.sfWidth >= displaySurf[0].sfWidth)
     {  /* bitmap occupies the whole screen width */
        bmpDestRect.left = bmpSrcRect.left = 0;
        bmpDestRect.right = bmpSrcRect.right = (long)displaySurf[0].sfWidth;
     }
    else
     {  /* bitmap does not occupy the whole screen width */
        bmpSrcRect.left = 0;
        bmpSrcRect.right = bmpSurf.sfWidth;
        bmpDestRect.left = (long)(displaySurf[0].sfWidth - bmpSurf.sfWidth)/2;
        bmpDestRect.right = bmpDestRect.left + bmpSurf.sfWidth;
     }
    if (bmpSurf.sfHeight >= displaySurf[0].sfHeight)
     {  /* bitmap occupies the whole screen height */
        bmpDestRect.top = bmpSrcRect.top = 0;
        bmpDestRect.bottom = bmpSrcRect.bottom = (long)displaySurf[0].sfHeight;
     }
    else
     {  /* bitmap does not occupy the whole screen height  */
        bmpSrcRect.top = 0;
        bmpSrcRect.bottom = bmpSurf.sfHeight;
        bmpDestRect.top = (long)(displaySurf[0].sfHeight - bmpSurf.sfHeight)/2;
        bmpDestRect.bottom = bmpDestRect.top + bmpSurf.sfHeight;
     }

    /* load numbers' bitmap to a surface in video memory */
    if (!bmpLoadSurfaceHalf(&numSurf, &lpDDSNum, "numbers.bmp", bpp, screenFormat))        
     {
        printf("error : cannot load numbers bitmap to the video memory\n");
        printf("        trying to load it to the system memory instead\n");
        /* try to load it into the system memory instead */
        /* remember to specify the S3DTK_SYSTEM flag */
        if (!bmpLoadSurfaceHalf(&numSurf, &lpDDSNum, "numbers.bmp", bpp, screenFormat | S3DTK_SYSTEM))        
         {
            printf("error : cannot load numbers bitmap to the system memory neither\n");
            return(FALSE);
         }
     }
    numHeight = numSurf.sfHeight;
    numWidth = numSurf.sfWidth/10;  /* there are 10 number bitmap in the file */
    /* Set the color key for this bitmap */
//    ddck.dwColorSpaceLowValue = 0L;
//    ddck.dwColorSpaceHighValue = 0L;
//    lpDDSNum->lpVtbl->SetColorKey(lpDDSNum, DDCKEY_SRCBLT, &ddck);

    /* load checkmark bitmap to a surface in video memory */
    if (!bmpLoadSurfaceHalf(&checkSurf, &lpDDSCheck, "mark.bmp", bpp, screenFormat))        
     {
        printf("error : cannot load checkmark bitmap to the video memory\n");
        printf("        trying to load it to the system memory instead\n");
        /* try to load it into the system memory instead */
        /* remember to specify the S3DTK_SYSTEM flag */
        if (!bmpLoadSurfaceHalf(&checkSurf, &lpDDSCheck, "mark.bmp", bpp, screenFormat | S3DTK_SYSTEM))        
         {
            printf("error : cannot load checkmark bitmap to the system memory neither\n");
            return(FALSE);
         }
     }

    return(TRUE);
}

void cleanupMemoryBuffer(void)
{
    /* call DirectDraw member functions to release the surfaces */
    if( lpDD != NULL )
     {
        if( lpDDSPrimary != NULL )
         {
            lpDDSPrimary->lpVtbl->Release(lpDDSPrimary);
            lpDDSPrimary = NULL;
         }
        if( lpDDSOverlay != NULL )
         {
            DDOVERLAYFX dofx;
            RECT        srcrect;
            RECT        destrect;
            DWORD       ovlyDwFlags;
            /*
             * hide the overlay surface before releasing it
             */
            memset(&dofx, 0, sizeof(dofx));
            dofx.dwSize = sizeof( dofx );
            ovlyDwFlags = DDOVER_HIDE;
            ddrval = lpDDSOverlay->lpVtbl->UpdateOverlay( lpDDSOverlay,
                                                    &srcrect,
                                                    lpDDSPrimary,
                                                    &destrect,
                                                    ovlyDwFlags,
                                                    &dofx );
            lpDDSOverlay->lpVtbl->Release(lpDDSOverlay);
            lpDDSOverlay = NULL;
         }
        if( lpDDSZBuffer != NULL )
         {
            lpDDSZBuffer->lpVtbl->Release(lpDDSZBuffer);
            lpDDSZBuffer = NULL;
         }
        if( lpDDSBmp != NULL )
         {
            lpDDSBmp->lpVtbl->Release(lpDDSBmp);
            lpDDSBmp = NULL;
         }
        if( lpDDSTexture != NULL )
         {
            lpDDSTexture->lpVtbl->Release(lpDDSTexture);
            lpDDSTexture = NULL;
         }
        if( lpDDSNum != NULL )
         {
            lpDDSNum->lpVtbl->Release(lpDDSNum);
            lpDDSNum = NULL;
         }
        if( lpDDSCheck != NULL )
         {
            lpDDSCheck->lpVtbl->Release(lpDDSCheck);
            lpDDSCheck = NULL;
         }
     }
}

void fillBackground(void)
{
    int buf;
    for (buf=0; buf<NUMSURF; buf++)
     {
        /* clear the background */
        pS3DTK_Funct->S3DTK_RectFill(pS3DTK_Funct, &(displaySurf[buf]), &zBufferRect, BGCOLOR);
        /* fill the background with image*/
        if (bitbltOn)
            pS3DTK_Funct->S3DTK_BitBlt(pS3DTK_Funct, &(displaySurf[buf]), &bmpDestRect, &bmpSurf, &bmpSrcRect);
     }
}

void initBackground(void)
{
    int buf;

    fillBackground();

    /* assuming the object occupies the whole screen initially */
    for (buf=0; buf<NUMSURF; buf++)
     {
        bFillObjRect[buf] = TRUE;
        /* bitmap covered region */
        bmpDestObjRect[buf] = bmpDestRect;
        bmpSrcObjRect[buf]  = bmpSrcRect;
        /* whole screen */
        fillDestObjRect[buf] = zBufferRect;
     }

    /* calculate the region occupied by the frame rate numbers */
    bmpDestFrRect.top    = FPS_Y;
    bmpDestFrRect.left   = FPS_X;
    bmpDestFrRect.bottom = bmpDestFrRect.top + numHeight;
    bmpDestFrRect.right  = bmpDestFrRect.left + numWidth*3;
    if (bmpDestRect.top > bmpDestFrRect.bottom || bmpDestRect.left > bmpDestFrRect.right)
        bBltFrRect = FALSE;         /* the area is not filled with the bitmap image */
                                    /* fill the area with background color instead  */
    else
     {
        bBltFrRect = TRUE;
        bmpSrcFrRect.top    = bmpSrcRect.top + FPS_Y;
        bmpSrcFrRect.left   = bmpSrcRect.left + FPS_X;
        bmpSrcFrRect.bottom = bmpSrcFrRect.top + numHeight;
        bmpSrcFrRect.right  = bmpSrcFrRect.left + numWidth*3;
     }

    /* calculate the region occupied by the left options */
    bmpDestLOptRect.top    = bmpDestRect.top + MARK_Y;
    bmpDestLOptRect.left   = bmpDestRect.left + MARK_XL;
    bmpDestLOptRect.bottom = bmpDestLOptRect.top + MARKLINEHT * 6;
    bmpDestLOptRect.right  = bmpDestLOptRect.left + (int)checkSurf.sfWidth;
    bmpSrcLOptRect.top    = bmpSrcRect.top + MARK_Y;
    bmpSrcLOptRect.left   = bmpSrcRect.left + MARK_XL;
    bmpSrcLOptRect.bottom = bmpSrcLOptRect.top + MARKLINEHT * 6;
    bmpSrcLOptRect.right  = bmpSrcLOptRect.left + (int)checkSurf.sfWidth;
    if (bmpDestLOptRect.bottom > bmpDestRect.bottom)
     {
        bmpDestLOptRect.bottom = bmpDestRect.bottom;
        bmpSrcLOptRect.bottom = bmpSrcLOptRect.top + bmpDestLOptRect.bottom - bmpDestLOptRect.top;
     }

    /* calculate the region occupied by the right options */
    bmpDestROptRect.top    = bmpDestRect.top + MARK_Y;
    bmpDestROptRect.left   = bmpDestRect.left + MARK_XR;
    bmpDestROptRect.bottom = bmpDestROptRect.top + MARKLINEHT;
    bmpDestROptRect.right  = bmpDestROptRect.left + (int)checkSurf.sfWidth;
    bmpSrcROptRect.top    = bmpSrcRect.top + MARK_Y;
    bmpSrcROptRect.left   = bmpSrcRect.left + MARK_XR;
    bmpSrcROptRect.bottom = bmpSrcROptRect.top + MARKLINEHT;
    bmpSrcROptRect.right  = bmpSrcROptRect.left + (int)checkSurf.sfWidth;
    if (bmpDestROptRect.left > bmpDestRect.right)
        bBltROptRect = FALSE;
    else
        bBltROptRect = TRUE;
    if (bmpDestROptRect.bottom > bmpDestRect.bottom)
     {
        bmpDestROptRect.bottom = bmpDestRect.bottom;
        bmpSrcROptRect.bottom = bmpSrcROptRect.top + bmpDestROptRect.bottom - bmpDestROptRect.top;
     }
    if (bmpDestROptRect.right > bmpDestRect.right)
     {
        bmpDestROptRect.right = bmpDestRect.right;
        bmpSrcROptRect.right = bmpSrcROptRect.left + bmpDestROptRect.right - bmpDestROptRect.left;
     }
}

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

void setupTexture(void)
{
    /* which surface contains the texture */
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_TEXTUREACTIVE, (ULONG)(&textureSurf));
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_TEXBLENDINGMODE, S3DTK_TEXMODULATE);
    /* setup alpha blending */
    if (alphablendingOn)
        pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_ALPHABLENDING, S3DTK_ALPHATEXTURE);
    else
        pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_ALPHABLENDING, S3DTK_ALPHAOFF);
    /* setup the filtering type */
    if (filteringOn)
     {
        if (textureMipmapLevels)
            pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_TEXFILTERINGMODE, S3DTK_TEXM4TPP);
        else
            pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_TEXFILTERINGMODE, S3DTK_TEX4TPP);
     }
    else
     {
        if (textureMipmapLevels)
            pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_TEXFILTERINGMODE, S3DTK_TEXM1TPP);
        else
            pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_TEXFILTERINGMODE, S3DTK_TEX1TPP);
     }
    /* setup the texture mapping type */
    if (perspectiveOn && litOn)
        pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_RENDERINGTYPE, S3DTK_LITTEXTUREPERSPECT); 
    else if (perspectiveOn && !litOn)
        pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_RENDERINGTYPE, S3DTK_UNLITTEXTUREPERSPECT); 
    else if (!perspectiveOn && litOn)
        pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_RENDERINGTYPE, S3DTK_LITTEXTURE); 
    else
        pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_RENDERINGTYPE, S3DTK_UNLITTEXTURE);
}

void transformObject(VERTEX *vtxList, S3DTK_VERTEX_TEX *s3dVtxList, int vertexNum,
                     S3DTKVALUE rotateX, S3DTKVALUE rotateY, S3DTKVALUE rotateZ)
{
    int vtx, top, left, right, bottom;
    /* keep track of the rectangle that bound the object */
    top = (int)displaySurf[0].sfHeight;
    bottom = 0;
    right = 0;
    left = (int)displaySurf[0].sfWidth;
    /* transform the object */
    for (vtx=0; vtx<vertexNum; vtx++)
     {
        S3DTKVALUE x, y, z, projRatio;
        /* copy the init. position */
        x = vtxList[vtx].x;
        y = vtxList[vtx].y;
        z = vtxList[vtx].z;
        /* rotation about x axis */
        if (rotateX != 0)
         {
            S3DTKVALUE tempY, tempZ, cosValue, sinValue;
            cosValue = (S3DTKVALUE)cos(rotateX);
            sinValue = (S3DTKVALUE)sin(rotateX);
            tempY = y*cosValue + z*sinValue;
            tempZ = z*cosValue - y*sinValue;
            y = tempY;
            z = tempZ;
         }
        /* rotation about y axis */
        if (rotateY != 0)
         {
            S3DTKVALUE tempX, tempZ, cosValue, sinValue;
            cosValue = (S3DTKVALUE)cos(rotateY);
            sinValue = (S3DTKVALUE)sin(rotateY);
            tempX = x*cosValue - z*sinValue;
            tempZ = x*sinValue + z*cosValue;
            x = tempX;
            z = tempZ;
         }
        /* rotation about z axis */
        if (rotateZ != 0)
         {
            S3DTKVALUE tempX, tempY, cosValue, sinValue;
            cosValue = (S3DTKVALUE)cos(rotateZ);
            sinValue = (S3DTKVALUE)sin(rotateZ);
            tempX = x*cosValue + y*sinValue;
            tempY = y*cosValue - x*sinValue;
            x = tempX;
            y = tempY;
         }
        /* save the coordinate */
        vtxList[vtx].x = x;
        vtxList[vtx].y = y;
        vtxList[vtx].z = z;
        /* translate object to its actual position */
        z = z + objectZ;                
        /* setup for perspective corrected texture mapping */
        s3dVtxList[vtx].W = z;
        /* setup fogging effect according to distance from the camera */
        if (foggingOn)
         {
            S3DTKVALUE tempA;
            /* scale up the z value so alpha values spend a wider range */
            tempA = (z - (S3DTKVALUE)2.0) * (S3DTKVALUE)50.0;   
            if (tempA > 255.0)
                tempA = (S3DTKVALUE)255.0;
            if (tempA < 0.0)
                tempA = (S3DTKVALUE)0.0;
            s3dVtxList[vtx].A = (BYTE)(255.0 - tempA);
         }
        /* project onto screen */
        projRatio = screenD/z;
        x = x*projRatio;
        y = y*projRatio;
        s3dVtxList[vtx].X = halfWidth - x*(displaySurf[0].sfWidth)/aspectRatio;
        s3dVtxList[vtx].Y = halfHeight - y*(displaySurf[0].sfHeight);
        /* scale up the z value for z buffer comparison */
        s3dVtxList[vtx].Z = z * 100;        
        /* check bounding rectangle */
        if (s3dVtxList[vtx].X > right)
            right = (int)s3dVtxList[vtx].X;
        if (s3dVtxList[vtx].X < left)
            left = (int)s3dVtxList[vtx].X;
        if (s3dVtxList[vtx].Y > bottom)
            bottom = (int)s3dVtxList[vtx].Y;
        if (s3dVtxList[vtx].Y < top)
            top = (int)s3dVtxList[vtx].Y;
     }
    /* the right and bottom edges of a rectangle are not drawn */
    /* so we take the next higher values for right and bottom  */
    right++;
    bottom++;
    /* check boundaries */
    if (right > displaySurf[0].sfWidth)
        right = (int)displaySurf[0].sfWidth;
    if (left < 0)
        left = 0;
    if (bottom > displaySurf[0].sfHeight)
        bottom = (int)displaySurf[0].sfHeight;
    if (top < 0)
        top = 0;

    if (top    < bmpDestRect.top ||
        bottom > bmpDestRect.bottom ||
        left   < bmpDestRect.left ||
        right  > bmpDestRect.right)
     {
        bFillObjRect[backBuffer] = TRUE;
        /* setup the area needed to be filled with background color */
        fillDestObjRect[backBuffer].top    = top;
        fillDestObjRect[backBuffer].left   = left;
        fillDestObjRect[backBuffer].right  = right;
        fillDestObjRect[backBuffer].bottom = bottom;
        /* setup the area needed to be bitbltted with the bitmap */
        bmpDestObjRect[backBuffer].top    = top < bmpDestRect.top ? bmpDestRect.top : top;
        bmpDestObjRect[backBuffer].left   = left < bmpDestRect.left ? bmpDestRect.left : left;
        bmpDestObjRect[backBuffer].right  = right > bmpDestRect.right ? bmpDestRect.right : right;
        bmpDestObjRect[backBuffer].bottom = bottom > bmpDestRect.bottom ? bmpDestRect.bottom : bottom;
     }
    else
     {
        bFillObjRect[backBuffer] = FALSE;
        /* setup the area needed to be bitbltted with the bitmap */
        bmpDestObjRect[backBuffer].top    = top;
        bmpDestObjRect[backBuffer].left   = left;
        bmpDestObjRect[backBuffer].right  = right;
        bmpDestObjRect[backBuffer].bottom = bottom;
     }
    /* setup the area needed to be bitbltted from */
    bmpSrcObjRect[backBuffer].top    = bmpDestObjRect[backBuffer].top - bmpDestRect.top;
    bmpSrcObjRect[backBuffer].left   = bmpDestObjRect[backBuffer].left - bmpDestRect.left;
    bmpSrcObjRect[backBuffer].right  = bmpDestObjRect[backBuffer].right - bmpDestRect.left;
    bmpSrcObjRect[backBuffer].bottom = bmpDestObjRect[backBuffer].bottom - bmpDestRect.top;
}

void initObject(void)
{
    int i;
    S3DTKVALUE maxX, minX, maxY, minY;
    /* no rotation at the beginnning */
    angleX = (S3DTKVALUE)0.0;
    angleY = (S3DTKVALUE)0.0;
    angleZ = (S3DTKVALUE)0.0;
    transformObject(objVtxList, s3dObjVtxList, NUMVERTEX, angleX, angleY, angleZ);

    /* setup color for each vertex */
    for (i=0; i<NUMVERTEX; i++)
     {
        s3dObjVtxList[i].R = objVtxClrList[i].r;
        s3dObjVtxList[i].G = objVtxClrList[i].g;
        s3dObjVtxList[i].B = objVtxClrList[i].b;
     }

    /* setup the triangle list that S3D toolkit required to draw the object */
    for (i=0; i<LISTLENGTH; i++)
        s3dObjTriList[i] = &(s3dObjVtxList[objTriList[i]]);

    /* setup texture mapping u, v coordinates */
    maxX=maxY=minX=minY=(S3DTKVALUE)0.0;
    for (i=0; i<NUMVERTEX; i++)
     {
        if (objVtxList[i].x < minX)     
            minX = objVtxList[i].x;
        if (objVtxList[i].x > maxX)     
            maxX = objVtxList[i].x;
        if (objVtxList[i].y < minY)     
            minY = objVtxList[i].y;
        if (objVtxList[i].y > maxY)     
            maxY = objVtxList[i].y;
     }
    for (i=0; i<NUMVERTEX; i++)
     {
        s3dObjVtxList[i].U = (maxX - objVtxList[i].x)*(textureSurf.sfWidth-(S3DTKVALUE)1.0)/(maxX-minX);
        if (textureMipmapLevels)    /* we are not interested in the other mipmap levels */
                                    /* so height = width */
            s3dObjVtxList[i].V = (maxY - objVtxList[i].y)*(textureSurf.sfWidth-(S3DTKVALUE)1.0)/(maxY-minY);
        else
            s3dObjVtxList[i].V = (maxY - objVtxList[i].y)*(textureSurf.sfHeight-(S3DTKVALUE)1.0)/(maxY-minY);
     }

    /* setup rendering parameters */
    /* tell the engine where is the z buffer */
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_ZBUFFERSURFACE, (ULONG)(&zBuffer));
    /* update pixel if source pixel is less than z buffer */
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_ZBUFFERCOMPAREMODE, S3DTK_ZSRCLSZFB);
    if (textureOn)
        setupTexture();
    else
        pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_RENDERINGTYPE, S3DTK_GOURAUD);
}

void drawObject(void)
{
    /* transform the object */
    transformObject(objVtxList, s3dObjVtxList, NUMVERTEX, angleX, angleY, angleZ);
    /* draw the updated triangle type list */
    pS3DTK_Funct->S3DTK_TriangleSet(pS3DTK_Funct, (ULONG FAR *)(&(s3dObjTriList[0])), LISTLENGTH, TRISETMODE);
}

void updateOverlay(void)
{
    DDOVERLAYFX dofx;
    RECT        srcrect;
    RECT        destrect;
    DWORD       ovlyDwFlags;

    /*
     * set up overlay fx
     */
    memset(&dofx, 0, sizeof(dofx));
    dofx.dwSize = sizeof( dofx );

    /* display overlay surface only */
    dofx.dwAlphaDestConst = 0L;
    dofx.dwAlphaSrcConst = 0L;
    dofx.dckSrcColorkey.dwColorSpaceLowValue = 0L;
    dofx.dckSrcColorkey.dwColorSpaceLowValue = 0L;

    /* setup destination rectangle */
    destrect.top    = 0;
    destrect.bottom = PSHEIGHT;
    destrect.left   = 0;
    destrect.right  = PSWIDTH;

    /* setup source rectangle */
    srcrect.top    = 0;
    srcrect.left   = 0;
    srcrect.bottom = OSHEIGHT;
    srcrect.right  = OSWIDTH;

    /* setup overlay mode : display overlay surface only */
    ovlyDwFlags = DDOVER_SHOW |
                  DDOVER_DDFX |
                  DDOVER_KEYSRCOVERRIDE;
//                DDOVER_ALPHASRCNEG |                  /* src. is opaque if alpha is zero */
//                DDOVER_ALPHASRCCONSTOVERRIDE;         /* blending with src. alpha, */
//                DDOVER_ALPHADESTNEG |                 /* src. is opaque if alpha is zero */
//                DDOVER_ALPHADESTCONSTOVERRIDE;        /* blending with dest. alpha, */
                                                        /* dwConstAlphaDest is set to zero */
    ddrval = lpDDSOverlay->lpVtbl->UpdateOverlay( lpDDSOverlay,
                                                  &srcrect,
                                                  lpDDSPrimary,
                                                  &destrect,
                                                  ovlyDwFlags,
                                                  &dofx );
}

void updateScreen(void)
{
    /* wait for screen updated (previous buffer displayed) */
    while (lpDDSOverlay->lpVtbl->GetFlipStatus(lpDDSOverlay, DDGFS_ISFLIPDONE) == DDERR_WASSTILLDRAWING)
        ;
    /* clear z buffer with max. value */
    pS3DTK_Funct->S3DTK_RectFill(pS3DTK_Funct, &zBuffer, &zBufferRect, 0x0000ffff);
    /* repaint the background */
    if (bitbltOn)
     {
        /* repaint the area occupied by the frame rate numbers */
        if (bBltFrRect)
            pS3DTK_Funct->S3DTK_BitBlt(pS3DTK_Funct, &(displaySurf[backBuffer]), &bmpDestFrRect, &bmpSurf, &bmpSrcFrRect);
        else
            pS3DTK_Funct->S3DTK_RectFill(pS3DTK_Funct, &(displaySurf[backBuffer]), &bmpDestFrRect, BGCOLOR);
        /* repaint the area occupied by the left options */
        pS3DTK_Funct->S3DTK_BitBlt(pS3DTK_Funct, &(displaySurf[backBuffer]), &bmpDestLOptRect, &bmpSurf, &bmpSrcLOptRect);
        /* repaint the area occupied by the right options */
        if (bBltROptRect)
            pS3DTK_Funct->S3DTK_BitBlt(pS3DTK_Funct, &(displaySurf[backBuffer]), &bmpDestROptRect, &bmpSurf, &bmpSrcROptRect);
        /* repaint the area occupied by the object */
        if (bFillObjRect[backBuffer])
            pS3DTK_Funct->S3DTK_RectFill(pS3DTK_Funct, &(displaySurf[backBuffer]), &(fillDestObjRect[backBuffer]), BGCOLOR);
        pS3DTK_Funct->S3DTK_BitBlt(pS3DTK_Funct, &(displaySurf[backBuffer]), &(bmpDestObjRect[backBuffer]), &bmpSurf, &(bmpSrcObjRect[backBuffer]));
        /* display the options */
        displayOptionStatus();
     }
    else
        pS3DTK_Funct->S3DTK_RectFill(pS3DTK_Funct, &(displaySurf[backBuffer]), &zBufferRect, BGCOLOR);
    /* setup the rendering surface */
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_DRAWSURFACE, (ULONG)(&(displaySurf[backBuffer])));
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_ZBUFFERENABLE, 1);
    /* draw 3D object */
    drawObject();
    /* display frame rate */
    displayFrameRate();
    /* setup the display surface */
    lpDDSOverlay->lpVtbl->Flip(lpDDSOverlay, NULL, DDFLIP_WAIT);
    backBuffer = 1-backBuffer;     /* update the back buffer index */
}

BOOL doInit(void)
{
    S3DTK_LIB_INIT libInitStruct={
                                  S3DTK_INITPIO,
                                  0L, 
                                  0L
                                 };
    S3DTK_RENDERER_INITSTRUCT rendInitStruct={
                                              S3DTK_FORMAT_FLOAT|   \
                                              S3DTK_VERIFY_UVRANGE| \
                                              S3DTK_VERIFY_XYRANGE,
                                              0L, 
                                              0L
                                             };

    if (!initDirectDraw())
        return(initFail());
    S3DTK_InitLib((ULONG)(&libInitStruct));
    S3DTK_CreateRenderer((ULONG)(&rendInitStruct), (void * *)&pS3DTK_Funct);
    initScreen();
    if (!initMemoryBuffer())
        return(initFail());
    initBackground();
    initObject();
    updateOverlay();
    return(TRUE);
}

void cleanUp(void)
{
    cleanupMemoryBuffer();
    restoreScreen();
    S3DTK_DestroyRenderer((void * *)&pS3DTK_Funct);
    S3DTK_ExitLib();
    exitDirectDraw();
}

