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
 * Mipmapping samples will be available in the future.
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

/* uncomment one and only one of the following triangle list types */
/*#define   CUBE    */
/*#define   FAN     */
/*#define   STRIP   */

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

#ifdef USEDIRECTDRAW
#define PSWIDTH     640
#define PSHEIGHT    480
#define PSDDBD      16
/* surface definitions */
LPDIRECTDRAW            lpDD=NULL;          /* DirectDraw object                        */
LPDIRECTDRAWSURFACE     lpDDSPrimary=NULL;  /* DirectDraw primary surface               */
LPDIRECTDRAWSURFACE     lpDDSBack=NULL;     /* DirectDraw back surface                  */
LPDIRECTDRAWSURFACE     lpDDSZBuffer=NULL;  /* DirectDraw Z buffer surface              */
LPDIRECTDRAWSURFACE     lpDDSTexture=NULL;  /* surface containing the texture           */
LPDIRECTDRAWSURFACE     lpDDSBmp=NULL;      /* Offscreen surface holding background bmp */
LPDIRECTDRAWSURFACE     lpDDSNum=NULL;      /* surface containing the numerical char.   */
LPDIRECTDRAWSURFACE     lpDDSCheck=NULL;    /* surface containing the check mark        */
HRESULT                 ddrval;             /* Holds result of DD calls                 */
#endif

#define BGCOLOR     0               /* background color of the display surface       */
#define NUMSURF     2               /* number of display surfaces including back buf */

/* buffer definitions */
int backBuffer;                     /* index of back buffer                          */
S3DTK_SURFACE displaySurf[NUMSURF]; /* one for front buffer and one for back buffer  */
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

#ifndef USEDIRECTDRAW
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
                printf("Unknown option : [%s]\n", argv[i]);
                exitprogram = 1;
             }
        if (exitprogram)
         {
            showSyntax();
            exit(1);
         }
     }
}
#endif

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
    /* get the original display mode and save it */
    pS3DTK_Funct->S3DTK_GetState(pS3DTK_Funct, S3DTK_VIDEOMODE, (ULONG)(&oldmode));
    /* set to the new mode */
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_VIDEOMODE, mode);
    /* get and save the properties of the display mode */
    width = (S3DTKVALUE)getScreenWidth(mode);
    height = (S3DTKVALUE)getScreenHeight(mode);
    bpp = getScreenBpp(mode);
#endif
    aspectRatio = width/height;
    halfWidth = width/(S3DTKVALUE)2.0;
    halfHeight = height/(S3DTKVALUE)2.0;
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

#define MARK_XL     12
#define MARK_XR     332
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


#ifdef USEDIRECTDRAW
extern ULONG frameBufferPhysical;
#endif

BOOL initMemoryBuffer(void)
{
 #ifdef USEDIRECTDRAW
    DDSURFACEDESC       ddsd;
    DDSCAPS             ddscaps;
    DDCOLORKEY          ddck;

    allocInit(pS3DTK_Funct);

    /* Create the primary surface with 1 back buffer */
    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof( ddsd );
    ddsd.dwFlags = DDSD_CAPS | DDSD_BACKBUFFERCOUNT;
    ddsd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE |
                          DDSCAPS_FLIP |
                          DDSCAPS_COMPLEX;
    ddsd.dwBackBufferCount = 1;
    ddrval = lpDD->lpVtbl->CreateSurface(lpDD, &ddsd, &lpDDSPrimary, NULL);
    if( ddrval != DD_OK )
        return(FALSE);
    ddscaps.dwCaps = DDSCAPS_BACKBUFFER;
    ddrval = lpDDSPrimary->lpVtbl->GetAttachedSurface(lpDDSPrimary, &ddscaps, &lpDDSBack);
    if( ddrval != DD_OK )
        return(FALSE);
    /* setup S3D structures for display surface and its back buffer */
    ddsd.dwSize = sizeof(ddsd);
    lpDDSPrimary->lpVtbl->Lock(lpDDSPrimary, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
    lpDDSPrimary->lpVtbl->Unlock(lpDDSPrimary, NULL);
    displaySurf[0].sfWidth  = displaySurf[1].sfWidth  = ddsd.dwWidth;
    displaySurf[0].sfHeight = displaySurf[1].sfHeight = ddsd.dwHeight;
    displaySurf[0].sfFormat = displaySurf[1].sfFormat = screenFormat;
    displaySurf[0].sfOffset = linearToPhysical((ULONG)ddsd.lpSurface) - frameBufferPhysical;
    lpDDSBack->lpVtbl->Lock(lpDDSBack, NULL, &ddsd, DDLOCK_SURFACEMEMORYPTR, NULL);
    lpDDSBack->lpVtbl->Unlock(lpDDSBack, NULL);
    displaySurf[1].sfOffset = linearToPhysical((ULONG)ddsd.lpSurface) - frameBufferPhysical;
    backBuffer = 1;

    /* Create Z buffer surface */
    memset(&ddsd, 0, sizeof(ddsd));
    ddsd.dwSize = sizeof(ddsd);
    ddsd.dwFlags = DDSD_CAPS | 
                   DDSD_HEIGHT | 
                   DDSD_WIDTH;
/*  allocating z-buffer does not work 
    ddsd.ddsCaps.dwCaps = DDSCAPS_ZBUFFER;
*/
    ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_VIDEOMEMORY;
    ddsd.dwHeight =displaySurf[0].sfHeight;
    ddsd.dwWidth = displaySurf[0].sfWidth;
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
    zBufferRect.right = (long)width;
    zBufferRect.bottom = (long)height;

    /* Create the texture surface */
    if (!LoadTexture(&textureSurf, &lpDDSTexture, "texture.tex", &textureMipmapLevels))
     {
        printf("error : cannot load texture bitmap\n");
        return(FALSE);
     }

    /* load a bitmap to a surface in system memory */
    if (!bmpLoadSurface(&bmpSurf, &lpDDSBmp, "back.bmp", bpp, screenFormat | S3DTK_SYSTEM))       
     {
        printf("error : cannot load background bitmap\n");
        return(FALSE);
     }
    /* try to put the bitmap on the middle of screen */
    if (bmpSurf.sfWidth >= width)
     {  /* bitmap occupies the whole screen width */
        bmpDestRect.left = bmpSrcRect.left = 0;
        bmpDestRect.right = bmpSrcRect.right = (long)width;
     }
    else
     {  /* bitmap does not occupy the whole screen width */
        bmpSrcRect.left = 0;
        bmpSrcRect.right = bmpSurf.sfWidth;
        bmpDestRect.left = (long)(width - bmpSurf.sfWidth)/2;
        bmpDestRect.right = bmpDestRect.left + bmpSurf.sfWidth;
     }
    if (bmpSurf.sfHeight >= height)
     {  /* bitmap occupies the whole screen height */
        bmpDestRect.top = bmpSrcRect.top = 0;
        bmpDestRect.bottom = bmpSrcRect.bottom = (long)height;
     }
    else
     {  /* bitmap does not occupy the whole screen height  */
        bmpSrcRect.top = 0;
        bmpSrcRect.bottom = bmpSurf.sfHeight;
        bmpDestRect.top = (long)(height - bmpSurf.sfHeight)/2;
        bmpDestRect.bottom = bmpDestRect.top + bmpSurf.sfHeight;
     }

    /* load numbers' bitmap to a surface in video memory */
    if (!bmpLoadSurface(&numSurf, &lpDDSNum, "numbers.bmp", bpp, screenFormat))        
     {
        printf("error : cannot load numbers bitmap to the video memory\n");
        printf("        trying to load it to the system memory instead\n");
        /* try to load it into the system memory instead */
        /* remember to specify the S3DTK_SYSTEM flag */
        if (!bmpLoadSurface(&numSurf, &lpDDSNum, "numbers.bmp", bpp, screenFormat | S3DTK_SYSTEM))        
         {
            printf("error : cannot load numbers bitmap to the system memory neither\n");
            return(FALSE);
         }
     }
    numHeight = numSurf.sfHeight;
    numWidth = numSurf.sfWidth/10;  /* there are 10 number bitmap in the file */
    /* Set the color key for this bitmap */
    ddck.dwColorSpaceLowValue = 0L;
    ddck.dwColorSpaceHighValue = 0L;
    lpDDSNum->lpVtbl->SetColorKey(lpDDSNum, DDCKEY_SRCBLT, &ddck);

    /* load checkmark bitmap to a surface in video memory */
    if (!bmpLoadSurface(&checkSurf, &lpDDSCheck, "mark.bmp", bpp, screenFormat))        
     {
        printf("error : cannot load checkmark bitmap to the video memory\n");
        printf("        trying to load it to the system memory instead\n");
        /* try to load it into the system memory instead */
        /* remember to specify the S3DTK_SYSTEM flag */
        if (!bmpLoadSurface(&checkSurf, &lpDDSCheck, "mark.bmp", bpp, screenFormat | S3DTK_SYSTEM))        
         {
            printf("error : cannot load checkmark bitmap to the system memory neither\n");
            return(FALSE);
         }
     }

    return(TRUE);
 #else  /* not defined USEDIRECTDRAW */
    allocInit(pS3DTK_Funct);
    /* allocate display surfaces (front and back) */
    if (!allocSurf(&(displaySurf[0]), (ULONG)width, (ULONG)height, bpp, screenFormat))   
     {
        printf("error : cannot allocate display surface 0 (%dx%dx%d)\n", (int)width, (int)height, (int)bpp);
        return(FALSE);
     }
    if (!allocSurf(&(displaySurf[1]), (ULONG)width, (ULONG)height, bpp, screenFormat))
     {
        printf("error : cannot allocate display surface 1 (%dx%dx%d)\n", (int)width, (int)height, (int)bpp);
        return(FALSE);
     }
    backBuffer = 1;
    /* allocate z-buffer (16bpp) */
    if (!allocSurf(&zBuffer, (ULONG)width, (ULONG)height, 2, S3DTK_Z16))          
     {
        printf("error : cannot allocate z buffer (%dx%dx2)\n", (int)width, (int)height);
        return(FALSE);
     }
    zBufferRect.top = 0;
    zBufferRect.left = 0;
    zBufferRect.right = width;
    zBufferRect.bottom = height;
    /* load a texture */
    if (!LoadTexture(&textureSurf, "texture.tex", &textureMipmapLevels))
     {
        printf("error : cannot load texture bitmap\n");
        return(FALSE);
     }
    /* load a bitmap to a surface in system memory */
    if (!bmpLoadSurface(&bmpSurf, "back.bmp", bpp, screenFormat | S3DTK_SYSTEM))       
     {
        printf("error : cannot load background bitmap\n");
        return(FALSE);
     }
    /* try to put the bitmap on the middle of screen */
    if (bmpSurf.sfWidth >= width)
     {  /* bitmap occupies the whole screen width */
        bmpDestRect.left = bmpSrcRect.left = 0;
        bmpDestRect.right = bmpSrcRect.right = width;
     }
    else
     {  /* bitmap does not occupy the whole screen width */
        bmpSrcRect.left = 0;
        bmpSrcRect.right = bmpSurf.sfWidth;
        bmpDestRect.left = (width - bmpSurf.sfWidth)/2;
        bmpDestRect.right = bmpDestRect.left + bmpSurf.sfWidth;
     }
    if (bmpSurf.sfHeight >= height)
     {  /* bitmap occupies the whole screen height */
        bmpDestRect.top = bmpSrcRect.top = 0;
        bmpDestRect.bottom = bmpSrcRect.bottom = height;
     }
    else
     {  /* bitmap does not occupy the whole screen height  */
        bmpSrcRect.top = 0;
        bmpSrcRect.bottom = bmpSurf.sfHeight;
        bmpDestRect.top = (height - bmpSurf.sfHeight)/2;
        bmpDestRect.bottom = bmpDestRect.top + bmpSurf.sfHeight;
     }
    /* load numbers' bitmap to a surface in video memory */
    if (!bmpLoadSurface(&numSurf, "numbers.bmp", bpp, screenFormat))        
     {
        printf("error : cannot load numbers bitmap to the video memory\n");
        printf("        trying to load it to the system memory instead\n");
        /* try to load it into the system memory instead */
        /* remember to specify the S3DTK_SYSTEM flag */
        if (!bmpLoadSurface(&numSurf, "numbers.bmp", bpp, screenFormat | S3DTK_SYSTEM))        
         {
            printf("error : cannot load numbers bitmap to the system memory neither\n");
            return(FALSE);
         }
     }
    numHeight = numSurf.sfHeight;
    numWidth = numSurf.sfWidth/10;  /* there are 10 number bitmap in the file */
    /* load checkmark bitmap to a surface in video memory */
    if (!bmpLoadSurface(&checkSurf, "mark.bmp", bpp, screenFormat))        
     {
        printf("error : cannot load checkmark bitmap to the video memory\n");
        printf("        trying to load it to the system memory instead\n");
        /* try to load it into the system memory instead */
        /* remember to specify the S3DTK_SYSTEM flag */
        if (!bmpLoadSurface(&checkSurf, "mark.bmp", bpp, screenFormat | S3DTK_SYSTEM))        
         {
            printf("error : cannot load checkmark bitmap to the system memory neither\n");
            return(FALSE);
         }
     }
    return(TRUE);
#endif  /* not defined USEDIRECTDRAW */
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
#else
    /* free the memory allocated if surface is in system memory */
    if ((bmpSurf.sfFormat & S3DTK_SYSTEM) && bmpSurf.sfOffset)
        free((void *)bmpSurf.sfOffset);
    if ((numSurf.sfFormat & S3DTK_SYSTEM) && numSurf.sfOffset)
        free((void *)numSurf.sfOffset);
    if ((checkSurf.sfFormat & S3DTK_SYSTEM) && checkSurf.sfOffset)
        free((void *)checkSurf.sfOffset);
#endif
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
    /* keep track of the rectangle that bound the object*/
    top = (int)height;
    bottom = 0;
    right = 0;
    left = (int)width;
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
        s3dVtxList[vtx].X = halfWidth - x*width/aspectRatio;
        s3dVtxList[vtx].Y = halfHeight - y*height;
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
    if (right > width)
        right = (int)width;
    if (left < 0)
        left = 0;
    if (bottom > height)
        bottom = (int)height;
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

void updateScreen(void)
{
#ifndef USEDIRECTDRAW
    int dummy;
#endif

    /* wait for screen updated (previous buffer displayed) */
#ifdef  USEDIRECTDRAW
    while (lpDDSPrimary->lpVtbl->GetFlipStatus(lpDDSPrimary, DDGFS_ISFLIPDONE) == DDERR_WASSTILLDRAWING)
        ;
#else
    while (!(pS3DTK_Funct->S3DTK_GetState(pS3DTK_Funct, S3DTK_DISPLAYADDRESSUPDATED, (ULONG)(&dummy)))) 
        ;
#endif
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
#ifdef  USEDIRECTDRAW
    lpDDSPrimary->lpVtbl->Flip(lpDDSPrimary, NULL, DDFLIP_WAIT);
#else
    pS3DTK_Funct->S3DTK_SetState(pS3DTK_Funct, S3DTK_DISPLAYSURFACE, (ULONG)(&(displaySurf[backBuffer])));
#endif
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

#ifdef  USEDIRECTDRAW
    if (!initDirectDraw())
        return(initFail());
#endif
    S3DTK_InitLib((ULONG)(&libInitStruct));
    S3DTK_CreateRenderer((ULONG)(&rendInitStruct), (void * *)&pS3DTK_Funct);
    initScreen();
    if (!initMemoryBuffer())
        return(initFail());
    initBackground();
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

