/*==========================================================================
 *
 * Copyright (C) 1996 S3 Incorporated. All Rights Reserved.
 *
 ***************************************************************************/

#include <conio.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

extern ULONG mode;


/***************************************************************************
 *
 *  Prototypes
 *
 ***************************************************************************/
void cleanUp(void);
void processKey(int key);
void updateScreen(void);
BOOL doInit(void);
void showSyntax(void);
void processCmdLine(int argc, char *argv[]);

/***************************************************************************
 * 
 *  Misc. utilities
 *
 ***************************************************************************/

/*
 * Return 0 if no key is pressed.
 *        ASCII code of the key 
 *        for enhanced keys, such as cursor keys and function keys, bit 7 is
 *        set
 */
int getKey(void)
{
    int key;
    if (!kbhit())
        return(0);
    if ((key=getch()) == 0)
        key = getch() | 0x80;
    return(key);
}

/*
 * Return the width of the mode
 */
int getScreenWidth(unsigned int wMode)
{
    switch (0x0FFF & wMode)
     {
        case 0x215 :
        case 0x216 :
            return(512);
        case 0x13 :
        case 0x10D :
        case 0x10E :
        case 0x10F :
            return(320);
        case 0x100 :
            return(640);
        case 0x101 :
        case 0x110 :
        case 0x111 :
        case 0x112 :
            return(640);
        case 0x103 :
        case 0x113 :
        case 0x114 :
        case 0x115 :
            return(800);
        case 0x105 :
        case 0x116 :
        case 0x117 :
        case 0x118 :
            return(1024);
        case 0x107 :
        case 0x119 :
        case 0x11A :
        case 0x11B :
            return(1200);
        default :
            return(640);
     }
}

/*
 * Return the height of the mode
 */
int getScreenHeight(unsigned int wMode)
{
    switch (0x0FFF & wMode)
     {
        case 0x215 :
        case 0x216 :
            return(384);
        case 0x13 :
        case 0x10D :
        case 0x10E :
        case 0x10F :
            return(200);
        case 0x100 :
            return(400);
        case 0x101 :
        case 0x110 :
        case 0x111 :
        case 0x112 :
            return(480);
        case 0x103 :
        case 0x113 :
        case 0x114 :
        case 0x115 :
            return(600);
        case 0x105 :
        case 0x116 :
        case 0x117 :
        case 0x118 :
            return(768);
        case 0x107 :
        case 0x119 :
        case 0x11A :
        case 0x11B :
            return(1024);
        default :
            return(480);
     }
}

/*
 * Return the number of bytes per pixel of the mode
 */
int getScreenBpp(unsigned int wMode)
{
    switch (0x0FFF & wMode)
     {
        case 0x13 :
        case 0x100 :
        case 0x101 :
        case 0x103 :
        case 0x105 :
        case 0x107 :
        case 0x215 :
            return(1);
        case 0x10D :
        case 0x10E :
        case 0x110 :
        case 0x111 :
        case 0x113 :
        case 0x114 :
        case 0x116 :
        case 0x117 :
        case 0x119 :
        case 0x11A :
        case 0x216 :
            return(2);
        case 0x10F :
        case 0x112 :
        case 0x115 :
        case 0x11F :
        case 0x11B :
            return(3);
        default :
            return(1);
     }
}


BOOL initFail(void)
{
    cleanUp();
    printf("Init. failed\n");
    return(FALSE);
} 

void main(int argc, char *argv[])
{
    int key;
    
    processCmdLine(argc, argv);

    /* initialization */
    if (!doInit())
        exit(1);

    updateScreen();  

    /* check and process user input */
    while ((key=getKey()) != ESC)
     {
        if (key)
            processKey(key);
        updateScreen();  
     }

    /* clean up */
    cleanUp();
}
