/*==========================================================================
 *
 * Copyright (C) 1996 S3 Incorporated. All Rights Reserved.
 *
 ***************************************************************************/

#include "utils.h"
// #include <windows.h>


#define NAME "S3dEx"
#define TITLE "S3D Toolkit Example"

/***************************************************************************
 *
 *  Prototypes
 *
 ***************************************************************************/
void cleanUp(void);
void processKey(int key);
void updateScreen(void);
BOOL doInit(void);


HWND gThisWnd;
HANDLE ghInst;

/*
 * This function is called if the initialization function fails
 */
BOOL initFail( void )
{
    cleanUp();
    MessageBox( NULL, "DirectDraw Init FAILED", "ERROR", MB_OK );
    DestroyWindow( gThisWnd );
    return(FALSE);
} /* initFail */


long FAR PASCAL WindowProc( HWND hWnd, UINT message,
                WPARAM wParam, LPARAM lParam )
{
    switch( message )
    {
        case WM_CREATE:
            break;

        case WM_KEYDOWN:
            switch( wParam )
            {
                case VK_ESCAPE:
                    DestroyWindow( hWnd );
                    break;
                case VK_UP:
                    processKey(UP);
                    break;
                case VK_DOWN:
                    processKey(DOWN);
                    break;
                case VK_LEFT:
                    processKey(LEFT);
                    break;
                case VK_RIGHT:
                    processKey(RIGHT);
                    break;
                case VK_PRIOR:
                    processKey(PGUP);
                    break;
                case VK_NEXT:
                    processKey(PGDN);
                    break;
                case VK_HOME:
                    processKey(HOME);
                    break;
                case VK_END:
                    processKey(END);
                    break;
                case VK_ADD:
                    processKey('+');
                    break;
                case VK_SUBTRACT:
                    processKey('-');
                    break;
                case 'A' :
                case 'B' :                     
                case 'F' :                     
                case 'L' :                    
                case 'P' :                    
                case 'R' :
                case 'S' :                     
                case 'T' :                   
                case 'Z' :                     
                    processKey(wParam);
                    break;
                default:
                    return DefWindowProc(hWnd, message, wParam, lParam);
            }
            break;

        case WM_DESTROY:
            ShowCursor( TRUE );
            PostQuitMessage( 0 );
            break;

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return 0L;
} /* WindowProc */


// doInitWin - Create and initialize the window and the cursor
HWND doInitWin(HANDLE hInstance, int nCmdShow)
{
    HWND hwnd;
    WNDCLASS wc;

    /*
     * set up and register window class
     */
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WindowProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon( hInstance, IDI_APPLICATION );
    wc.hCursor = LoadCursor( NULL, IDC_ARROW );
    wc.hbrBackground = NULL;
    wc.lpszMenuName = NAME;
    wc.lpszClassName = NAME;
    RegisterClass( &wc );

    /*
     * create a window
     */
    hwnd = CreateWindowEx(WS_EX_TOPMOST, NAME, TITLE, WS_POPUP, 0, 0, 640, 480, NULL, NULL, hInstance, NULL);
    if (hwnd == NULL)
        return hwnd;
    gThisWnd = hwnd;

    ShowWindow( hwnd, nCmdShow );
    UpdateWindow( hwnd );
    SetFocus( hwnd );
    return hwnd;
}

/*
 * WinMain - initialization, message loop
 */
int PASCAL WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance,
            LPSTR lpCmdLine, int nCmdShow)
{
    MSG         msg;

    lpCmdLine = lpCmdLine;
    hPrevInstance = hPrevInstance;

    if( !doInitWin( hInstance, nCmdShow ) )
    {
        return FALSE;
    }

    ghInst = hInstance;

    doInit();
        
    ShowCursor( FALSE );

    updateScreen();

    while( 1 )
    {
        if( PeekMessage( &msg, NULL, 0, 0, PM_NOREMOVE ) )
        {
            if( !GetMessage( &msg, NULL, 0, 0 ) )
                return msg.wParam;
            TranslateMessage(&msg); 
            DispatchMessage(&msg);
        }
        else
        {
            updateScreen();
        }
    }

    return msg.wParam;

} /* WinMain */

