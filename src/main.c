#include "app.h"
#include "cli.h"
#include "gui.h"

#include <shellapi.h>
#include <string.h>
#include <stdio.h>

static bool has_gui_option(int argc, wchar_t **argv)
{
    int i;
    for (i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--gui") == 0) return true;
    }
    return false;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                    PWSTR command_line, int nCmdShow)
{
    int argc = 0;
    wchar_t **argv;
    bool gui;
    int rc;
    (void)hPrevInstance;
    (void)command_line;

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) {
        return GuiMain(hInstance, nCmdShow);
    }
    gui = (argc <= 1) || has_gui_option(argc, argv);
    if (gui) {
        rc = GuiMain(hInstance, nCmdShow);
    } else {
        CliAttachConsole();
        rc = CliMain(argc, argv);
    }
    LocalFree(argv);
    return rc;
}
