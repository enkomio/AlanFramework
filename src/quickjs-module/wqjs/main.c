#include <Windows.h>
#include <wincrypt.h>
#include "run_js.h"

int main(int argc, char** argv) {
    int result = 0;
    char* buf = 0;    
    if (argc > 1) {
        if (!strcmp(argv[1], "--file")) {
            if (argc > 2)
                run_quickjs_file(argv[2]);            
            else
                result = -1;            
        }
        else {            
            DWORD buf_size = 0;
            if (!CryptStringToBinaryA(argv[1], strlen(argv[1]), CRYPT_STRING_BASE64, NULL, &buf_size, NULL, NULL)) {
                result = -1;
                goto exit;
            }

            buf = malloc(buf_size + 1);
            if (!buf) {
                result = -1;
                goto exit;
            }

            if (!CryptStringToBinaryA(argv[1], strlen(argv[1]), CRYPT_STRING_BASE64, buf, &buf_size, NULL, NULL)) {
                result = -1;
                goto exit;
            }

            buf[buf_size] = 0;
            run_quickjs_code(buf, "<input>");
        }
    }
    else
    {
        result = -2;
    }

exit:
    if (buf) free(buf);
    return result;
}

static void pre_main(void) {
    int num_args = 0;
    char** argva = 0;
    LPWSTR* argvw = CommandLineToArgvW(GetCommandLineW(), &num_args);
    if (argvw) {
        argva = malloc(num_args * sizeof(intptr_t));
        for (int i = 0; i < num_args; i++) {
            int l = wcslen(argvw[i]);
            argva[i] = malloc(l + 1);
            if (!WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, argvw[i], l, argva[i], l, NULL, NULL))
                goto fail;
            argva[i][l] = 0;
        }
    }    

    return main(num_args, argva);

fail:
    if (argva) {
        for (int i = 0; num_args; i++) {
            free(argva[i]);
        }
        free(argva);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        pre_main();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow) {
    pre_main();    
	return 1;
}