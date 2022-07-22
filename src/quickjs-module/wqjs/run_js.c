#include <Windows.h>
#include <stdbool.h>
#include "run_js.h"

extern JSModuleDef* js_init_module_win32(JSContext* ctx, const char* module_name);
extern void js_free_module_win32(void);

static int eval_buf(JSContext* ctx, const void* buf, int buf_len, const char* filename, int eval_flags)
{
    JSValue val;
    int ret;

    if ((eval_flags & JS_EVAL_TYPE_MASK) == JS_EVAL_TYPE_MODULE) {
        val = JS_Eval(ctx, buf, buf_len, filename,
            eval_flags | JS_EVAL_FLAG_COMPILE_ONLY);
        if (!JS_IsException(val)) {
            js_module_set_import_meta(ctx, val, TRUE, TRUE);
            val = JS_EvalFunction(ctx, val);
        }
    }
    else {
        val = JS_Eval(ctx, buf, buf_len, filename, eval_flags);
    }
    if (JS_IsException(val)) {
        js_std_dump_error(ctx);
        ret = -1;
    }
    else {
        ret = 0;
    }
    JS_FreeValue(ctx, val);
    return ret;
}

static JSContext* JS_NewCustomContext(JSRuntime* rt)
{
    JSContext* ctx;
    ctx = JS_NewContext(rt);
    if (!ctx)
        return NULL;

    /* system modules */
    js_init_module_std(ctx, "std");
    js_init_module_os(ctx, "os");
    js_init_module_storage(ctx, "storage");

    /* Alan modules */
    js_init_module_win32(ctx, "Win32");
    return ctx;
}

int run_quickjs_code(char* js_code, char* filename) {
    int error = 0;
    JSRuntime* rt = 0;
    JSContext* ctx = 0;
    int eval_flags = 0;

    rt = JS_NewRuntime();
    if (!rt) {
        error = 1;
        goto exit;
    }

    js_std_init_handlers(rt);
    ctx = JS_NewCustomContext(rt);
    if (!ctx) {
        error = 2;
        goto exit;
    }

    JS_SetModuleLoaderFunc(rt, NULL, js_module_loader, NULL);
    js_std_add_helpers(ctx, -1, 0);

    eval_flags = JS_EVAL_TYPE_MODULE;
    error = eval_buf(ctx, js_code, strlen(js_code), filename, eval_flags);
    
    js_free_module_win32();
    js_std_free_handlers(rt);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);    
exit:
    return error;
}

int run_quickjs_file(char* filename) {    
    uint8_t* buf;
    size_t buf_len;
    int error = 0;

    buf = js_load_file(0, &buf_len, filename);
    if (!buf) {
        error = 3;
        goto exit;
    }
     
    error = run_quickjs_code(buf, filename);
    free(buf);

exit:
    return error;
}

