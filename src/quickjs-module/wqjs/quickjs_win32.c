#include <Windows.h>
#include "run_js.h"

#define countof(x) (sizeof(x) / sizeof((x)[0]))

typedef intptr_t(__stdcall* func_00)(void);
typedef intptr_t(__stdcall* func_01)(intptr_t);
typedef intptr_t(__stdcall* func_02)(intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_03)(intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_04)(intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_05)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_06)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_07)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_08)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_09)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_10)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_11)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_12)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_13)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_14)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_15)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_16)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_17)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_18)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_19)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef intptr_t(__stdcall* func_20)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);

static JSClassID js_win32_class_id;
static uint32_t function_index = 0;

static struct array_info {
    JSValue value;
    uint32_t size;
    uint8_t* data;
    struct array_info* next;
};

struct array_info* g_objects = 0;

static intptr_t call_function(int32_t argc, intptr_t* cargv, intptr_t func_ptr) {
    intptr_t return_value = 0;

    switch (argc) {
    case 0:
        return_value = ((func_00)func_ptr)();
        break;
    case 1:
        return_value = ((func_01)func_ptr)(cargv[0]);
        break;
    case 2:
        return_value = ((func_02)func_ptr)(cargv[0], cargv[1]);
        break;
    case 3:
        return_value = ((func_03)func_ptr)(cargv[0], cargv[1], cargv[2]);
        break;
    case 4:
        return_value = ((func_04)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3]);
        break;
    case 5:
        return_value = ((func_05)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4]);
        break;
    case 6:
        return_value = ((func_06)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5]);
        break;
    case 7:
        return_value = ((func_07)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6]);
        break;
    case 8:
        return_value = ((func_08)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6], cargv[7]);
        break;
    case 9:
        return_value = ((func_09)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6], cargv[7], cargv[8]);
        break;
    case 10:
        return_value = ((func_10)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6], cargv[7], cargv[8], cargv[9]);
        break;
    case 11:
        return_value = ((func_11)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6], cargv[7], cargv[8], cargv[9], cargv[10]);
        break;
    case 12:
        return_value = ((func_12)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6], cargv[7], cargv[8], cargv[9], cargv[10], cargv[11]);
        break;
    case 13:
        return_value = ((func_13)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6], cargv[7], cargv[8], cargv[9], cargv[10], cargv[11], cargv[12]);
        break;
    case 14:
        return_value = ((func_14)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6], cargv[7], cargv[8], cargv[9], cargv[10], cargv[11], cargv[12], cargv[13]);
        break;
    case 15:
        return_value = ((func_15)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6], cargv[7], cargv[8], cargv[9], cargv[10], cargv[11], cargv[12], cargv[13], cargv[14]);
        break;
    case 16:
        return_value = ((func_16)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6], cargv[7], cargv[8], cargv[9], cargv[10], cargv[11], cargv[12], cargv[13], cargv[14], cargv[15]);
        break;
    case 17:
        return_value = ((func_17)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6], cargv[7], cargv[8], cargv[9], cargv[10], cargv[11], cargv[12], cargv[13], cargv[14], cargv[15], cargv[16]);
        break;
    case 18:
        return_value = ((func_18)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6], cargv[7], cargv[8], cargv[9], cargv[10], cargv[11], cargv[12], cargv[13], cargv[14], cargv[15], cargv[16], cargv[17]);
        break;
    case 19:
        return_value = ((func_19)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6], cargv[7], cargv[8], cargv[9], cargv[10], cargv[11], cargv[12], cargv[13], cargv[14], cargv[15], cargv[16], cargv[17], cargv[18]);
        break;
    case 20:
        return_value = ((func_20)func_ptr)(cargv[0], cargv[1], cargv[2], cargv[3], cargv[4], cargv[5], cargv[6], cargv[7], cargv[8], cargv[9], cargv[10], cargv[11], cargv[12], cargv[13], cargv[14], cargv[15], cargv[16], cargv[17], cargv[18], cargv[19]);
        break;
    }

    return return_value;
}

static struct array_info* get_array_info(JSValue obj) {
    struct array_info* info = 0;

    if (g_objects) {
        struct array_info* p = g_objects;
        do {
            if (p->value == obj) {
                info = p;
                break;
            }
            p = p->next;
        } while (p);
    }

    if (!info) {
        // create and add the info object to the array
        info = calloc(1, sizeof(struct array_info));
        if (!info) goto fail;
        if (!g_objects) {
            g_objects = info;
        }
        else {
            struct array_info* p = g_objects;
            while (p->next) p = p->next;
            p->next = info;
        }
    }

exit:
    return info;

fail:
    info = 0;
    goto exit;
}

static JSValue js_win32_call(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv, int magic) {
    intptr_t func_ptr = 0;
    intptr_t return_value = 0;
    JSValue js_return_value;    
    intptr_t* cargv = 0;

    // obtain function address
    JSValue global_object = JS_GetGlobalObject(ctx);
    JSValue func_addr = JS_GetPropertyUint32(ctx, global_object, magic);
    if (sizeof(void*) == 4) {
        if (JS_ToInt32(ctx, &func_ptr, func_addr))
            return JS_EXCEPTION;
    }
    else {
        if (JS_ToInt64(ctx, &func_ptr, func_addr))
            return JS_EXCEPTION;
    }

    if (!func_ptr)
        goto fail;

    // convert parameters
    cargv = calloc(argc, sizeof(intptr_t));
    if (!cargv) goto fail;
    for (int i = 0; i < argc; i++) {
        if (JS_IsBool(argv[i]))
            cargv[i] = JS_ToBool(ctx, argv[i]);
        else if (JS_IsNull(argv[i]))
            cargv[i] = 0;
        else if (JS_IsNumber(argv[i]))
            if (sizeof(void*) == 4)
                JS_ToInt32(ctx, &cargv[i], argv[i]);
            else
                JS_ToInt64(ctx, &cargv[i], argv[i]);
        else if (JS_IsString(argv[i]))
            cargv[i] = JS_ToCString(ctx, argv[i]);
        else if (JS_IsArray(ctx, argv[i])) {
            JSValue js_array_length = JS_GetPropertyStr(ctx, argv[i], "length");
            int32_t array_length = 0;
            JS_ToInt32(ctx, &array_length, js_array_length);
            if (array_length > 0) {
                struct array_info* info = get_array_info(argv[i]);

                // setup the info object
                if (info->size != array_length) {
                    info->size = array_length;
                    info->value = argv[i];
                    info->data = calloc(array_length, sizeof(uint8_t));
                    if (!info->data) goto fail;
                }                

                // set the memory value from the JS array
                cargv[i] = info->data;
                for (int32_t j = 0; j < array_length; j++) {
                    JSValue js_array_j = JS_GetPropertyUint32(ctx, argv[i], j);
                    int32_t array_j = 0;
                    JS_ToInt32(ctx, &array_j, js_array_j);
                    info->data[j] = (uint8_t)array_j;
                }
            }
            else {
                cargv[i] = 0;
            }           
        }
    }

    return_value = call_function(argc, cargv, func_ptr);

exit:
    if (sizeof(void*) == 4)
        js_return_value = JS_NewInt32(ctx, (int32_t)return_value);
    else
        js_return_value = JS_NewInt64(ctx, (int64_t)return_value);
        
    // write back the value to the JS array  
    for (int i = 0; i < argc; i++) {
        if (JS_IsArray(ctx, argv[i])) {
            struct array_info* info = get_array_info(argv[i]);
            for (int j = 0; j < info->size; j++) {
                JSValue byte_val = JS_NewUint32(ctx, ((uint8_t*)info->data)[j]);
                JS_DefinePropertyValueUint32(ctx, argv[i], j, byte_val, JS_PROP_CONFIGURABLE);
            }
        }
    }   

    if (cargv)
        free(cargv);

    return js_return_value;

fail:
    return_value = 0;
    goto exit;
}

static JSValue js_win32_load_library(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    HMODULE hMod = 0;
    const char* lib_name = JS_ToCString(ctx, argv[0]);
    hMod = LoadLibraryA(lib_name);
    if (sizeof(void*) == 4)
        return JS_NewInt32(ctx, (int32_t)hMod);
    else
        return JS_NewInt64(ctx, (int64_t)hMod);
}

static JSValue js_win32_get_proc_address(JSContext* ctx, JSValueConst this_val, int argc, JSValueConst* argv) {
    HMODULE hMod;
    JSValue js_func = JS_UNDEFINED;

    if (sizeof(void*) == 4) {
        int32_t tmp;
        if (JS_ToInt32(ctx, &tmp, argv[0]))
            return JS_EXCEPTION;
        hMod = (HMODULE)tmp;
    }
    else {
        int64_t tmp;
        if (JS_ToInt64(ctx, &tmp, argv[0]))
            return JS_EXCEPTION;
        hMod = (HMODULE)tmp;
    }

    const char* func_name = JS_ToCString(ctx, argv[1]);
    FARPROC func_addr = GetProcAddress(hMod, func_name);
    
    if (func_addr) {
        js_func = JS_NewCFunction2(ctx, js_win32_call, func_name, 0, JS_CFUNC_generic_magic, function_index);
        JSValue global_object = JS_GetGlobalObject(ctx);
        JS_DefinePropertyValueUint32(ctx, global_object, function_index, JS_NewInt64(ctx, func_addr), 0);
        function_index++;
    }

    return js_func;
}

static JSValue js_win32_ctor(JSContext* ctx, JSValueConst new_target, int argc, JSValueConst* argv) {
    JSValue obj = JS_UNDEFINED;
    JSValue proto;

    /* using new_target to get the prototype is necessary when the
       class is extended. */
    proto = JS_GetPropertyStr(ctx, new_target, "prototype");
    if (JS_IsException(proto))
        goto fail;
    obj = JS_NewObjectProtoClass(ctx, proto, js_win32_class_id);
    JS_FreeValue(ctx, proto);
    if (JS_IsException(obj))
        goto fail;
    return obj;
fail:
    JS_FreeValue(ctx, obj);
    return JS_EXCEPTION;
}

static const JSCFunctionListEntry js_win32_proto_funcs[] = {
    JS_CFUNC_DEF("LoadLibrary", 1, js_win32_load_library),
    JS_CFUNC_DEF("GetProcAddress", 2, js_win32_get_proc_address),
};

static int js_win32_init(JSContext* ctx, JSModuleDef* m) {
    return JS_SetModuleExportList(ctx, m, js_win32_proto_funcs, countof(js_win32_proto_funcs));    
}

JSModuleDef* js_init_module_win32(JSContext* ctx, const char* module_name) {
    JSModuleDef* m;
    m = JS_NewCModule(ctx, module_name, js_win32_init);
    if (!m)
        return NULL;
    JS_AddModuleExportList(ctx, m, js_win32_proto_funcs, countof(js_win32_proto_funcs));
    return m;
}

extern void js_free_module_win32(void)
{
    struct array_info* p = g_objects;
    if (p) {
        do
        {
            free(p->data);
            struct array_info* t = p;
            p = p->next;
            free(t);
        } while (p);
    }
}