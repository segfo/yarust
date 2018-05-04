#include"yara.h"
#include<string.h>
#include <stdlib.h>
#include<stdint.h>

//#define DEBUG

#ifdef DEBUG
#define PRINT_DEBUG(...)  printf(__VA_ARGS__)
#else
#define PRINT_DEBUG(...)
#endif

typedef struct YARA_FFI{
    YR_COMPILER*    compiler;
    YR_RULES*   rules;
    int (*callback_matching)(struct YARA_FFI* user_data,size_t address,size_t datalength,uint8_t* rule_id_string,size_t ruleid_len);
    int (*callback_not_matching)(struct YARA_FFI* user_data,uint8_t* rule_id_string);
    void* user_data;
}YARA_FFI;

// デフォルトのコールバック関数　なんもしない
void default_macher(){PRINT_DEBUG("***default matcher called.\n");}

static YARA_FFI *yara_ffi_init(){
    YARA_FFI* yara = malloc(sizeof(YARA_FFI));
    yara->compiler=NULL;
    yara->rules=NULL;
    yara->callback_matching=(void*)default_macher;
    return yara;
}

int ffi_initialize(){
    int result=yr_initialize();
    PRINT_DEBUG("yr initialize running!\n");
    return result;
}

// エラー処理は上位でやる。仕様です。
YARA_FFI *ffi_get_scanner(){
    YARA_FFI* yaraffi = NULL;
    yaraffi = yara_ffi_init();
    return yaraffi;
}

// ルールをテキストファイルからロードしてコンパイルする
int ffi_load_rules_at_file(YARA_FFI* yara,FILE* fp){
    yr_compiler_create(&yara->compiler);
    int ret=yr_compiler_add_file(yara->compiler,fp,NULL,"yararule_compile_error.log");
    if(ret!=0){
        return ERROR_INVALID_FILE;
    }
    yr_compiler_get_rules(yara->compiler,&yara->rules);
    PRINT_DEBUG("ret is : %d\n",ret);
    return ERROR_SUCCESS;
}
// ルールにマッチした場合に呼ばれる
int proc_match(YR_RULE* rule,YARA_FFI* yara){
    size_t ruleid_len=0;

    ruleid_len=strlen(rule->identifier);
    
    PRINT_DEBUG("rule id : %s\n",rule->identifier);
    
    const char* rule_tags=NULL;
    yr_rule_tags_foreach(rule,rule_tags){
        PRINT_DEBUG(" + tag %s\n",rule_tags);
    }

    YR_STRING* yrstr=NULL;
    yr_rule_strings_foreach(rule,yrstr){
        YR_MATCH* match;
        yr_string_matches_foreach(yrstr, match){
            PRINT_DEBUG("0x%x:%d:%s\n",
                match->base + match->offset,
                match->data_length,
                yrstr->identifier);
            yara->callback_matching(yara,match->base + match->offset,match->data_length,yrstr->identifier,strlen(yrstr->identifier));
        }
    }
    PRINT_DEBUG(" + namespace : %s\n",rule->ns->name);
    return CALLBACK_CONTINUE;
}

int proc_not_match(YR_RULE* rule,YARA_FFI* yara){
    return CALLBACK_CONTINUE;
}

static int do_scan_callback(int message,void* message_data,void* user_data){
    PRINT_DEBUG("---perse ready---\n");
    switch(message){
        case CALLBACK_MSG_RULE_MATCHING:
            proc_match(message_data,user_data);
            break;
        case CALLBACK_MSG_RULE_NOT_MATCHING:
            PRINT_DEBUG(" - not match\n");
            proc_not_match(message_data,user_data);
            break;
        case CALLBACK_MSG_SCAN_FINISHED:
            break;
        case CALLBACK_MSG_IMPORT_MODULE:
            break;
        case CALLBACK_MSG_MODULE_IMPORTED:
            break;
        default:
            return ERROR_CALLBACK_ERROR;
    }
    PRINT_DEBUG("---perse done---\n");
    return CALLBACK_CONTINUE;
}

int ffi_do_scan_file(YARA_FFI* yara,const char* target_file,int flags, int timeout){
    return yr_rules_scan_file(yara->rules,target_file,flags,do_scan_callback,yara,timeout);
}

void ffi_finalize(){
    yr_finalize();
    PRINT_DEBUG("yr finalize running!\n");
}

void ffi_scanner_finalize(YARA_FFI* yaraffi){
    if(yaraffi->compiler){
        yr_compiler_destroy(yaraffi->compiler);
    }
    if(yaraffi->rules){
        yr_rules_destroy(yaraffi->rules);
    }
    PRINT_DEBUG("yaraffi : %p\n",yaraffi);
    free(yaraffi);
}

/// callback setters
void ffi_set_callback_match(YARA_FFI* yara,void* cb){
    yara->callback_matching=cb;
}

void ffi_finalize_thread(){
    yr_finalize_thread();
}