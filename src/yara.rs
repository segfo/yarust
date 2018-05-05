use std;
use libc;
use libc::*;
use std::error::Error;
use std::ffi::*;

#[derive(Debug)]
#[repr(C)]
pub struct YARA_FFI{
    compiler:*const libc::c_void,
    rules:*const libc::c_void,
    callback_matching:*const libc::c_void,
    pub user_data:*mut YARA_DATA,
}

extern {
    fn ffi_initialize()->libc::c_int;
    fn ffi_get_scanner()->* mut YARA_FFI;
    fn ffi_scanner_finalize(yaraffi:* mut YARA_FFI);
    fn ffi_finalize();
    fn ffi_load_rules_at_file(yara:*mut YARA_FFI,filename:*mut libc::FILE)->libc::c_int;
    fn ffi_do_scan_file(
        yara:*mut YARA_FFI,
        target_file:* const libc::c_char,
        flags:libc::c_int,
        timeout:libc::c_int)->libc::c_int;
    fn ffi_set_callback_match(yara:*mut YARA_FFI,cb:fn(*mut YARA_FFI, usize, usize, *mut u8,usize, *mut u8,usize) -> i32);
    fn ffi_finalize_thread();
}

#[derive(Debug)]
#[repr(C)]
pub struct YARA_DATA{
    pub rule_file:Option<String>,
    pub target_file:Option<String>,
    pub scope_width:usize,
}

#[derive(Debug)]
pub struct YARA;

#[derive(Debug)]
#[repr(C)]
pub struct YARA_SCANNER{
    yara:*mut YARA_FFI,
    user_data:YARA_DATA
}

impl YARA{
    pub fn new()->Self{
        let libstate=unsafe{ffi_initialize()};
        if libstate!=0{
            panic!("ffi initialize panic!(library initialize failure)");
        }
        YARA{}
    }
    pub fn get_scanner_instance(&self)->Box<YARA_SCANNER>{
        YARA_SCANNER::new()
    }
}

impl YARA_SCANNER{
    fn new()->Box<Self>{
        let yara=unsafe{ffi_get_scanner()};
        let mut yara = Box::new(YARA_SCANNER{
            yara:yara,
            user_data:YARA_DATA{
                rule_file:None,
                target_file:None,
                scope_width:20 , //デフォルト前後20バイト抜き出す
            }
        });
        if yara.yara==std::ptr::null_mut(){
            panic!("ffi initialize panic!(library initialize failure)");
        }
        unsafe{(*(yara.yara)).user_data=&mut yara.user_data;}
        yara
    }
    pub fn do_scanfile(&mut self,target_path:&str,scope_width:usize){
        if scope_width!=0{self.user_data.scope_width=scope_width;}
        self.user_data.target_file=Some(target_path.to_owned());
        let target_path=CString::new(target_path).unwrap();
        unsafe{
            ffi_do_scan_file(self.yara,target_path.as_ptr(),0,0);
        }
        
    }

    pub fn load_rule(&mut self,path:&str)->Result<(),Box<Error>>{
        let c_path=CString::new(path).unwrap();
        let mode=CString::new("r").unwrap();
        let fp = unsafe{libc::fopen(c_path.as_ptr(),mode.as_ptr())};
        if fp == std::ptr::null_mut(){
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "NotFound or Permission denied")));
        }
        let state = unsafe{ffi_load_rules_at_file(self.yara,fp)};
        if state!=0{
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid file.")));
        }
        unsafe{(*(*(self.yara)).user_data).rule_file=Some(path.to_owned());}
        Ok(())
    }

    pub fn set_callback_match(&self,cb:fn(*mut YARA_FFI,usize,usize,*mut u8,usize,*mut u8,usize)->libc::c_int){
        unsafe{ffi_set_callback_match(self.yara,cb);}
    }
}


impl Drop for YARA{
    fn drop(&mut self){
        unsafe{ffi_finalize();}
    }
}

impl Drop for YARA_SCANNER{
    fn drop(&mut self){
        unsafe{ffi_scanner_finalize(self.yara);}
    }
}