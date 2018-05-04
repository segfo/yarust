extern crate libc;
use libc::*;
use std::error::Error;
use std::ffi::*;
use std::thread;

#[derive(Debug)]
#[repr(C)]
struct YARA_FFI{
    compiler:*const libc::c_void,
    rules:*const libc::c_void,
    callback_matching:*const libc::c_void,
    user_data:*mut YARA_DATA,
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
    fn ffi_set_callback_match(yara:*mut YARA_FFI,cb:fn(*mut YARA_FFI, usize, usize, *mut u8,usize) -> i32);
    fn ffi_finalize_thread();
}

#[derive(Debug)]
#[repr(C)]
struct YARA_DATA{
    rule_file:Option<String>,
    target_file:Option<String>,
}

#[derive(Debug)]
struct YARA;

#[derive(Debug)]
#[repr(C)]
struct YARA_SCANNER{
    yara:*mut YARA_FFI,
    user_data:YARA_DATA
}

impl YARA{
    fn new()->Self{
        let libstate=unsafe{ffi_initialize()};
        if libstate!=0{
            panic!("ffi initialize panic!(library initialize failure)");
        }
        YARA{}
    }
    fn get_scanner_instance(&self)->Box<YARA_SCANNER>{
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
                target_file:None
            }
        });
        if yara.yara==std::ptr::null_mut(){
            panic!("ffi initialize panic!(library initialize failure)");
        }
        unsafe{(*(yara.yara)).user_data=&mut yara.user_data;}
        yara
    }
    pub fn do_scanfile(&mut self,target_path:&str){
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

    pub fn set_callback_match(&self,cb:fn(*mut YARA_FFI,usize,usize,*mut u8,usize)->libc::c_int){
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

fn main() {
    let a=YARA::new();
    let mut a = a.get_scanner_instance();
    a.load_rule("test.yr").map_err(|e|{let s=e.description().to_owned();panic!(s);});
    a.set_callback_match(callback_matching);
    a.do_scanfile("src/main.rs");
}

fn callback_matching(yara:*mut YARA_FFI,address:usize,datalength:usize,rule_id_string:*mut u8,ruleid_len:usize)->libc::c_int{
    let mut rule_id = Vec::new();
    let data = unsafe{&(*(*yara).user_data)};
    let rulefile = data.rule_file.clone().unwrap();
    let target = data.target_file.clone().unwrap();
    for i in 0..ruleid_len{
        unsafe{
            rule_id.push(*(rule_id_string.offset(i as isize)));
        }
    }
    let rule_id = std::str::from_utf8(&rule_id).unwrap();
    println!("{:?} ===> {:?} : 0x{:x}:{:x}:{}",rulefile,target,address,datalength,rule_id);
    return 0;
}