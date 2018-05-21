// YARA_FFIはYARA_DATA内に持つrule_fileなどのRust関連の型がFFI-unsafeなので警告を出す
// C側ではそれをいじることは一切行わないので、それを無視する。いじりさえしなければ安全。
#![allow(improper_ctypes)]
use std;
use libc;
use libc::*;
use std::error::Error;
use std::ffi::*;
use std::io::Write;

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
    fn ffi_maxthreads()->size_t;
}
use std::sync::{Arc, Mutex};
#[repr(C)]
pub struct YARA_DATA{
    pub rule_file:Option<String>,
    pub target_file:Option<String>,
    pub scope_width:usize,
    pub coloring:bool,
    pub out:Arc<Mutex<Box<Write+Send>>>
}
use std::fmt::Formatter;
use std::fmt::Debug;
impl Debug for YARA_DATA{
    fn fmt(&self,f:&mut Formatter)->Result<(),std::fmt::Error>{
        write!(f,"{:?} {:?} {}",self.rule_file,self.target_file,self.scope_width)
    }
}

#[derive(Debug)]
pub struct YARA;

#[derive(Debug)]
#[repr(C)]
pub struct YARA_SCANNER{
    yara:SendableYARAFFIPtr,
    user_data:YARA_DATA
}

use std::ptr::NonNull;
#[repr(C)]
#[derive(Debug)]
struct SendableYARAFFIPtr(NonNull<YARA_FFI>);
unsafe impl std::marker::Send for SendableYARAFFIPtr{}

impl YARA{
    pub fn new()->Self{
        let libstate=unsafe{ffi_initialize()};
        if libstate!=0{
            panic!("ffi initialize panic!(library initialize failure)");
        }
        YARA{}
    }
    pub fn get_scanner_instance(&self,writer:Arc<Mutex<Box<Write+Send>>>)->Box<YARA_SCANNER>{
        YARA_SCANNER::new(writer)
    }
    pub fn get_maxthreads(&self)->usize{
        unsafe{ffi_maxthreads()}
    }
}

impl YARA_SCANNER{
    fn new(writer:Arc<Mutex<Box<Write+Send>>>)->Box<Self>{
        let yara=SendableYARAFFIPtr(NonNull::new(unsafe{ffi_get_scanner()}).expect("ffi initialize panic!(library initialize failure)"));
        let mut yara = Box::new(YARA_SCANNER{
            yara:yara,
            user_data:YARA_DATA{
                rule_file:None,
                target_file:None,
                scope_width:20 , //デフォルト前後20バイト抜き出す
                coloring:true,
                out:writer,
            }
        });

        unsafe{(*(yara.yara.0.as_ptr())).user_data=&mut yara.user_data;}
        yara
    }

    pub fn set_scope_width(&mut self,scope_width:usize)->&Self{
        if scope_width!=0{self.user_data.scope_width=scope_width;}
        self
    }

    pub fn set_coloring(&mut self,coloring:bool)->&Self{
        self.user_data.coloring=coloring;
        self
    }

    pub fn do_scanfile(&mut self,target_path:&str){
        self.user_data.target_file=Some(target_path.to_owned());
        let target_path=CString::new(target_path).unwrap();
        unsafe{
            ffi_do_scan_file(self.yara.0.as_ptr(),target_path.as_ptr(),0,0);
        }
    }
    pub fn finalize_thread(&self){
        unsafe{ffi_finalize_thread()}
    }

    pub fn load_rule(&mut self,path:&str)->Result<(),Box<Error>>{
        let c_path=CString::new(path).unwrap();
        let mode=CString::new("r").unwrap();
        let fp = unsafe{libc::fopen(c_path.as_ptr(),mode.as_ptr())};
        if fp == std::ptr::null_mut(){
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "NotFound or Permission denied")));
        }
        let state = unsafe{ffi_load_rules_at_file(self.yara.0.as_ptr(),fp)};
        if state!=0{
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid file.")));
        }
        unsafe{(*(*(self.yara.0.as_ptr())).user_data).rule_file=Some(path.to_owned());}
        Ok(())
    }

    pub fn set_callback_match(&self,cb:fn(*mut YARA_FFI,usize,usize,*mut u8,usize,*mut u8,usize)->libc::c_int){
        unsafe{ffi_set_callback_match(self.yara.0.as_ptr(),cb);}
    }
}

impl Drop for YARA{
    fn drop(&mut self){
        unsafe{ffi_finalize();}
    }
}

impl Drop for YARA_SCANNER{
    fn drop(&mut self){
        unsafe{ffi_scanner_finalize(self.yara.0.as_ptr());}
    }
}