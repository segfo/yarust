extern crate libc;
extern crate clap;
use clap::*;
mod yara;
use yara::*;
use std::path::*;
use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
mod console;
use console::*;
mod dirworker;
use dirworker::*;

fn init<'a>()->ArgMatches<'a>{
    app_from_crate!()
    .arg(Arg::with_name("search_path")
        .long("path")
        .short("p")
        .required(true)
        .takes_value(true)
        .help("Specify the path of the search target file or directory"))
    .arg(Arg::with_name("rule_file")
        .long("rule")
        .short("r")
        .required(true)
        .takes_value(true)
        .help("Specify file path of YARA rule"))
    .arg(Arg::with_name("scope_width")
        .long("width")
        .short("w")
        .validator(|s|if s.parse::<usize>().is_ok()==false{
                Err(format!("\"{}\" is Invalid number(parse error)",s).to_owned())
            }else{
                Ok(())
            })
        .takes_value(true)
        .help("Specify an arbitrary number of bytes before and after display from the matching part (default 20 bytes)"))
    .arg(Arg::with_name("redirect_file_path")
        .long("logfile")
        .short("l")
        .required(false)
        .takes_value(true)
        .help("Specify log file path"))
    .get_matches()
}

fn main() {
    let opt = init();
    let scope_width = 
        if opt.is_present("scope_width"){
            opt.value_of("scope_width").unwrap().parse().unwrap()
        }else{0};

    let a=YARA::new();

    let mut file:Box<Write>;
    if opt.is_present("redirect_file_path"){
        file = Box::new(File::create(opt.value_of("redirect_file_path").unwrap()).unwrap());
    }else{
        file = Box::new(stdout());
    }
    let mut a = a.get_scanner_instance(file);
    let rule_path = opt.value_of("rule_file").unwrap();
    if let Err(e) = a.load_rule(rule_path){
        eprintln!("Rule load error : \"{}\" {}",rule_path,e);
        return;
    }
    a.set_callback_match(callback_matching);

    // スキャンの準備（基本はディレクトリ単位で行う）
    let search_path = opt.value_of("search_path").unwrap();
    if Path::new(search_path).exists() == false{
        eprintln!("\"{}\" is not exists",search_path);
        return;
    }
    let mut walker = match DirectoryWalker::new(search_path){
        Ok(walker)=>walker,
        Err(e)=>{
            println!("walker generate fail : {}",e);
            return;
        }
    };
    // サーチしたパスを格納するバッファを用意する
    let mut path = Vec::<PathBuf>::new();
    loop{
        let dir=walker.dir_list.pop().unwrap();
        // ファイルが指定されたときはError。
        // 単一ファイルをとりあえずスキャンして終わる
        match walker.dir_walk(&dir,&mut path){
            Ok(_)=>{},
            Err(e)=>{
                a.do_scanfile(&dir.path,scope_width);
                return;
            }
        };
        if walker.dir_list.len()==0{break;}
    }
    // ディレクトリ配下にあるファイルをすべてスキャンする
    for p in path{
        a.do_scanfile(p.to_str().unwrap(),scope_width);
    }
}

fn u8ptr_to_vec(s:*mut u8,s_len:usize)->Vec<u8>{
    let mut tmp = Vec::new();
    for i in 0..s_len{
        unsafe{
            tmp.push(*(s.offset(i as isize)));
        }
    }
    tmp
}

// 一致した際に呼ばれるコールバックメソッド
fn callback_matching(yara:*mut YARA_FFI,address:usize,datalength:usize,rule_id_string:*mut u8,ruleid_len:usize,cond_string_id_string:*mut u8,condstringid_len:usize)->libc::c_int{
    let mut data = unsafe{&mut (*(*yara).user_data)};
    let rulefile = data.rule_file.clone().unwrap();
    let target = data.target_file.clone().unwrap();

    let rule_id = u8ptr_to_vec(rule_id_string,ruleid_len);
    let rule_id = std::str::from_utf8(&rule_id).unwrap();
    let cond_string_id = u8ptr_to_vec(cond_string_id_string,condstringid_len);
    let cond_string_id = std::str::from_utf8(&cond_string_id).unwrap();
    
    print_result(&mut data,&rulefile,&target,address,datalength,rule_id,cond_string_id);
    return 0;
}

use std::io::{stdout, Write, BufWriter};
// 一致したデータの該当部分周辺と該当箇所を表示するメソッド
fn print_result(user_data:&mut YARA_DATA,rule_file:&str,target_name:&str,address:usize,data_length:usize,rule_id:&str,cond_string_id:&str){
    let mut target = File::open(target_name).unwrap();
    let mut offset = 0;
    let diff;
    if address>user_data.scope_width{
        offset = address-user_data.scope_width;
        diff = user_data.scope_width;
    }else{
        diff = address;
    }
    let _=target.seek(SeekFrom::Start((offset) as u64));
    let mut buf = Vec::new();
    let _=(&target).take((user_data.scope_width*2+data_length) as u64).read_to_end(&mut buf).unwrap();

    let mut out = &mut user_data.out;
/*
    let out = stdout();
    let mut out = BufWriter::new(out);
    let mut out = File::create("out.txt").unwrap();
*/
    let _ = out.write(&format!("[ルールファイル: {}(ルールID : {}/{})] ===> [探索対象ファイル: {}(オフセット(開始 - 終了): 0x{:x} - 0x{:x} = {} バイトにマッチ)]\n",
    //println!("[Rule file: {} (Rule ID: {}/{})] ===> [Search target file: {} (offset (start - end): 0x {:x} - 0x {:x} = {} bytes)]",
        rule_file,rule_id,cond_string_id,target_name,address,address+data_length,data_length).as_bytes());
    print_buffer(&buf[0..diff],&mut out);
    match ConsoleColor::new(){
        Ok(mut con)=>{
            con.red(&mut out);
            print_buffer(&buf[diff..diff+data_length],&mut out);
            con.reset(&mut out);
        },
        Err(_)=>{print_buffer(&buf[diff..diff+data_length],&mut out);}
    }
    
    print_buffer(&buf[diff+data_length..buf.len()],&mut out);
    let _ = out.write(b"\n---------------------------------------------------\n");
}

// バッファを出力するラッパメソッド
fn print_buffer(buf:&[u8],out:&mut std::io::Write){
    let _ = match std::str::from_utf8(buf){
        Ok(s)=>{
            let _= out.write(&format!("{}",s.replace("\r","\\r").replace("\n","\\n")).as_bytes());
        },
        Err(_)=>{
            let mut s = String::new();
            for n in buf{
                if *n>=0x20&&*n<0x7f{
                    s.push_str(&format!("{}",*n as char));
                }else{
                    s.push_str(&format!("\\x{:x}",n));
                }
            }
            let _= out.write(s.as_bytes());
        }
    };
}
