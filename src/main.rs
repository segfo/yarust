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
    .get_matches()
}

fn main() {
    let opt = init();
    let scope_width = 
        if opt.is_present("scope_width"){
            opt.value_of("scope_width").unwrap().parse().unwrap()
        }else{0};

    let a=YARA::new();
    let mut a = a.get_scanner_instance();
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

// 一致した際に呼ばれるコールバックメソッド
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
    print_result(data,&rulefile,&target,address,datalength,rule_id);
    return 0;
}

// 一致したデータの該当部分周辺と該当箇所を表示するメソッド
fn print_result(user_data:&YARA_DATA,rule_file:&str,target_name:&str,address:usize,data_length:usize,rule_id:&str){
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
    
    println!("[ルールファイル: {}(ルールID : {})] ===> [探索対象ファイル: {}(オフセット(開始 - 終了): 0x{:x} - 0x{:x} = {} バイトにマッチ)]",
    //println!("[Rule file: {} (Rule ID: {})] ===> [Search target file: {} (offset (start - end): 0x {:x} - 0x {:x} = {} bytes)]",
        rule_file,rule_id,target_name,address,address+data_length,data_length);
    print_buffer(&buf[0..diff]);
    match ConsoleColor::new(){
        Ok(mut con)=>{
            con.red();
            print_buffer(&buf[diff..diff+data_length]);
            con.reset();
        },
        Err(_)=>{print_buffer(&buf[diff..diff+data_length]);}
    }
    print_buffer(&buf[diff+data_length..buf.len()]);
    println!("\n---------------------------------------------------");
}

// バッファを出力するラッパメソッド
fn print_buffer(buf:&[u8]){
    match std::str::from_utf8(buf){
        Ok(s)=>print!("{}",s.replace("\r","\\r").replace("\n","\\n")),
        Err(_)=>{
            let mut s = String::new();
            for n in buf{
                if *n>=0x20&&*n<0x7f{
                    s.push_str(&format!("{}",*n as char));
                }else{
                    s.push_str(&format!("\\x{:x}",n));
                }
            }
            print!("{}",s);
        }
    }
}
