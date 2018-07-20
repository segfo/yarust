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
mod dirwalker;
use dirwalker::*;
extern crate num_cpus;

fn init<'a>()->ArgMatches<'a>{
    let num_validator=|s:String|if s.parse::<usize>().is_ok()==false{
            Err(format!("\"{}\" is Invalid number(parse error)",s).to_owned())
        }else{
            Ok(())
        };

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
        .validator(num_validator)
        .takes_value(true)
        .help("Specify an arbitrary number of bytes before and after display from the matching part (default 20 bytes)"))
    .arg(Arg::with_name("redirect_file_path")
        .long("logfile")
        .short("l")
        .required(false)
        .takes_value(true)
        .help("Specify log file path"))
    .arg(Arg::with_name("threads_count")
        .long("threads")
        .short("t")
        .required(false)
        .validator(num_validator)
        .takes_value(true)
        .help("Specify the count of threads"))
    .get_matches()
}

use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let opt = init();
    let yara=YARA::new();

    let max_threads = match opt.value_of("threads_count"){
        Some(t)=>t.parse::<usize>().unwrap(),
        None=>if yara.get_maxthreads()>num_cpus::get()*2{num_cpus::get()*2}else{yara.get_maxthreads()}
    };
    let mut scanners = Vec::new();
    let file:Arc<Mutex<Box<Write+Send>>>;
    let logmode=opt.is_present("redirect_file_path");

    if logmode{
        file = Arc::new(Mutex::new(Box::new(File::create(opt.value_of("redirect_file_path").unwrap()).unwrap())));
    }else{
        file = Arc::new(Mutex::new(Box::new(stdout())));

    }

    let scope_width:usize = opt.value_of("scope_width").unwrap_or("0").parse::<usize>().unwrap();

    for _ in 0..max_threads{
        let mut scanner = Arc::new(Mutex::new(yara.get_scanner_instance(file.clone())));
        let rule_path = opt.value_of("rule_file").unwrap();
        if let Err(e) = scanner.lock().unwrap().load_rule(rule_path){
            eprintln!("Rule load error : \"{}\" {}",rule_path,e);
            return;
        }
        scanner.lock().unwrap().set_callback_match(callback_matching);
        scanner.lock().unwrap().set_scope_width(scope_width);
        if logmode{scanner.lock().unwrap().set_coloring(false);}
        scanners.push(scanner);
    }
    let scanner=&scanners[0];

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
            Err(_)=>{
                scanner.lock().unwrap().do_scanfile(&dir.path);
                return;
            }
        };
        if walker.dir_list.len()==0{break;}
    }
    let mut th_list = Vec::new();
    
    // ディレクトリ配下にあるファイルをすべてスキャンする
    let mut use_scanners = 0;
    for p in path{
        let p=p.clone();
        let scanner=scanners[use_scanners].clone();
        use_scanners+=1;
        let th = thread::spawn(move || {
            let mut scanner=scanner.lock().unwrap();
            if logmode{
                println!("{} scanning...",p.to_str().unwrap());
            }
            scanner.do_scanfile(p.to_str().unwrap());
            scanner.finalize_thread();
        });
        th_list.push(th);
        // ループ中にスレッドの最大数を上回らないように調整するWait
        if th_list.len()>=scanners.len(){
            join_wait(&mut th_list,&mut use_scanners);
        }
    }
    // スレッド数が最大数未満のとき、スレッドの終了を待つWait
    // スレッド数が最大数と同一の場合は、何もしない
    join_wait(&mut th_list,&mut use_scanners);
}

fn join_wait(th_list:&mut Vec<std::thread::JoinHandle<()>>,use_scanners:&mut usize){
    if *use_scanners>0{
        for _ in (0..*use_scanners){
            let th = th_list.pop().unwrap();
            let _ = th.join();
            if th_list.len()==0{break;}
        }
    }
    *use_scanners=0;
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

use std::io::{stdout, Write};
// 一致したデータの該当部分周辺と該当箇所を表示するメソッド
fn print_result(user_data:&mut YARA_DATA,rule_file:&str,target_name:&str,address:usize,data_length:usize,rule_id:&str,cond_string_id:&str){
    let mut out = &mut user_data.out.lock().unwrap();

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

/*
    let out = stdout();
    let mut out = BufWriter::new(out);
    let mut out = File::create("out.txt").unwrap();
*/
    let _ = out.write(&format!("[ルールファイル: {}(ルールID : {}/{})] ===> [探索対象ファイル: {}(オフセット(開始 - 終了): 0x{:x} - 0x{:x} = {} バイトにマッチ)]\n",
    //println!("[Rule file: {} (Rule ID: {}/{})] ===> [Search target file: {} (offset (start - end): 0x {:x} - 0x {:x} = {} bytes)]",
        rule_file,rule_id,cond_string_id,target_name,address,address+data_length,data_length).as_bytes());
    print_buffer(&buf[0..diff],&mut out);

    let con = ConsoleColor::new();
    if con.is_ok()&&user_data.coloring{
        let mut con = con.unwrap();
        con.red(&mut out);
        print_buffer(&buf[diff..diff+data_length],&mut out);
        con.reset(&mut out);
    }else{
        print_buffer(&buf[diff..diff+data_length],&mut out);
    }

    print_buffer(&buf[diff+data_length..buf.len()],&mut out);
    let _ = out.write(b"\n---------------------------------------------------\n");
}

// バッファを出力するラッパメソッド
fn print_buffer(buf:&[u8],out:&mut (std::sync::MutexGuard<Box<std::io::Write+Send>>)){
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
