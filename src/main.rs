extern crate libc;
extern crate clap;
extern crate num_cpus;
mod yara;
use yara::*;
use std::{
    io::{SeekFrom, prelude::*},
    path::*,
    fs::File,
    sync::{Arc, Mutex},
    thread,collections::HashMap,
    sync::{mpsc,mpsc::{Sender, Receiver}}
};
mod console;
use console::*;
mod dirwalker;
use dirwalker::*;
mod resource_pool;
use resource_pool::ResourceAllocator;
mod startup;
use startup::init;

fn main() {
    let opt = init();
    // スキャン結果を格納するファイル
    let scan_result_file:Arc<Mutex<Box<Write+Send>>>;
    let logmode=opt.is_present("redirect_file_path");

    if logmode{
        scan_result_file = Arc::new(Mutex::new(Box::new(File::create(opt.value_of("redirect_file_path").unwrap()).unwrap())));
    }else{
        scan_result_file = Arc::new(Mutex::new(Box::new(stdout())));
    }

    // スキャンの準備（基本はディレクトリ単位で行う）
    eprintln!("directory scanning...");
    let search_path = opt.value_of("search_path").unwrap();
    if Path::new(search_path).exists() == false{
        eprintln!("\"{}\" is not exists",search_path);
        return;
    }

    let mut walker = match DirectoryWalker::new(search_path){
        Ok(walker)=>walker,
        Err(e)=>{
            eprintln!("walker generate fail : {}",e);
            return;
        }
    };

    // YARAインスタンスの準備
    eprintln!("scanner instance generating...");
    let yara=YARA::new();
    let max_threads = match opt.value_of("threads_count"){
        Some(t)=>t.parse::<usize>().unwrap(),
        None=>if yara.get_maxthreads()>num_cpus::get()*2{num_cpus::get()*2}else{yara.get_maxthreads()}
    };

    // スキャナのインスタンスを同時実行スレッド分生成し、ルールをロード・コンパイルする。
    // そのスキャナインスタンスをすべて、リソースプールに登録しておく。
    // 使用側は、リソースプールからここで準備したスキャナを取得する。
    let mut scanner_pool = ResourceAllocator::<PathBuf,std::sync::Arc<std::sync::Mutex<std::boxed::Box<yara::YARA_SCANNER>>>>::new();
    let scope_width:usize = opt.value_of("scope_width").unwrap_or("0").parse::<usize>().unwrap();
    for _ in 0..max_threads{
        let scanner = Arc::new(Mutex::new(yara.get_scanner_instance(scan_result_file.clone())));
        let rule_path = opt.value_of("rule_file").unwrap();
        if let Err(e) = scanner.lock().unwrap().load_rule(rule_path){
            eprintln!("Rule load error : \"{}\" {}",rule_path,e);
            return;
        }
        scanner.lock().unwrap().set_callback_match(callback_matching);
        scanner.lock().unwrap().set_scope_width(scope_width);
        if logmode{scanner.lock().unwrap().set_coloring(false);}
        scanner_pool.register_resource_pool(scanner);
    }
    eprintln!("scanning...");
    // ディレクトリの走査を行う。（再帰的に行う）
    let mut path = Vec::<PathBuf>::new();
    loop{
        let dir=walker.dir_list.pop().unwrap();
        // ファイルが指定されたときはError。
        // 単一ファイルをとりあえずスキャンして終わる
        match walker.dir_walk(&dir,&mut path){
            Ok(_)=>{},
            Err(_)=>{
                let scanner=scanner_pool.get(PathBuf::from(dir.path.clone())).unwrap();
                scanner.lock().unwrap().do_scanfile(&dir.path);
                return;
            }
        };
        if walker.dir_list.len()==0{break;}
    }

    // ここからスキャンを実施する。
    // スレッドリストを格納するハッシュマップを用意する。
    // スレッドが完了したらこのマップから削除する。
    let mut th_list = HashMap::new();
    // ディレクトリ配下にあるファイルをすべてスキャンする
    let (tx, rx): (Sender<(thread::ThreadId,PathBuf)>, Receiver<(thread::ThreadId,PathBuf)>) = mpsc::channel();
    for p in path.clone(){
        let p = p.clone();
        // スキャナをプールから取得し、Arcの参照カウントを増やす（クローン）
        let scanner = scanner_pool.get(p.clone()).unwrap().clone();
        let tx = tx.clone();
        // スレッドを生成する。
        let th = thread::spawn(move || {
            let mut scanner = scanner.lock().unwrap();
            if logmode{
                println!("{} scanning...",p.to_str().unwrap());
            }
            scanner.do_scanfile(p.to_str().unwrap());
            scanner.finalize_thread();
            // メインループにメッセージ送信。
            tx.send((thread::current().id(),p.clone())).unwrap();
        });
        th_list.insert(th.thread().id(),th);
        // ループ中にスキャナプールの最大数を上回らないように調整するWait
        // スレッドが終了したら、当該スレッドのスキャナを返却して、新たなスレッドを生成する。
        if th_list.len()>=max_threads{
            let (tid,filename) = rx.recv().unwrap();
            let filename = filename.to_path_buf().clone();
            scanner_pool.free(filename.clone());
            th_list.remove(&tid);
            if logmode{
                println!("done : {}",filename.to_str().unwrap());
            }
        }
    }
    // スレッド数が最大数未満のとき、スレッドの終了を待つWait
    // スレッド数が最大数と同一の場合は、何もしない
    for _ in 0..th_list.len(){
        let (_,filename) = rx.recv().unwrap();
        scanner_pool.free(filename.clone());
        if logmode{
            println!("done : {}",filename.to_str().unwrap());
        }
    }
    eprintln!("scan total : {} files",path.len());
    eprintln!("finalizing...");
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
