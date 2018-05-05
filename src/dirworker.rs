use std::fs::DirEntry;
use std::io;
use std::fs;
use std::path::*;

pub struct DirectoryInfo{
    pub path:String,
}

pub struct DirectoryWalker{
    pub dir_list:Vec<DirectoryInfo>,
    pub current_dir_mode:u32,
    pub root_dir:String,
}

//ディレクトリ走査を行うための実装
impl DirectoryWalker{
    pub fn new(root_dir:&str)->io::Result<DirectoryWalker>{
        let mut dir_list = Vec::<DirectoryInfo>::new();
        // アクセス権限は、上位ディレクトリのものを継承する。
        dir_list.push(DirectoryInfo{path:root_dir.to_owned()});
        let dw = DirectoryWalker{
            dir_list:dir_list,
            current_dir_mode:0,
            root_dir:root_dir.to_owned(),
        };
        Ok(dw)
    }
    
    pub fn dir_walk(&mut self,dir:&DirectoryInfo,filelist:&mut Vec<PathBuf>) -> io::Result<()> {
        let parent=dir;
        let dir=Path::new(&dir.path);
        for entry in fs::read_dir(dir)?{
            let entry = entry?;
            if entry.path().is_dir() {
                // ファイルの可視性を仮想的に実装する。
                // パーミッションの継承を行う。
                self.dir_list.push(DirectoryInfo{path:entry.path().into_os_string().into_string().unwrap()});
            }else{
                // self : 現在のディレクトリのパーミッションと検索開始ディレクトリのパーミッション
                // entry : ファイルの情報（パスとファイルシステムから取得できるパーミッション）
                // parent : 親ディレクトリ（パスと論理パーミッション（継承されたもの））
                //cb_file(&self,entry,parent)?;
                filelist.push(entry.path());
            }
        }
        Ok(())
    }
}