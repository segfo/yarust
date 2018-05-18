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
                // ディレクトリの場合は、ディレクトリリストに保存
                self.dir_list.push(DirectoryInfo{path:entry.path().into_os_string().into_string().unwrap()});
            }else{
                // メソッドの戻り値としてファイルリストを構築
                filelist.push(entry.path());
            }
        }
        Ok(())
    }
}