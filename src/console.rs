extern crate wincolor;
use std;
use std::io::Write;
use self::wincolor::{Console, Color, Intense};
use std::error::Error;

#[cfg(any(windows))]
pub struct ConsoleColor{
    con:Console
}

#[cfg(any(windows))]
impl ConsoleColor{
    pub fn new()->Result<Self,Box<Error>>{
        let con = Console::stdout()?;
        Ok(ConsoleColor{con:con})
    }
    pub fn red(&mut self){
        std::io::stdout().flush();
        self.con.fg(Intense::Yes,Color::Red).unwrap();
    }
    pub fn reset(&mut self){
        std::io::stdout().flush();
        self.con.reset();
    }
}
// linux
#[cfg(any(unix))]
pub struct ConsoleColor{

}

#[cfg(any(unix))]
impl ConsoleColor{
    pub fn new()->Self{
        ConsoleColor{}
    }
    pub fn red(&mut self){
    }
    pub fn reset(&mut self){
    }
}
