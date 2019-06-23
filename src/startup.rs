use clap::*;

pub fn init<'a>()->ArgMatches<'a>{
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
