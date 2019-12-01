extern crate reqwest;
extern crate regex;
extern crate sha1;
#[cfg(test)]
extern crate mockito;

use regex::Regex;
use sha1::{Sha1, Digest};
use std::error;
use std::fmt;


#[derive(Debug)]
pub struct PwnedError {
    pub uses: i32,
}

impl PwnedError {
    fn new(uses: i32) -> PwnedError {
        PwnedError{ uses }
    }
}

impl error::Error for PwnedError {
    fn description(&self) -> &str {
        "Password has been Pwned"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

impl fmt::Display for PwnedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Password has been Pwned {} times", self.uses)
    }
}


#[derive(Debug)]
pub enum Error {
    Pwned(PwnedError),
    Parse(std::num::ParseIntError),
    Reqwest(reqwest::Error),
    Regex(regex::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Pwned(ref err) => write!(f, "Pwned error: {}", err),
            Error::Parse(ref err) => write!(f, "Parse error: {}", err),
            Error::Reqwest(ref err) => write!(f, "Reqwest error: {}", err),
            Error::Regex(ref err) => write!(f, "Regex error: {}", err),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Pwned(ref err) => err.description(),
            Error::Parse(ref err) => err.description(),
            Error::Reqwest(ref err) => err.description(),
            Error::Regex(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Pwned(ref err) => Some(err),
            Error::Parse(ref err) => Some(err),
            Error::Reqwest(ref err) => Some(err),
            Error::Regex(ref err) => Some(err),
        }
    }
}

impl From<PwnedError> for Error {
    fn from(err: PwnedError) -> Error {
        Error::Pwned(err)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(err: std::num::ParseIntError) -> Error {
        Error::Parse(err)
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error::Reqwest(err)
    }
}

impl From<regex::Error> for Error {
    fn from(err: regex::Error) -> Error {
        Error::Regex(err)
    }
}


pub fn check(password: String) -> Result<(), Error> {
    let hash = hash(password);
    
    #[cfg(not(test))]
    let url = format!("https://api.pwnedpasswords.com/range/{}", hash.0);
    #[cfg(test)]
    let url = format!("{}/range/{}", mockito::server_url(), hash.0);

    let response = reqwest::get(&url)?.text()?;
    let reg = Regex::new(&format!(r"{}:(\d+)", hash.1))?;

    match reg.captures(&response) {
        Some(c) => {
            let uses: i32 = c.get(1).map_or("", |m| m.as_str()).parse()?;
            Err(Error::Pwned(<PwnedError>::new(uses)))
        },
        None => Ok(())
    }
}

fn hash(password: String) -> (String, String) {
    let hash = Sha1::new()
        .chain(password)
        .result();
    let hex = format!("{:X}", hash);
    (hex[0..5].to_string(), hex.clone()[5..].to_string())
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_hashes() {
        use super::hash;

        let hashed = hash("test".to_string());
        
        assert_eq!(hashed.0.chars().count(), 5);
        assert_eq!(hashed.1.chars().count(), 35);
    }

    #[test]
    fn it_checks_with_ok() {
        use super::check;
        use mockito::mock;

        // A94A8 is 0..5 of 'test' SHA1 
        // FE5CCB19BA61C4C0873D391E987982FBBD3 is 5.. of 'test' SHA1

        let _m = mock("GET", "/range/A94A8")
            .with_status(200)
            .with_body("
FD8D510BFF2210462F26307C2143E990E6E:2
FDFAEE848356AD27F8FB494E5C1B11956C2:2
FF36DC7D3284A39991ADA90CAF20D1E3C0D:1
FFF983A91443AE72BD98E59ADAB93B31974:2
")
            .create();

        let checked = check("test".to_string());
        assert!(checked.is_ok());
    }

    #[test]
    fn it_checks_with_err() {
        use super::check;
        use super::Error;
        use mockito::mock;

        // A94A8 is 0..5 of 'test' SHA1 
        // FE5CCB19BA61C4C0873D391E987982FBBD3 is 5.. of 'test' SHA1

        let _m = mock("GET", "/range/A94A8")
            .with_status(200)
            .with_body("
FD8D510BFF2210462F26307C2143E990E6E:2
FDFAEE848356AD27F8FB494E5C1B11956C2:2
FE5CCB19BA61C4C0873D391E987982FBBD3:42
FF36DC7D3284A39991ADA90CAF20D1E3C0D:1
FFF983A91443AE72BD98E59ADAB93B31974:2
")
            .create();

        let err: Error = check("test".to_string()).unwrap_err();

        match err {
            Error::Pwned(ref err) => assert_eq!(err.uses, 42),
            _ => panic!("Wrong error type"),
        };
    }
}
