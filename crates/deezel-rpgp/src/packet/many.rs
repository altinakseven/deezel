extern crate alloc;
use log::debug;

use crate::{
    composed::PacketBodyReader,
    errors::{Error, Result},
    packet::{Packet, PacketHeader},
};

use crate::io::BufRead;

pub struct PacketParser<R: BufRead> {
    /// The reader that gets advanced through the original source
    reader: R,
    /// Are we done?
    is_done: bool,
}

impl<R: BufRead> PacketParser<R> {
    pub fn new(source: R) -> Self {
        PacketParser {
            reader: source,
            is_done: false,
        }
    }

    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<'a, R: BufRead> Iterator for PacketParser<R> {
    type Item = Result<Packet>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_done {
            debug!("PacketParser is done");
            return None;
        }

        debug!("PacketParser: attempting to read header");
        let header = match PacketHeader::try_from_reader(&mut self.reader) {
            Ok(header) => {
                debug!("PacketParser: successfully read header: {header:?}");
                header
            },
            Err(err) => {
                debug!("PacketParser: failed to read header: {:?}", err);
                self.is_done = true;
                if err.kind() == crate::io::ErrorKind::UnexpectedEof {
                    debug!("PacketParser: EOF reached");
                    return None;
                }

                return Some(Err(err.into()));
            }
        };

        debug!("found header: {header:?}");
        let res = PacketBodyReader::new(header, &mut self.reader)
            .map_err(Error::from)
            .and_then(|mut body| {
                match Packet::from_reader(header, &mut body) {
                    Ok(packet) => Ok(packet),
                    Err(Error::PacketParsing { source, .. }) if source.is_incomplete() => {
                        debug!("incomplete packet for: {:?}", source);
                        // not bailing, we are just skipping incomplete bodies
                        Err(Error::PacketIncomplete {
                            source,
                            #[cfg(feature = "std")]
                            backtrace: snafu::GenerateImplicitData::generate(),
                        })
                    }
                    Err(err) => Err(err),
                }
            });
        Some(res)
    }
}

impl<'a, R: BufRead> PacketParser<R> {
    pub fn next_ref(&mut self) -> Option<Result<PacketBodyReader<&'_ mut R>>> {
        if self.is_done {
            return None;
        }

        let header = match PacketHeader::try_from_reader(&mut self.reader) {
            Ok(header) => header,
            Err(err) => {
                if err.kind() == crate::io::ErrorKind::UnexpectedEof {
                    return None;
                }

                self.is_done = true;
                return Some(Err(err.into()));
            }
        };

        debug!("found header: {header:?}");
        let body = PacketBodyReader::new(header, &mut self.reader).map_err(Into::into);
        Some(body)
    }

    pub fn next_owned(mut self) -> Option<Result<PacketBodyReader<R>>> {
        if self.is_done {
            return None;
        }

        let header = match PacketHeader::try_from_reader(&mut self.reader) {
            Ok(header) => header,
            Err(err) => {
                self.is_done = true;
                return Some(Err(err.into()));
            }
        };

        debug!("found header: {header:?}");
        let body = PacketBodyReader::new(header, self.reader).map_err(Into::into);
        Some(body)
    }
}
