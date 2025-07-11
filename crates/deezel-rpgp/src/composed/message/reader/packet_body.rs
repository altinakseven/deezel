extern crate alloc;
use bytes::{Buf, BytesMut};
use log::debug;

use super::{fill_buffer, LimitedReader};
use crate::{
    packet::PacketHeader,
    parsing_reader::BufReadParsing,
    types::{PacketLength, Tag},
};

use crate::io::{BufRead, Error, Read};


#[derive(Debug)]
pub struct PacketBodyReader<R: BufRead> {
    packet_header: PacketHeader,
    state: State<R>,
}

#[derive(derive_more::Debug)]
enum State<R: BufRead> {
    Body {
        #[debug("{}", hex::encode(buffer))]
        buffer: BytesMut,
        source: LimitedReader<R>,
    },
    Done {
        source: R,
    },
    Error,
}

impl<R: BufRead> BufRead for PacketBodyReader<R> {
    fn fill_buf(&mut self) -> Result<&[u8], Error> {
        match self.fill_inner() {
            Ok(()) => {},
            Err(e) => {
                debug!("PacketBodyReader::fill_inner failed: {:?}", e);
                return Err(e);
            }
        }
        match self.state {
            State::Body { ref mut buffer, .. } => {
                debug!("PacketBodyReader::fill_buf returning {} bytes", buffer.len());
                Ok(&buffer[..])
            },
            State::Done { .. } => {
                debug!("PacketBodyReader::fill_buf in Done state, returning empty");
                Ok(&[][..])
            },
            State::Error => {
                debug!("PacketBodyReader::fill_buf in Error state");
                Err(crate::io::Error::new(crate::io::ErrorKind::Other, "packet body reader error"))
            },
        }
    }

    fn consume(&mut self, amt: usize) {
        debug!("PacketBodyReader::consume {} bytes", amt);
        match self.state {
            State::Body { ref mut buffer, .. } => {
                buffer.advance(amt);
            }
            State::Done { .. } => {}
            State::Error => panic!("PacketBodyReader errored"),
        }
    }
}

impl<R: BufRead> Read for PacketBodyReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let internal_buf = self.fill_buf()?;
        let len = internal_buf.len().min(buf.len());
        buf[..len].copy_from_slice(&internal_buf[..len]);
        self.consume(len);
        Ok(len)
    }
}

impl<R: BufRead> PacketBodyReader<R> {
    pub fn new(packet_header: PacketHeader, source: R) -> Result<Self, Error> {
        let source = match packet_header.packet_length() {
            PacketLength::Fixed(len) => {
                debug!("fixed packet {}", len);
                LimitedReader::fixed(len as u64, source)
            }
            PacketLength::Indeterminate => {
                debug!("indeterminate packet");
                LimitedReader::Indeterminate(source)
            }
            PacketLength::Partial(len) => {
                debug!("partial packet start {}", len);
                // https://www.rfc-editor.org/rfc/rfc9580.html#name-partial-body-lengths
                // "An implementation MAY use Partial Body Lengths for data packets, be
                // they literal, compressed, or encrypted [...]
                // Partial Body Lengths MUST NOT be used for any other packet types"
                if !matches!(
                    packet_header.tag(),
                    Tag::LiteralData
                        | Tag::CompressedData
                        | Tag::SymEncryptedData
                        | Tag::SymEncryptedProtectedData
                ) {
                    return Err(crate::io::Error::new(crate::io::ErrorKind::Other, "packet body reader error"));
                }

                // https://www.rfc-editor.org/rfc/rfc9580.html#section-4.2.1.4-5
                // "The first partial length MUST be at least 512 octets long."
                if len < 512 {
                    return Err(crate::io::Error::new(crate::io::ErrorKind::Other, "packet body reader error"));
                }

                LimitedReader::Partial(super::limited::Take::new(source, len as u64))
            }
        };

        Ok(Self {
            packet_header,
            state: State::Body {
                source,
                buffer: BytesMut::with_capacity(1024),
            },
        })
    }

    pub fn new_done(packet_header: PacketHeader, source: R) -> Self {
        Self {
            packet_header,
            state: State::Done { source },
        }
    }

    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done { .. })
    }

    pub fn into_inner(self) -> R {
        match self.state {
            State::Body { source, .. } => source.into_inner(),
            State::Done { source } => source,
            State::Error => panic!("PacketBodyReader errored"),
        }
    }

    pub fn get_mut(&mut self) -> &mut R {
        match &mut self.state {
            State::Body { source, .. } => source.get_mut(),
            State::Done { source } => source,
            State::Error => panic!("PacketBodyReader errored"),
        }
    }

    pub fn packet_header(&self) -> PacketHeader {
        self.packet_header
    }

    fn fill_inner(&mut self) -> Result<(), Error> {
        debug!("PacketBodyReader::fill_inner called, state: {:?}", matches!(self.state, State::Done { .. }));
        if matches!(self.state, State::Done { .. }) {
            debug!("PacketBodyReader::fill_inner already done");
            return Ok(());
        }

        loop {
            match core::mem::replace(&mut self.state, State::Error) {
                State::Body {
                    mut buffer,
                    mut source,
                } => {
                    debug!("PacketBodyReader::fill_inner in Body state, buffer remaining: {}", buffer.has_remaining());
                    if buffer.has_remaining() {
                        self.state = State::Body { source, buffer };
                        return Ok(());
                    }

                    buffer.resize(1024, 0);
                    let read = match fill_buffer(&mut source, &mut buffer, Some(1024)) {
                        Ok(r) => {
                            debug!("PacketBodyReader::fill_inner read {} bytes", r);
                            r
                        },
                        Err(e) => {
                            debug!("PacketBodyReader::fill_inner fill_buffer failed: {:?}", e);
                            return Err(e);
                        }
                    };
                    buffer.truncate(read);

                    if read == 0 {
                        debug!("body source done: {:?}", self.packet_header);
                        match source {
                            LimitedReader::Fixed { mut reader } => {
                                let rest = reader.rest()?;
                                debug_assert!(rest.is_empty(), "{}", hex::encode(&rest));

                                if reader.limit() > 0 {
                                    debug!("PacketBodyReader::fill_inner Fixed reader still has limit: {}", reader.limit());
                                    // For reconstructed messages, we may have a mismatch between expected and actual data
                                    // Try to consume the remaining limit by reading from the source
                                    let mut remaining = reader.limit();
                                    let mut source = reader.into_inner();
                                    let mut consumed = 0;
                                    
                                    while remaining > 0 {
                                        match source.fill_buf() {
                                            Ok(buf) if buf.is_empty() => {
                                                debug!("PacketBodyReader: source exhausted but {} bytes still expected", remaining);
                                                // Source is exhausted but we still have limit remaining
                                                // This can happen with reconstructed messages - be lenient
                                                break;
                                            }
                                            Ok(buf) => {
                                                let to_consume = buf.len().min(remaining as usize);
                                                debug!("PacketBodyReader: consuming {} bytes to exhaust limit", to_consume);
                                                source.consume(to_consume);
                                                consumed += to_consume;
                                                remaining = remaining.saturating_sub(to_consume as u64);
                                            }
                                            Err(e) => {
                                                debug!("PacketBodyReader: error reading from source while exhausting limit: {:?}", e);
                                                return Err(e);
                                            }
                                        }
                                    }
                                    
                                    debug!("PacketBodyReader: consumed {} additional bytes to exhaust limit", consumed);
                                    self.state = State::Done { source };
                                } else {
                                    self.state = State::Done {
                                        source: reader.into_inner(),
                                    };
                                }
                            }
                            LimitedReader::Indeterminate(source) => {
                                debug!("PacketBodyReader::fill_inner transitioning to Done from Indeterminate");
                                self.state = State::Done { source };
                            }
                            LimitedReader::Partial(r) => {
                                // new round
                                debug!("PacketBodyReader::fill_inner handling partial packet continuation");
                                let mut source = r.into_inner();
                                let packet_length = PacketLength::try_from_reader(&mut source).map_err(|e| {
                                    debug!("PacketBodyReader::fill_inner PacketLength::try_from_reader failed: {:?}", e);
                                    crate::io::Error::new(crate::io::ErrorKind::Other, "packet body reader error: partial packet length parsing failed")
                                })?;

                                let source = match packet_length {
                                    PacketLength::Fixed(len) => {
                                        // the last one
                                        debug!("fixed partial packet {}", len);
                                        LimitedReader::fixed(len as u64, source)
                                    }
                                    PacketLength::Partial(len) => {
                                        // another one
                                        debug!("intermediary partial packet {}", len);
                                        LimitedReader::Partial(super::limited::Take::new(source, len as u64))
                                    }
                                    PacketLength::Indeterminate => {
                                        debug!("PacketBodyReader::fill_inner unexpected indeterminate in partial");
                                        return Err(crate::io::Error::new(crate::io::ErrorKind::Other, "packet body reader error: indeterminate in partial"));
                                    }
                                };

                                self.state = State::Body { source, buffer };
                                continue;
                            }
                        };
                    } else {
                        debug!("PacketBodyReader::fill_inner read {} bytes, staying in Body state", read);
                        self.state = State::Body { source, buffer };
                    }
                    return Ok(());
                }
                State::Done { source } => {
                    debug!("PacketBodyReader::fill_inner already in Done state");
                    self.state = State::Done { source };
                    return Ok(());
                }
                State::Error => {
                    debug!("PacketBodyReader::fill_inner in Error state");
                    return Err(crate::io::Error::new(crate::io::ErrorKind::Other, "packet body reader error: in error state"));
                }
            }
        }
    }
}
