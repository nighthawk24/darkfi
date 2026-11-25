/* This file is part of DarkFi (https://dark.fi)
 *
 * Copyright (C) 2020-2026 Dyne.org foundation
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::{
    fmt::Debug,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use futures::{AsyncReadExt, AsyncWriteExt};
use smol::net::TcpStream;
use tracing::debug;
use url::Url;

/// SOCKS5 dialer
#[derive(Clone, Debug)]
pub struct Socks5Dialer {
    client: Socks5Client,
    endpoint: AddrKind,
}

impl Socks5Dialer {
    /// Instantiate a new [`Socks5Dialer`] with given URI
    pub(crate) async fn new(uri: &Url) -> io::Result<Self> {
        // URIs in the form of: socks5://[user:pass@]proxy:port/destination:port
        let auth_user = uri.username();
        let auth_pass = uri.password();

        // Parse destination
        let path = uri
            .path()
            .strip_prefix('/')
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut dest = path.split(':');

        let Some(dest_host) = dest.next() else { return Err(io::ErrorKind::InvalidInput.into()) };
        let Some(dest_port) = dest.next() else { return Err(io::ErrorKind::InvalidInput.into()) };

        let dest_port: u16 = match dest_port.parse() {
            Ok(v) => v,
            Err(_) => return Err(io::ErrorKind::InvalidData.into()),
        };

        let proxy_host = uri
            .host_str()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let proxy_port = uri
            .port()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;

        let client = if !auth_user.is_empty() || auth_pass.is_some() {
            let pass = auth_pass.unwrap_or("");
            if auth_user.len() > u8::MAX as usize || pass.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS5 username/password exceeds 255 bytes",
                ))
            }
            Socks5Client::with_auth(proxy_host, proxy_port, auth_user, pass)
        } else {
            Socks5Client::new(proxy_host, proxy_port)
        };
        let endpoint: AddrKind = (dest_host, dest_port).into();

        Ok(Self { client, endpoint })
    }

    /// Internal dial function
    pub(crate) async fn do_dial(&self) -> io::Result<TcpStream> {
        debug!(
            target: "net::socks5::do_dial",
            "Dialing {:?} with SOCKS5...", self.endpoint,
        );

        self.client.connect(self.endpoint.clone()).await
    }
}

/// SOCKS5 proxy client
#[derive(Clone, Debug)]
pub struct Socks5Client {
    /// SOCKS5 server host
    host: String,
    /// SOCKS5 server port
    port: u16,
    /// Optional RFC 1929 username/password credentials
    auth: Option<(String, String)>,
}

impl Socks5Client {
    /// Instantiate a new SOCKS5 client from given host and port
    pub fn new(host: &str, port: u16) -> Self {
        Self { host: String::from(host), port, auth: None }
    }

    /// Instantiate a new SOCKS5 client with RFC 1929 username/password authentication
    pub fn with_auth(host: &str, port: u16, username: &str, password: &str) -> Self {
        Self {
            host: String::from(host),
            port,
            auth: Some((String::from(username), String::from(password))),
        }
    }

    /// Connect an instantiated SOCKS5 client to the given destination
    pub async fn connect(&self, addr: impl Into<AddrKind> + Debug) -> io::Result<TcpStream> {
        let addr: AddrKind = addr.into();

        // Connect to the SOCKS proxy
        let mut stream = TcpStream::connect(&format!("{}:{}", self.host, self.port)).await?;

        // Send version identifier/method selection message
        if let Some((ref username, ref password)) = self.auth {
            let user_bytes = username.as_bytes();
            let pass_bytes = password.as_bytes();
            if user_bytes.len() > u8::MAX as usize || pass_bytes.len() > u8::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS5 username/password exceeds 255 bytes",
                ))
            }

            // VER=5, NMETHODS=1, METHOD=USERNAME/PASSWORD (0x02)
            stream.write_all(&[0x05, 0x01, 0x02]).await?;
            stream.flush().await?;

            // Read server method selection message
            let mut buf = [0u8; 2];
            stream.read_exact(&mut buf).await?;
            if buf[0] != 0x05 || buf[1] != 0x02 {
                return Err(io::ErrorKind::PermissionDenied.into())
            }

            // RFC 1929 subnegotiation: VER=1, ULEN, UNAME, PLEN, PASSWD
            let mut auth_req = Vec::with_capacity(3 + user_bytes.len() + pass_bytes.len());
            auth_req.push(0x01);
            auth_req.push(user_bytes.len() as u8);
            auth_req.extend_from_slice(user_bytes);
            auth_req.push(pass_bytes.len() as u8);
            auth_req.extend_from_slice(pass_bytes);
            stream.write_all(&auth_req).await?;
            stream.flush().await?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await?;
            if auth_resp[0] != 0x01 || auth_resp[1] != 0x00 {
                return Err(io::ErrorKind::PermissionDenied.into())
            }
        } else {
            // VER=5, NMETHODS=1, METHOD=NO_AUTH (0x00)
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
            stream.flush().await?;

            // Read server method selection message
            let mut buf = [0u8; 2];
            stream.read_exact(&mut buf).await?;
            if buf[0] != 0x05 || buf[1] != 0x00 {
                return Err(io::ErrorKind::ConnectionRefused.into())
            }
        }

        // Build CONNECT request

        // VER=5, CMD=CONNECT, RSV
        let mut reqbuf = vec![0x05, 0x01, 0x00];

        match addr {
            AddrKind::Ip(socketaddr) => {
                if socketaddr.is_ipv4() {
                    // ATYP=0x01
                    reqbuf.push(0x01);
                } else {
                    // ATYP=0x04
                    reqbuf.push(0x04);
                }
                // DST.ADDR
                match socketaddr.ip() {
                    IpAddr::V4(ip) => reqbuf.extend_from_slice(&ip.octets()),
                    IpAddr::V6(ip) => reqbuf.extend_from_slice(&ip.octets()),
                }
                // DST.PORT
                reqbuf.extend_from_slice(&socketaddr.port().to_be_bytes());
            }
            AddrKind::Domain(ref host, port) => {
                // ATYP=0x03
                reqbuf.push(0x03);
                // DST.ADDR
                reqbuf.push(host.len() as u8);
                reqbuf.extend_from_slice(host.as_bytes());
                // DST.PORT
                reqbuf.extend_from_slice(&port.to_be_bytes());
            }
        };

        // Send it
        stream.write_all(&reqbuf).await?;
        stream.flush().await?;
        debug!(
            target: "net::transport::socks5::connect",
            "Flushed CONNECT({addr:?}) request"
        );

        // Handle the SOCKS server reply
        let mut buf = [0u8];
        stream.read_exact(&mut buf).await?;
        debug!(
            target: "net::transport::socks5::connect",
            "REPLY - Version: {:#02x}", buf[0],
        );

        if buf[0] != 0x05 {
            return Err(io::ErrorKind::ConnectionRefused.into())
        }

        buf[0] = 0x00;
        stream.read_exact(&mut buf).await?;
        debug!(
            target: "net::transport::socks5::connect",
            "REPLY - Reply: {:#02x}", buf[0],
        );
        match buf[0] {
            0x00 => {}
            0x01 => return Err(io::ErrorKind::ConnectionAborted.into()),
            0x02 => return Err(io::ErrorKind::PermissionDenied.into()),
            0x03 => return Err(io::ErrorKind::NetworkUnreachable.into()),
            0x04 => return Err(io::ErrorKind::HostUnreachable.into()),
            0x05 => return Err(io::ErrorKind::ConnectionRefused.into()),
            0x06 => return Err(io::ErrorKind::TimedOut.into()),
            0x07 => return Err(io::ErrorKind::Unsupported.into()),
            0x08 => return Err(io::ErrorKind::Unsupported.into()),
            _ => return Err(io::ErrorKind::ConnectionAborted.into()),
        }

        // Read RSV
        stream.read_exact(&mut buf).await?;

        // Read ATYP
        buf[0] = 0x00;
        stream.read_exact(&mut buf).await?;
        debug!(
            target: "net::transport::socks5::connect",
            "REPLY - ATYP: {:#02x}", buf[0],
        );

        // Read BND.ADDR accordingly
        match buf[0] {
            // IPv4
            0x01 => {
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await?;
                debug!(
                    target: "net::transport::socks5::connect",
                    "REPLY - BND.ADDR: {}", Ipv4Addr::from(buf),
                );
            }
            // IPv6
            0x04 => {
                let mut buf = [0u8; 16];
                stream.read_exact(&mut buf).await?;
                debug!(
                    target: "net::transport::socks5::connect",
                    "REPLY - BND.ADDR: {}", Ipv6Addr::from(buf),
                );
            }
            // Domain
            0x03 => {
                let mut len = [0u8];
                stream.read_exact(&mut len).await?;
                let mut buf = vec![0u8; len[0] as usize];
                stream.read_exact(&mut buf).await?;
                debug!(
                    target: "net::transport::socks5::connect",
                    "REPLY - BND.ADDR: {}", String::from_utf8_lossy(&buf),
                );
            }

            _ => return Err(io::ErrorKind::ConnectionAborted.into()),
        };

        // Read BND.PORT
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        debug!(
            target: "net::transport::socks5::connect",
            "REPLY - BND.PORT: {}", u16::from_be_bytes(buf),
        );

        Ok(stream)
    }
}

#[derive(Clone, Debug)]
pub enum AddrKind {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl From<(IpAddr, u16)> for AddrKind {
    fn from(value: (IpAddr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv4Addr, u16)> for AddrKind {
    fn from(value: (Ipv4Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(Ipv6Addr, u16)> for AddrKind {
    fn from(value: (Ipv6Addr, u16)) -> Self {
        Self::Ip(value.into())
    }
}

impl From<(String, u16)> for AddrKind {
    fn from((domain, port): (String, u16)) -> Self {
        Self::Domain(domain, port)
    }
}

impl From<(&'_ str, u16)> for AddrKind {
    fn from((domain, port): (&'_ str, u16)) -> Self {
        Self::Domain(domain.to_owned(), port)
    }
}

impl From<SocketAddr> for AddrKind {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl From<SocketAddrV4> for AddrKind {
    fn from(value: SocketAddrV4) -> Self {
        Self::Ip(value.into())
    }
}

impl From<SocketAddrV6> for AddrKind {
    fn from(value: SocketAddrV6) -> Self {
        Self::Ip(value.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smol::net::TcpListener;

    #[test]
    fn socks5_dialer_parses_optional_rfc1929_credentials() {
        smol::block_on(async {
            let plain = Url::parse("socks5://127.0.0.1:9050/example.onion:9601").unwrap();
            let d_plain = Socks5Dialer::new(&plain).await.unwrap();
            assert!(d_plain.client.auth.is_none());

            let authed = Url::parse("socks5://alice:s3cr3t@127.0.0.1:1080/lilith0.dark.fi:9600").unwrap();
            let d_authed = Socks5Dialer::new(&authed).await.unwrap();
            assert_eq!(d_authed.client.auth, Some(("alice".into(), "s3cr3t".into())));
        });
    }

    #[test]
    fn socks5_client_rfc1929_auth_succeeds_and_rejects_bad_password() {
        smol::block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();

            let server = smol::spawn(async move {
                for _ in 0..2 {
                    let (mut s, _) = listener.accept().await.unwrap();
                    let mut head = [0u8; 2];
                    s.read_exact(&mut head).await.unwrap();
                    assert_eq!(head[0], 0x05);
                    let mut methods = vec![0u8; head[1] as usize];
                    s.read_exact(&mut methods).await.unwrap();
                    assert!(methods.contains(&0x02));
                    s.write_all(&[0x05, 0x02]).await.unwrap();

                    let mut ver_ulen = [0u8; 2];
                    s.read_exact(&mut ver_ulen).await.unwrap();
                    assert_eq!(ver_ulen[0], 0x01);
                    let mut user = vec![0u8; ver_ulen[1] as usize];
                    s.read_exact(&mut user).await.unwrap();
                    let mut plen = [0u8; 1];
                    s.read_exact(&mut plen).await.unwrap();
                    let mut pass = vec![0u8; plen[0] as usize];
                    s.read_exact(&mut pass).await.unwrap();

                    let ok = user == b"alice" && pass == b"goodpass";
                    s.write_all(&[0x01, if ok { 0x00 } else { 0x01 }]).await.unwrap();
                    if !ok {
                        continue;
                    }

                    // Consume CONNECT request and reply success
                    let mut req = [0u8; 4];
                    s.read_exact(&mut req).await.unwrap();
                    assert_eq!(req[0], 0x05);
                    assert_eq!(req[1], 0x01);
                    assert_eq!(req[3], 0x03);
                    let mut dlen = [0u8; 1];
                    s.read_exact(&mut dlen).await.unwrap();
                    let mut domain = vec![0u8; dlen[0] as usize];
                    s.read_exact(&mut domain).await.unwrap();
                    let mut dport = [0u8; 2];
                    s.read_exact(&mut dport).await.unwrap();
                    s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();
                }
            });

            let ok_client = Socks5Client::with_auth("127.0.0.1", port, "alice", "goodpass");
            ok_client.connect(("example.com", 443)).await.unwrap();

            let bad_client = Socks5Client::with_auth("127.0.0.1", port, "alice", "wrong");
            let err = bad_client.connect(("example.com", 443)).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

            server.await;
        });
    }
}
