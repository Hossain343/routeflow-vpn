//! Inbound SOCKS5: CONNECT (TCP) and UDP ASSOCIATE, optional username/password (RFC 1929).
use crate::proxy::{self, ConnectError, Flow, Target};
use crate::state::Shared;
use crate::util::{ct_eq, invalid, is_benign};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const OK_REPLY: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

pub async fn handle(st: &Arc<Shared>, mut client: TcpStream, peer: SocketAddr) {
    if let Err(e) = serve(st, &mut client, peer).await {
        if !is_benign(&e) {
            log_warn!("[{}] SOCKS5: {}", peer, e);
        }
    }
    let _ = client.shutdown().await;
}

fn reply_code(e: &ConnectError) -> u8 {
    match e {
        ConnectError::Blocked(_) => 0x02,
        ConnectError::Refused(_) => 0x05,
        ConnectError::Timeout(_) | ConnectError::Dns(_) => 0x04,
        ConnectError::Other(_) => 0x01,
    }
}

async fn fail(client: &mut TcpStream, code: u8) -> io::Result<()> {
    client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    client.flush().await
}

async fn serve(st: &Arc<Shared>, client: &mut TcpStream, peer: SocketAddr) -> io::Result<()> {
    let settings = st.settings.load_full();

    // --- method negotiation
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(invalid("not a SOCKS5 greeting"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).await?;

    if !settings.username.is_empty() {
        if !methods.contains(&2) {
            client.write_all(&[5, 0xFF]).await?;
            client.flush().await?;
            return Err(invalid("the client offered no username/password login but one is required"));
        }
        client.write_all(&[5, 2]).await?;
        let mut v = [0u8; 2];
        client.read_exact(&mut v).await?;
        if v[0] != 1 {
            return Err(invalid("bad login sub-negotiation version"));
        }
        let mut user = vec![0u8; v[1] as usize];
        client.read_exact(&mut user).await?;
        let mut plen = [0u8; 1];
        client.read_exact(&mut plen).await?;
        let mut pass = vec![0u8; plen[0] as usize];
        client.read_exact(&mut pass).await?;
        let ok = ct_eq(&user, settings.username.as_bytes()) & ct_eq(&pass, settings.password.as_bytes());
        client.write_all(&[1, if ok { 0 } else { 1 }]).await?;
        client.flush().await?;
        if !ok {
            log_warn!("[{}] SOCKS5 login rejected (wrong username or password)", peer);
            return Ok(());
        }
    } else {
        if !methods.contains(&0) {
            client.write_all(&[5, 0xFF]).await?;
            client.flush().await?;
            return Err(invalid("the client does not accept 'no login' and none is configured"));
        }
        client.write_all(&[5, 0]).await?;
    }

    // --- request
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;
    if req[0] != 5 {
        return Err(invalid("bad SOCKS5 request version"));
    }
    let host: String = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            client.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut l = [0u8; 1];
            client.read_exact(&mut l).await?;
            let mut n = vec![0u8; l[0] as usize];
            client.read_exact(&mut n).await?;
            match String::from_utf8(n) {
                Ok(s) => s,
                Err(_) => {
                    fail(client, 0x08).await?;
                    return Err(invalid("the requested host name is not valid text"));
                }
            }
        }
        4 => {
            let mut a = [0u8; 16];
            client.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        other => {
            fail(client, 0x08).await?;
            return Err(invalid(format!("unsupported address type {}", other)));
        }
    };
    let mut p = [0u8; 2];
    client.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);

    match req[1] {
        1 => connect(st, client, peer, &host, port).await,
        3 => crate::udp::associate(st, client, peer).await,
        other => {
            fail(client, 0x07).await?;
            let what = if other == 2 { "BIND" } else { "this command" };
            Err(invalid(format!("{} is not supported (only CONNECT and UDP ASSOCIATE)", what)))
        }
    }
}

async fn connect(st: &Arc<Shared>, client: &mut TcpStream, peer: SocketAddr, host: &str, port: u16) -> io::Result<()> {
    let t = Target::new(host, port);
    let (mut remote, first, route) = if proxy::should_sniff(st, &t) {
        match proxy::sniff_connect(st, client, peer, "SOCKS5", &t, &OK_REPLY).await {
            Ok(Some(x)) => x,
            Ok(None) => return Ok(()),
            // the decision and the failure were logged by sniff_connect; the success reply is already sent
            Err(_) => return Ok(()),
        }
    } else {
        match proxy::open_outbound(st, peer, "SOCKS5", &t).await {
            Ok(o) => {
                client.write_all(&OK_REPLY).await?;
                client.flush().await?;
                (o.stream, Vec::new(), o.route)
            }
            Err(e) => {
                fail(client, reply_code(&e)).await?;
                return Ok(());
            }
        }
    };
    let flow = Flow { peer, kind: "SOCKS5", target: t.display(), route };
    proxy::relay(st, client, &mut remote, &first, &flow).await;
    Ok(())
}
