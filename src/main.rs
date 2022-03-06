mod autoupdate;
mod forward;
mod nat;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use anyhow::Context;
use env_logger::Env;
use geph4_binder_transport::{BinderClient, BinderRequestData, BinderResponse, ExitDescriptor};
use once_cell::sync::Lazy;
use smol::{net::TcpListener, prelude::*, Async};
use std::time::Duration;
use structopt::StructOpt;
type AsyncUdpSocket = async_dup::Arc<Async<std::net::UdpSocket>>;

use crate::forward::Forwarder;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(long, default_value = "http://binder-v4.geph.io:8964")]
    /// HTTP(S) address of the binder
    binder_http: String,

    #[structopt(
        long,
        default_value = "124526f4e692b589511369687498cce57492bf4da20f8d26019c1cc0c80b6e4b"
    )]
    /// x25519 master key of the binder
    binder_master_pk: String,

    /// bridge secret. All bridges and exits know this secret, and it's used to prevent random people from spamming the bridge table.
    #[structopt(long)]
    bridge_secret: String,

    /// bridge group.
    #[structopt(long, default_value = "other")]
    bridge_group: String,

    /// whether or not to use iptables for kernel-level forwarding
    #[structopt(long)]
    iptables: bool,

    /// additional IP addresses
    #[structopt(long)]
    additional_ip: Vec<Ipv4Addr>,
}

fn main() -> anyhow::Result<()> {
    // start the autoupdate thread
    std::thread::spawn(autoupdate::autoupdate);
    smol::block_on(async move {
        let opt: Opt = Opt::from_args();
        env_logger::Builder::from_env(Env::default().default_filter_or("geph4_bridge")).init();
        if opt.iptables {
            run_command("iptables -t nat -F");
            // --random to not leak origin ports
            run_command("iptables -t nat -A POSTROUTING -j MASQUERADE -p udp --random-fully");
            run_command("iptables -t nat -A POSTROUTING -j MASQUERADE -p tcp --random-fully");
        }
        // set TTL to 200 to hide distance of clients
        // run_command("iptables -t mangle -I POSTROUTING -j TTL --ttl-set 200");
        let binder_client = Arc::new(geph4_binder_transport::HttpClient::new(
            bincode::deserialize(&hex::decode(opt.binder_master_pk)?)?,
            opt.binder_http,
            &[],
            None,
        ));
        let mut ips = vec![*MY_IP];
        ips.extend_from_slice(&opt.additional_ip);
        bridge_loop(
            binder_client,
            &opt.bridge_secret,
            &opt.bridge_group,
            opt.iptables,
            ips,
        )
        .await;
        Ok(())
    })
}

/// Main loop of the bridge.
///
/// We poll the binder for a list of exits, and maintain a list of actor-like "exit manager" tasks that each manage a control-protocol connection.
async fn bridge_loop<'a>(
    binder_client: Arc<dyn BinderClient>,
    bridge_secret: &'a str,
    bridge_group: &'a str,
    iptables: bool,
    ips: Vec<Ipv4Addr>,
) {
    let mut current_exits = HashMap::new();
    loop {
        let binder_client = binder_client.clone();
        let exits = binder_client.request(BinderRequestData::GetExits).await;
        if let Ok(BinderResponse::GetExitsResp(exits)) = exits {
            log::info!("got {} exits!", exits.len());
            // insert all exits that aren't in current exit
            for exit in exits {
                if current_exits.get(&exit.hostname).is_none() {
                    log::info!("{} is a new exit, spawning new managers!", exit.hostname);
                    let exit2 = exit.clone();
                    let task = ips
                        .iter()
                        .cloned()
                        .map(move |ip| {
                            smolscale::spawn(manage_exit(
                                exit2.clone(),
                                bridge_secret.to_string(),
                                bridge_group.to_string(),
                                iptables,
                                ip,
                            ))
                        })
                        .collect::<Vec<_>>();
                    current_exits.insert(exit.hostname, task);
                }
            }
        }

        smol::Timer::after(Duration::from_secs(30)).await;
    }
}

async fn manage_exit(
    exit: ExitDescriptor,
    bridge_secret: String,
    bridge_group: String,
    iptables: bool,
    ip: Ipv4Addr,
) {
    loop {
        if let Err(err) = manage_exit_inner(
            exit.clone(),
            bridge_secret.clone(),
            bridge_group.clone(),
            iptables,
            ip,
        )
        .await
        {
            log::error!("manage_exit_inner: {:?}", err)
        }
    }
}

async fn manage_exit_inner(
    exit: ExitDescriptor,
    bridge_secret: String,
    bridge_group: String,
    iptables: bool,
    ip: Ipv4Addr,
) -> anyhow::Result<()> {
    let (local_udp, local_tcp) = std::iter::from_fn(|| Some(fastrand::u32(1000..65536)))
        .find_map(|port| {
            log::warn!("trying port {}", port);
            Some((
                async_dup::Arc::new(
                    Async::<std::net::UdpSocket>::bind(
                        format!("0.0.0.0:{}", port).parse::<SocketAddr>().unwrap(),
                    )
                    .ok()?,
                ),
                smol::future::block_on(TcpListener::bind(format!("0.0.0.0:{}", port))).ok()?,
            ))
        })
        .unwrap();
    log::info!(
        "forward to {} from local address {}",
        exit.hostname,
        local_udp.get_ref().local_addr().unwrap()
    );
    let (send_routes, recv_routes) = flume::bounded(0);
    let manage_fut = async {
        loop {
            let mut saddr = local_udp.get_ref().local_addr().unwrap();
            saddr.set_ip(ip.into());
            if let Err(err) =
                manage_exit_once(&exit, &bridge_secret, &bridge_group, saddr, &send_routes).await
            {
                log::warn!(
                    "restarting manage_exit_once for {}: {:?}",
                    exit.hostname,
                    err
                );
            }
        }
    };
    let route_fut = async {
        // command for route delete
        let mut forwarder: Option<Forwarder> = None;
        let mut last_remote_port = 0;
        loop {
            let (remote_port, _) = recv_routes.recv_async().await?;
            let remote_addr = resolve(format!("{}:{}", exit.hostname, remote_port)).await?[0];
            if remote_port != last_remote_port {
                last_remote_port = remote_port;
                forwarder.replace(Forwarder::new(
                    local_udp.clone(),
                    local_tcp.clone(),
                    remote_addr,
                    iptables,
                ));
            }
        }
    };
    smol::future::race(manage_fut, route_fut).await
}

fn run_command(s: &str) {
    // log::info!("running command {}", s);
    std::process::Command::new("sh")
        .arg("-c")
        .arg(s)
        .output()
        .unwrap();
}

static MY_IP: Lazy<Ipv4Addr> = Lazy::new(|| {
    ureq::get("http://checkip.amazonaws.com/")
        .call()
        .into_string()
        .unwrap()
        .trim()
        .to_string()
        .parse()
        .unwrap()
});

#[cached::proc_macro::cached(result = true)]
async fn resolve(string: String) -> anyhow::Result<Vec<SocketAddr>> {
    Ok(smol::net::resolve(string).await?)
}

async fn manage_exit_once(
    exit: &ExitDescriptor,
    bridge_secret: &str,
    bridge_group: &str,
    my_addr: SocketAddr,
    route_update: &flume::Sender<(u16, x25519_dalek::PublicKey)>,
) -> anyhow::Result<()> {
    let mut conn =
        smol::net::TcpStream::connect(resolve(format!("{}:28080", exit.hostname)).await?[0])
            .await
            .context("cannot connect to control port")?;
    // first read the challenge string
    let mut challenge_string = [0u8; 32];
    conn.read_exact(&mut challenge_string).await?;
    // compute the challenge response
    let challenge_response = blake3::keyed_hash(&challenge_string, bridge_secret.as_bytes());
    conn.write_all(challenge_response.as_bytes()).await?;
    // enter the main loop
    loop {
        // send address and group
        geph4_aioutils::write_pascalish(&mut conn, &(my_addr, bridge_group)).await?;
        // receive route
        let (port, sosistab_pk): (u16, x25519_dalek::PublicKey) =
            geph4_aioutils::read_pascalish(&mut conn).await?;
        // log::info!(
        //     "route at {} is {}/{}",
        //     exit.hostname,
        //     port,
        //     hex::encode(sosistab_pk.as_bytes())
        // );
        // update route
        route_update.send_async((port, sosistab_pk)).await?;
        smol::Timer::after(Duration::from_secs(30)).await;
    }
}
