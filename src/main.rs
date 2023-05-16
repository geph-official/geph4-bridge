mod autoupdate;
mod forward;
mod nat;

use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use env_logger::Env;

use geph4_protocol::{
    binder::{
        client::E2eeHttpTransport,
        protocol::{BinderClient, ExitDescriptor},
    },
    bridge_exit::BridgeExitTransport,
};

use once_cell::sync::Lazy;
use rand::prelude::*;
use smol::{
    future::FutureExt,
    net::{TcpListener, UdpSocket},
};
use std::time::Duration;
use stdcode::StdcodeSerializeExt;
use structopt::StructOpt;

use crate::forward::Forwarder;
use geph4_protocol::bridge_exit::{BridgeExitClient, LegacyProtocol};

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(long, default_value = "https://binder-v4.geph.io/next-gen")]
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
    // /// additional IP addresses
    // #[structopt(long)]
    // additional_ip: Vec<Ipv4Addr>,
}

fn main() {
    let opt: Opt = Opt::from_args();
    // start the autoupdate thread
    std::thread::spawn(autoupdate::autoupdate);

    smol::block_on(async move {
        env_logger::Builder::from_env(Env::default().default_filter_or("geph4_bridge")).init();
        if opt.iptables {
            run_command("iptables -t nat -F");
            run_command("iptables -t mangle -F");
            // --random to not leak origin ports
            run_command("iptables -t nat -A POSTROUTING -j MASQUERADE -p udp");
            run_command("iptables -t nat -A POSTROUTING -j MASQUERADE -p tcp");
        }
        // // set TTL to hide distance between this and the exit in order to be better obfuscate
        run_command("iptables -t mangle -p udp -I POSTROUTING -j TTL --ttl-set 200");
        let binder_client = Arc::new(BinderClient::from(E2eeHttpTransport::new(
            bincode::deserialize(
                &hex::decode(&opt.binder_master_pk).expect("invalid hex in binder pk"),
            )
            .expect("invalid format of master binder pk"),
            opt.binder_http.clone(),
            vec![],
        )));
        bridge_loop(
            binder_client,
            &opt.bridge_secret,
            &opt.bridge_group,
            opt.iptables,
        )
        .await;
        anyhow::Ok(())
    })
    .unwrap()
}

/// Main loop of the bridge.
///
/// We poll the binder for a list of exits, and maintain a list of actor-like "exit manager" tasks that each manage a control-protocol connection.
async fn bridge_loop<'a>(
    binder_client: Arc<BinderClient>,
    bridge_secret: &'a str,
    bridge_group: &'a str,
    iptables: bool,
) {
    let mut current_exits = HashMap::new();
    loop {
        let binder_client = binder_client.clone();
        let summary = binder_client.get_summary().await;
        if let Ok(summary) = summary {
            let exits = summary.exits;
            log::info!("got {} exits!", exits.len());
            // insert all exits that aren't in current exit
            let binder_exits: HashSet<_> = exits.iter().map(|e| e.hostname.clone()).collect();
            current_exits.retain(|k, _| binder_exits.contains(k));
            for exit in exits {
                if current_exits.get(&exit.hostname).is_none() {
                    log::info!("{} is a new exit, spawning new managers!", exit.hostname);
                    let exit2 = exit.clone();
                    let task = smolscale::spawn(manage_exit(
                        exit2.clone(),
                        bridge_secret.to_string(),
                        bridge_group.to_string(),
                        iptables,
                    ));
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
) {
    loop {
        let v2 = manage_exit_inner_v2(
            exit.clone(),
            bridge_secret.clone(),
            bridge_group.clone(),
            iptables,
        );
        if let Err(err) = v2.await {
            log::error!("manage_exit_inner: {:?}", err)
        }
    }
}

static UNIQUE_ID: Lazy<u128> = Lazy::new(|| rand::thread_rng().gen());

async fn manage_exit_inner_v2(
    exit: ExitDescriptor,
    bridge_secret: String,
    bridge_group: String,
    iptables: bool,
) -> anyhow::Result<()> {
    let mut rng = rand::rngs::StdRng::from_seed(
        *blake3::hash(&(&exit, &bridge_secret, &bridge_group, *UNIQUE_ID).stdcode()).as_bytes(),
    );
    let exit_addr = resolve(format!("{}:28080", exit.hostname)).await?[0];
    log::debug!("bridge secret prehash {:?}", bridge_secret);
    let bridge_secret = blake3::hash(bridge_secret.as_bytes());
    log::debug!("bridge secret {:?}", bridge_secret);
    let transport = BridgeExitTransport::new(*bridge_secret.as_bytes(), exit_addr);
    let client = BridgeExitClient(transport);

    let udp_listener = loop {
        if let Ok(bound) = UdpSocket::bind(format!("0.0.0.0:{}", rng.gen_range(1000..60000))).await
        {
            break bound;
        }
    };
    let tcp_listener = loop {
        if let Ok(bound) =
            TcpListener::bind(format!("0.0.0.0:{}", rng.gen_range(1000..60000))).await
        {
            break bound;
        }
    };
    log::info!("V2 forward to {}", exit.hostname);
    // the easiest way of implementing this lol
    let mut forwarders: HashMap<(SocketAddr, SocketAddr), Arc<Forwarder>> = HashMap::new();
    loop {
        let fallible = async {
            let udp_remote = client
                .advertise_raw_v2(
                    "sosistab2-obfsudp".into(),
                    SocketAddr::new((*MY_IP).into(), udp_listener.local_addr()?.port()),
                    bridge_group.as_str().into(),
                )
                .await?;
            let tcp_remote = client
                .advertise_raw_v2(
                    "sosistab2-obfstls".into(),
                    SocketAddr::new((*MY_IP).into(), tcp_listener.local_addr()?.port()),
                    bridge_group.as_str().into(),
                )
                .await?;
            anyhow::Ok((udp_remote, tcp_remote))
        };
        match fallible.await {
            Ok((udp_remote, tcp_remote)) => {
                let key = (udp_remote, tcp_remote);
                if !forwarders.contains_key(&key) {
                    let forwarder = Forwarder::new(
                        bridge_group.clone(),
                        udp_listener.clone(),
                        tcp_listener.clone(),
                        udp_remote,
                        tcp_remote,
                        iptables,
                        false,
                    );
                    forwarders.clear();
                    forwarders.insert(key, forwarder.into());
                }
            }
            Err(err) => {
                log::warn!("error managing: {:?}", err)
            }
        }
        smol::Timer::after(Duration::from_secs_f64(fastrand::f64() * 30.0)).await;
    }
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
        .timeout(Duration::from_secs(1))
        .call()
        .unwrap()
        .into_string()
        .unwrap()
        .trim()
        .to_string()
        .parse()
        .unwrap()
});

#[cached::proc_macro::cached(result = true, time = 60)]
async fn resolve(string: String) -> anyhow::Result<Vec<SocketAddr>> {
    Ok(smol::net::resolve(string).await?)
}
