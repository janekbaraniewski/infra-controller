/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#![allow(dead_code, unused_imports)]
mod command_line;
mod tar_router;

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;

use axum::Router;
use bmc_mock::{
    BmcCommand, Callbacks, DpuMachineInfo, HostHardwareType, HostMachineInfo, ListenerOrAddress,
    MachineInfo, MockPowerState, SetSystemPowerError, SystemPowerControl,
};
use tar_router::TarGzOption;
use tokio::sync::{RwLock, mpsc};
use tracing::info;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::fmt::Layer;
use tracing_subscriber::prelude::*;

///
/// bmc-mock behaves like a Redfish BMC server
/// Run: 'cargo run'
/// Try it:
///  - start docker-compose things
///  - `cargo make bootstrap-forge-docker`
///  - `grpcurl -d '{"machine_id": {"value": "71363261-a95a-4964-9eb1-8dd98b870746"}}' -insecure
///  127.0.0.1:1079 forge.Forge/CleanupMachineCompleted`
///  where that UUID is a host machine in DB.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut routers_by_ip: HashMap<String, Router> = HashMap::default();

    let env_filter = EnvFilter::from_default_env()
        .add_directive(LevelFilter::DEBUG.into())
        .add_directive("tower=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("h2=warn".parse().unwrap());

    tracing_subscriber::registry()
        .with(Layer::default().compact())
        .with(env_filter)
        .init();

    // collection of path to entries map to avoid duplicating entries when multiple machines
    // use the same archive
    let mut tar_router_entries = HashMap::default();

    let args = command_line::parse_args();
    if let Some(ip_routers) = args.ip_router {
        for ip_router in ip_routers {
            info!(
                "Using archive {} for {}",
                ip_router.targz.to_string_lossy(),
                ip_router.ip_address
            );
            let r = tar_router::tar_router(
                TarGzOption::Disk(&ip_router.targz),
                Some(&mut tar_router_entries),
            )
            .unwrap();
            routers_by_ip.insert(ip_router.ip_address, r);
        }
    }

    let listen_addr = args.port.map(|p| SocketAddr::from(([0, 0, 0, 0], p)));
    info!("Using cert_path: {:?}", args.cert_path);
    let router = if let Some(tar_path) = args.targz {
        info!("Using archive {} as default", tar_path.to_string_lossy());
        tar_router::tar_router(TarGzOption::Disk(&tar_path), Some(&mut tar_router_entries)).unwrap()
    } else {
        info!("Using default BMC mock");
        default_host_mock()
    };

    // FLEET: no default fallback — only explicit per-VM BMC IPs respond, so site-explorer
    // discovers exactly the fleet BMCs (not the same phantom host at every scanned IP).
    let _ = router; // keep default router built but unused
    // routers_by_ip.insert("".to_owned(), router);

    // FLEET: per-VM BMC routers keyed by static BMC IP; each drives its libvirt domain.
    // Read from --fleet-config JSON if provided (scales without recompiling);
    // otherwise fall back to the built-in 3-machine fleet.
    #[derive(serde::Deserialize)]
    struct FleetEntry { bmc_ip: String, domain: String, mac: String, bmc_mac: String, serial: String }
    let fleet: Vec<FleetEntry> = if let Some(path) = args.fleet_config.as_ref() {
        let data = std::fs::read_to_string(path).expect("read --fleet-config file");
        let v: Vec<FleetEntry> = serde_json::from_str(&data).expect("parse --fleet-config JSON");
        info!("loaded {} fleet entries from {:?}", v.len(), path);
        v
    } else {
        vec![
            FleetEntry { bmc_ip: "192.168.192.21".into(), domain: "ManagedHost".into(), mac: "52:54:00:ab:cd:01".into(), bmc_mac: "52:54:00:ff:ff:01".into(), serial: "NICOVM0001".into() },
            FleetEntry { bmc_ip: "192.168.192.22".into(), domain: "fleet-vm-2".into(),  mac: "52:54:00:ab:cd:02".into(), bmc_mac: "52:54:00:ff:ff:02".into(), serial: "NICOVM0002".into() },
            FleetEntry { bmc_ip: "192.168.192.23".into(), domain: "fleet-vm-3".into(),  mac: "52:54:00:ab:cd:03".into(), bmc_mac: "52:54:00:ff:ff:03".into(), serial: "NICOVM0003".into() },
        ]
    };
    for e in &fleet {
        let cb: Arc<dyn Callbacks> = Arc::new(VirshCallbacks::new(&e.domain));
        let mut h = HostMachineInfo::new(HostHardwareType::DellPowerEdgeR750, vec![]);
        h.non_dpu_mac_address = Some(e.mac.parse().unwrap());
        h.bmc_mac_address = e.bmc_mac.parse().unwrap();
        h.serial = e.serial.clone();
        let r = bmc_mock::machine_router(MachineInfo::Host(h), cb, String::default(), false).0;
        routers_by_ip.insert(e.bmc_ip.clone(), r);
        info!("fleet BMC router: {} -> domain {}", e.bmc_ip, e.domain);
    }


    let server_config = bmc_mock::tls::server_config(args.cert_path)?;
    let mut handle = bmc_mock::CombinedServer::run(
        "bmc-mock",
        Arc::new(RwLock::new(routers_by_ip)),
        listen_addr.map(ListenerOrAddress::Address),
        server_config,
    );
    handle.wait().await?;
    Ok(())
}

fn spawn_qemu_reboot_handler() -> mpsc::UnboundedSender<BmcCommand> {
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Some(command) = command_rx.recv().await else {
                break;
            };
            match command {
                // Assume SetSystemPower is just a reboot
                BmcCommand::SetSystemPower { .. } => {}
                BmcCommand::StateRefreshIndication => continue,
            }
            let reboot_output = match Command::new("virsh")
                .arg("reboot")
                .arg("ManagedHost")
                .output()
            {
                Ok(o) => o,
                Err(err) if matches!(err.kind(), ErrorKind::NotFound) => {
                    tracing::info!("`virsh` not found. Cannot reboot QEMU host.");
                    continue;
                }
                Err(err) => {
                    tracing::error!("Error trying to run 'virsh reboot ManagedHost'. {}", err);
                    continue;
                }
            };

            match reboot_output.status.code() {
                Some(0) => {
                    tracing::debug!("Rebooted qemu managed host...");
                }
                Some(exit_code) => {
                    tracing::error!(
                        "Reboot command 'virsh reboot ManagedHost' failed with exit code {exit_code}."
                    );
                    tracing::info!("STDOUT: {}", String::from_utf8_lossy(&reboot_output.stdout));
                    tracing::info!("STDERR: {}", String::from_utf8_lossy(&reboot_output.stderr));
                }
                None => {
                    tracing::error!("Reboot command killed by signal");
                }
            }
        }
    });
    command_tx
}

#[derive(Debug)]
struct VirshCallbacks { domain: String }
impl VirshCallbacks {
    fn new(domain: &str) -> Self { Self { domain: domain.to_string() } }
    fn run_virsh(&self, c: SystemPowerControl, args: &[&str]) {
        tracing::info!("VirshCallbacks: {:?} -> virsh {:?}", c, args);
        let _ = Command::new("virsh").args(args).output();
    }
}
impl Callbacks for VirshCallbacks {
    fn get_power_state(&self) -> MockPowerState {
        match Command::new("virsh").arg("domstate").arg(&self.domain).output() {
            Ok(o) => {
                let st = String::from_utf8_lossy(&o.stdout);
                if st.contains("shut off") || st.contains("crashed") { MockPowerState::Off }
                else { MockPowerState::On }
            }
            Err(_) => MockPowerState::On,
        }
    }
    fn send_power_command(&self, c: SystemPowerControl) -> Result<(), SetSystemPowerError> {
        use SystemPowerControl as C;
        let running = matches!(self.get_power_state(), MockPowerState::On);
        let d = self.domain.as_str();
        // For boot-causing restarts we must COLD boot (destroy + start) rather than
        // `virsh reset`. `virsh reset` keeps the already-running domain definition and
        // does NOT re-read the persistent XML, so a boot-order change applied via
        // set_boot_device() would be ignored. destroy+start forces libvirt to re-read
        // the persistent <os> boot order, so the boot device the BMC selected actually
        // takes effect. This mirrors how a real reset applies the staged boot override.
        match c {
            C::On | C::ForceOn => self.run_virsh(c, &["start", d]),
            C::GracefulShutdown => self.run_virsh(c, &["shutdown", d]),
            C::ForceOff => self.run_virsh(c, &["destroy", d]),
            C::ForceRestart | C::PowerCycle | C::GracefulRestart => {
                if running {
                    self.run_virsh(c, &["destroy", d]);
                }
                self.run_virsh(c, &["start", d]);
            }
            _ => {
                if running {
                    self.run_virsh(c, &["destroy", d]);
                    self.run_virsh(c, &["start", d]);
                } else {
                    self.run_virsh(c, &["start", d]);
                }
            }
        }
        Ok(())
    }
    fn set_boot_device(&self, dev: bmc_mock::BootOptionKind) {
        use bmc_mock::BootOptionKind as K;
        // Rewrite the domain's persistent <os> boot order so the NEXT cold boot uses
        // the device the BMC selected. virt-xml --edit --boot rewrites <boot dev=.../>
        // in the persistent config; the subsequent destroy+start (see send_power_command)
        // makes libvirt honor it. The non-selected device is kept as a fallback so a
        // failed PXE attempt still eventually boots from disk, matching firmware order.
        let order = match dev {
            K::Network => "network,hd",
            K::Disk => "hd,network",
        };
        let d = self.domain.as_str();
        tracing::info!(
            "VirshCallbacks: set_boot_device {:?} -> virt-xml {} --edit --boot {}",
            dev, d, order
        );
        let out = Command::new("virt-xml")
            .args([d, "--edit", "--boot", order])
            .output();
        match out {
            Ok(o) if o.status.success() => {}
            Ok(o) => tracing::error!(
                "virt-xml boot-order edit failed for {}: stdout={} stderr={}",
                d,
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => tracing::error!("failed to exec virt-xml for {}: {}", d, e),
        }
    }
    fn state_refresh_indication(&self) {}
}

fn default_host_mock() -> Router {
    let callbacks: Arc<dyn Callbacks> = Arc::new(VirshCallbacks::new("ManagedHost"));
    let mut host = HostMachineInfo::new(HostHardwareType::DellPowerEdgeR750, vec![]);
    host.non_dpu_mac_address = Some("52:54:00:ab:cd:01".parse().unwrap());
    host.bmc_mac_address = "52:54:00:ff:ff:01".parse().unwrap();
    host.serial = "NICOVM0001".to_string();
    bmc_mock::machine_router(MachineInfo::Host(host), callbacks, String::default(), false).0
}

#[derive(Debug)]
struct ChannelCallbacks {
    command_channel: mpsc::UnboundedSender<BmcCommand>,
}

impl ChannelCallbacks {
    fn new(command_channel: mpsc::UnboundedSender<BmcCommand>) -> Self {
        Self { command_channel }
    }
}

impl Callbacks for ChannelCallbacks {
    fn get_power_state(&self) -> MockPowerState {
        MockPowerState::On
    }

    fn send_power_command(
        &self,
        reset_type: SystemPowerControl,
    ) -> Result<(), SetSystemPowerError> {
        self.command_channel
            .send(BmcCommand::SetSystemPower {
                request: reset_type,
                reply: None,
            })
            .map_err(|err| SetSystemPowerError::CommandSendError(err.to_string()))
    }

    fn state_refresh_indication(&self) {
        let _ = self
            .command_channel
            .send(BmcCommand::StateRefreshIndication);
    }
}
