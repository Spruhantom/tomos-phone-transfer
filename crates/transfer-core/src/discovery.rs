use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::{net::IpAddr, time::Duration};
use thiserror::Error;

pub const SERVICE_TYPE: &str = "_tomos-transfer._tcp.local.";

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("mDNS error: {0}")] Mdns(String),
}

pub struct Discovery { daemon: ServiceDaemon }

impl Discovery {
    pub fn start() -> Result<Self, DiscoveryError> {
        let daemon = ServiceDaemon::new().map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        Ok(Self { daemon })
    }

    pub fn advertise(&self, instance: &str, host: &str, address: IpAddr, port: u16, device_id: &str) -> Result<(), DiscoveryError> {
        let properties = [("device_id", device_id), ("protocol", "1")];
        let service = ServiceInfo::new(SERVICE_TYPE, instance, host, address, port, &properties[..])
            .map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        self.daemon.register(service).map_err(|e| DiscoveryError::Mdns(e.to_string()))
    }

    /// Starts browsing. The returned callback waits for the next event without
    /// exposing the discovery library's channel type to platform front ends.
    pub fn browse(&self) -> Result<impl FnMut(Duration) -> Option<ServiceEvent>, DiscoveryError> {
        let receiver = self.daemon.browse(SERVICE_TYPE).map_err(|e| DiscoveryError::Mdns(e.to_string()))?;
        Ok(move |timeout| receiver.recv_timeout(timeout).ok())
    }
}
