use dns_lookup::lookup_host;
use rand::{thread_rng, Rng};
use std::net::IpAddr;

/// Iterates through DNS seeds semi-randomly
#[derive(Clone)]
pub struct SeedIter {
    /// Port that is common to all IPs
    pub port: u16,
    seeds: Vec<String>,
    nodes: Vec<IpAddr>,
    seed_index: usize,
    node_index: usize,
    random_offset: usize,
}

impl SeedIter {
    /// Creates a new seed iterator from a list of DNS seeds
    pub fn new(seeds: &Vec<String>, port: u16) -> SeedIter {
        SeedIter {
            seeds: seeds.clone(),
            port,
            nodes: Vec::new(),
            seed_index: 0,
            node_index: 0,
            random_offset: thread_rng().gen_range::<usize>(0, 100),
        }
    }
}

impl Iterator for SeedIter {
    type Item = (IpAddr, u16);
    fn next(&mut self) -> Option<(IpAddr, u16)> {
        loop {
            if self.seed_index == self.seeds.len() {
                return None;
            }

            if self.nodes.len() == 0 {
                let i = (self.seed_index + self.random_offset) % self.seeds.len();
                info!("Looking up DNS {:?}", self.seeds[i]);
                match lookup_host(&self.seeds[i]) {
                    Ok(ip_list) => self.nodes = ip_list,
                    Err(e) => {
                        error!("Failed to look up DNS {:?}: {}", self.seeds[i], e);
                        self.seed_index += 1;
                        continue;
                    }
                }
            }

            if self.node_index == self.nodes.len() {
                self.node_index = 0;
                self.seed_index += 1;
                self.nodes.clear();
            } else {
                let i = (self.node_index + self.random_offset) % self.nodes.len();
                self.node_index += 1;
                return Some((self.nodes[i], self.port));
            }
        }
    }
}
