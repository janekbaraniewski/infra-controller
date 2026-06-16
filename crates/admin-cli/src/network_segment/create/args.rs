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

use carbide_uuid::vpc::VpcId;
use clap::{Parser, ValueEnum};

use ::rpc::forge::{NetworkPrefix, NetworkSegmentCreationRequest, NetworkSegmentType};

/// SegmentType is the CLI-facing spelling of the forge NetworkSegmentType enum.
/// Defaults to HostInband, which is the only segment type a Flat (zero-DPU) VPC
/// accepts — so the day-0 seed for the zero-DPU flow can omit `--type`.
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum SegmentType {
    Tenant,
    Admin,
    Underlay,
    HostInband,
}

impl From<SegmentType> for NetworkSegmentType {
    fn from(value: SegmentType) -> Self {
        match value {
            SegmentType::Tenant => NetworkSegmentType::Tenant,
            SegmentType::Admin => NetworkSegmentType::Admin,
            SegmentType::Underlay => NetworkSegmentType::Underlay,
            SegmentType::HostInband => NetworkSegmentType::HostInband,
        }
    }
}

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(long, help = "Name of the network segment (must be unique within the site)")]
    pub name: String,

    #[clap(
        long,
        help = "CIDR prefix for the segment (e.g. a per-host data-NIC /31 like 192.168.129.10/31)"
    )]
    pub prefix: String,

    #[clap(long, help = "Optional gateway address for the prefix")]
    pub gateway: Option<String>,

    #[clap(
        long,
        value_enum,
        default_value = "host-inband",
        help = "Segment type. Defaults to host-inband (required for zero-DPU / Flat VPCs)"
    )]
    pub segment_type: SegmentType,

    #[clap(
        long,
        help = "Optional VPC to bind the segment to at creation. Leave unset to create it unbound \
                (the platform binds it per-tenant at allocation time)."
    )]
    pub vpc_id: Option<VpcId>,

    #[clap(long, default_value_t = 9000, help = "MTU for the segment")]
    pub mtu: i32,
}

impl From<Args> for NetworkSegmentCreationRequest {
    fn from(args: Args) -> Self {
        Self {
            vpc_id: args.vpc_id,
            name: args.name,
            subdomain_id: None,
            mtu: Some(args.mtu),
            prefixes: vec![NetworkPrefix {
                id: None,
                prefix: args.prefix,
                gateway: args.gateway,
                reserve_first: 0,
                free_ip_count: 1,
                svi_ip: None,
            }],
            segment_type: NetworkSegmentType::from(args.segment_type) as i32,
            // No explicit id: forge generates a random NetworkSegmentId.
            id: None,
        }
    }
}
