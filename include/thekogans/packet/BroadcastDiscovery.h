// Copyright 2016 Boris Kogan (boris@thekogans.net)
//
// This file is part of libthekogans_packet.
//
// libthekogans_packet is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libthekogans_packet is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libthekogans_packet. If not, see <http://www.gnu.org/licenses/>.

#if !defined (__thekogans_packet_BroadcastDiscovery_h)
#define __thekogans_packet_BroadcastDiscovery_h

#include <thekogans/util/Singleton.h>
#include <thekogans/stream/UDPSocket.h>
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Discovery.h"

namespace thekogans {
    namespace packet {

        /// \struct BroadcastDiscovery BroadcastDiscovery.h thekogans/packet/BroadcastDiscovery.h
        ///
        /// \brief
        /// BroadcastDiscovery is a method of peer discovery on a local sub-net
        /// using broadcast (UDP) packets. The protocol used is described in
        /// \see{InitiateDiscoveryPacket}, \see{BeaconPacket} and \see{PingPacket}.

        struct _LIB_THEKOGANS_PACKET_DECL BroadcastDiscovery :
                public util::Singleton<BroadcastDiscovery>,
                public Discovery,
                public util::Subscriber<stream::UDPSocketEvents> {
        private:
            /// \brief
            /// Listening socket.
            stream::UDPSocket::SharedPtr discoverySocket;

        public:
            // Discovery
            /// \brief
            /// Start listening for peers.
            virtual void Start () override;
            /// \brief
            /// Stop listening for peers.
            virtual void Stop () override;

            /// \brief
            /// Open the discovery windows and initiate peer discovery for a given device.
            virtual void InitiateDiscovery () override;

        private:
            /// \brief
            /// Beacon has arrived.
            /// \param[in] udpSocket UDP socket that received the beacon.
            /// \param[in] buffer The beacon.
            /// \param[in] from Peer that sent the beacon.
            /// \param[in] to Local adapter address the packet was received on.
            virtual void OnUDPSocketReadMsg (
                stream::UDPSocket::SharedPtr /*udpSocket*/,
                util::Buffer::SharedPtr buffer,
                const stream::Address &from,
                const stream::Address &to) throw () override;

            /// \brief
            /// BroadcastDiscovery is a singleton. It's neither copy constructable
            /// nor assignable.
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (BroadcastDiscovery)
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_BroadcastDiscovery_h)
