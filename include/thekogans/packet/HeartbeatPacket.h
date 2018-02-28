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

#if !defined (__thekogans_packet_HeartbeatPacket_h)
#define __thekogans_packet_HeartbeatPacket_h

#include <ctime>
#include "thekogans/util/Types.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Packet.h"
#include "thekogans/packet/Packets.h"

namespace thekogans {
    namespace packet {

        /// \struct HeartbeatPacket HeartbeatPacket.h thekogans/packet/HeartbeatPacket.h
        ///
        /// \brief
        /// Encapsulates data that makes up the heartbeat packet. HeartbeatPacket
        /// packets are used to probe the health of the connection.

        struct _LIB_THEKOGANS_PACKET_DECL HeartbeatPacket : public Packet {
            /// \brief
            /// Pull in \see{Packet} dynamic creation machinery.
            THEKOGANS_PACKET_DECLARE_PACKET (HeartbeatPacket)

            enum {
                /// \brief
                /// Packet id.
                ID = Packets::PACKET_ID_HEARTBEAT,
                /// \brief
                /// Packet version.
                VERSION = 1
            };

            /// \brief
            /// Last time a packet was received from the peer.
            util::i64 lastReceivedPacketTime;
            /// \brief
            /// Host current time.
            util::i64 currentTime;

            /// \brief
            /// ctor.
            /// \param[in] lastReceivedPacketTime_ Last time a packet was received from the peer.
            explicit HeartbeatPacket (
                util::i64 lastReceivedPacketTime_) :
                lastReceivedPacketTime (lastReceivedPacketTime_),
                currentTime (time (0)) {}

        protected:
            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual util::ui32 GetSize () const {
                return
                    util::Serializer::Size (lastReceivedPacketTime) +
                    util::Serializer::Size (currentTime);
            }

            /// \brief
            /// De-serialize the packet.
            /// \param[in] packetHeader Packet header.
            /// \param[in] buffer Packet contents.
            virtual void Read (
                const PacketHeader & /*packetHeader*/,
                util::Buffer &buffer);
            /// \brief
            /// Serialize the packet.
            /// \param[in] buffer Packet contents.
            virtual void Write (util::Buffer &buffer) const;

            /// \brief
            /// HeartbeatPacket is neither copy constructable nor assignable.
            THEKOGANS_PACKET_DISALLOW_COPY_AND_ASSIGN (HeartbeatPacket)
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_HeartbeatPacket_h)
