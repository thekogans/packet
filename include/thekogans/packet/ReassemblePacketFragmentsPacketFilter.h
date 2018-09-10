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

#if !defined (__thekogans_packet_ReassemblePacketFragmentsPacketFilter_h)
#define __thekogans_packet_ReassemblePacketFragmentsPacketFilter_h

#include "thekogans/util/Types.h"
#include "thekogans/util/ByteSwap.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/PacketFilter.h"

namespace thekogans {
    namespace packet {

        /// \struct ReassemblePacketFragmentsPacketFilter ReassemblePacketFragmentsPacketFilter.h
        /// thekogans/packet/ReassemblePacketFragmentsPacketFilter.h
        ///
        /// \brief
        /// ReassemblePacketFragmentsPacketFilter is a \see{PacketFragmentPacket} reassembly filter.
        /// Insert it in to your \see{Tunnel} incoming filter chain if you allow fragmented packets
        /// from peers.

        struct _LIB_THEKOGANS_PACKET_DECL ReassemblePacketFragmentsPacketFilter : public PacketFilter {
        private:
            /// \brief
            /// Maximum fragment size.
            std::size_t maxCiphertextLength;
            /// \brief
            /// Packet frame endianness.
            util::Buffer packetFragmentBuffer;

        public:
            /// \brief
            /// ctor.
            /// \param[in] maxCiphertextLength_ Maximum fragment size.
            /// \param[in] endianness Packet frame endianness.
            ReassemblePacketFragmentsPacketFilter (
                std::size_t maxCiphertextLength_,
                util::Endianness endianness = util::NetworkEndian) :
                maxCiphertextLength (maxCiphertextLength_),
                packetFragmentBuffer (endianness) {}

            /// \brief
            /// Called by \see{Tunnel}::HandlePacket to reassemble \see{PacketFragmentPacket}.
            /// \param[in] packet \see{Packet} to filter.
            /// \return If the given packet is \see{PacketFragmentPacket}, reassemble
            /// (and possibly return) the packet it contains, otherwise call CallNextPacketFilter.
            virtual Packet::Ptr FilterPacket (Packet::Ptr packet);
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_ReassemblePacketFragmentsPacketFilter_h)
