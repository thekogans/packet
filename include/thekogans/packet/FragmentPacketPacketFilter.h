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

#if !defined (__thekogans_packet_FragmentPacketPacketFilter_h)
#define __thekogans_packet_FragmentPacketPacketFilter_h

#include "thekogans/packet/Config.h"
#include "thekogans/packet/PacketFilter.h"

namespace thekogans {
    namespace packet {

        struct Tunnel;

        /// \struct FragmentPacketPacketFilter FragmentPacketPacketFilter.h
        /// thekogans/packet/FragmentPacketPacketFilter.h
        ///
        /// \brief
        /// FragmentPacketPacketFilter is used to fragment a single big packet in to multiple
        /// \see{PacketFragmentPacket} packets. Insert it in to your \see{Tunnel} outgoing
        /// filter chain if you constrain wire frame sizes.

        struct _LIB_THEKOGANS_PACKET_DECL FragmentPacketPacketFilter : public PacketFilter {
        private:
            /// \brief
            /// \see{Tunnel} to which this filter belongs.
            Tunnel &tunnel;
            /// \brief
            /// Maximum fragment size.
            std::size_t maxCiphertextLength;

        public:
            /// \brief
            /// ctor.
            /// \param[in] tunnel_ \see{Tunnel} to which this filter belongs.
            /// \param[in] maxCiphertextLength_ Maximum fragment size.
            FragmentPacketPacketFilter (
                Tunnel &tunnel_,
                std::size_t maxCiphertextLength_) :
                tunnel (tunnel_),
                maxCiphertextLength (maxCiphertextLength_) {}

            /// \brief
            /// Called by \see{Tunnel}::SendPacket to fragment a large packet in to multiple
            /// \see{PacketFragmentPacket} packets.
            /// \param[in] packet \see{Packet} to filter.
            /// \return If the given packet is too big, fragment it in to multiple
            /// \see{PacketFragmentPacket} packets, otherwise call CallNextPacketFilter.
            virtual Packet::SharedPtr FilterPacket (Packet::SharedPtr packet) override;
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_FragmentPacketPacketFilter_h)
