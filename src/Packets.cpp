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

#if defined (TOOLCHAIN_TYPE_Static)
    #include "thekogans/packet/ClientKeyExchangePacket.h"
    #include "thekogans/packet/ServerKeyExchangePacket.h"
    #include "thekogans/packet/PacketFragmentPacket.h"
    #include "thekogans/packet/Packets.h"
#endif // defined (TOOLCHAIN_TYPE_Static)

namespace thekogans {
    namespace packet {

    #if defined (TOOLCHAIN_TYPE_Static)
        void Packets::StaticInit () {
            ClientKeyExchangePacket::StaticInit ();
            ServerKeyExchangePacket::StaticInit ();
            PacketFragmentPacket::StaticInit ();
        }
    #endif // defined (TOOLCHAIN_TYPE_Static)

    } // namespace packet
} // namespace thekogans
