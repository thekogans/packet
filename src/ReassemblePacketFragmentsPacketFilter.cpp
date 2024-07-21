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

#include "thekogans/packet/PacketFragmentPacket.h"
#include "thekogans/packet/ReassemblePacketFragmentsPacketFilter.h"

namespace thekogans {
    namespace packet {

        Packet::SharedPtr ReassemblePacketFragmentsPacketFilter::FilterPacket (Packet::SharedPtr packet) {
            if (packet.Get () != 0) {
                if (packet->Type () == PacketFragmentPacket::TYPE) {
                    PacketFragmentPacket *packetFragment =
                        static_cast<PacketFragmentPacket *> (packet.Get ());
                    // reassemble the fragmented packet.
                    if (packetFragment->fragmentCount > 1) {
                        if (packetFragment->fragmentNumber == 1) {
                            packetFragmentBuffer.Resize (packetFragment->fragmentCount * maxCiphertextLength);
                        }
                        packetFragmentBuffer.Write (
                            packetFragment->fragment.GetReadPtr (),
                            packetFragment->fragment.GetDataAvailableForReading ());
                        if (packetFragment->fragmentNumber == packetFragment->fragmentCount) {
                            packetFragment->fragment = std::move (packetFragmentBuffer);
                        }
                    }
                    Packet::SharedPtr packet;
                    if (packetFragment->fragmentNumber == packetFragment->fragmentCount) {
                        packetFragment->fragment >> packet;
                    }
                    return packet;
                }
                return CallNextPacketFilter (packet);
            }
            else {
                THEKOGANS_UTIL_THROW_ERROR_CODE_EXCEPTION (
                    THEKOGANS_UTIL_OS_ERROR_CODE_EINVAL);
            }
        }

    } // namespace packet
} // namespace thekogans
