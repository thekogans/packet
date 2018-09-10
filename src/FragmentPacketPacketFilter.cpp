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

#include "thekogans/util/Buffer.h"
#include "thekogans/util/Exception.h"
#include "thekogans/packet/Tunnel.h"
#include "thekogans/packet/PacketFragmentPacket.h"
#include "thekogans/packet/FragmentPacketPacketFilter.h"

namespace thekogans {
    namespace packet {

        Packet::Ptr FragmentPacketPacketFilter::FilterPacket (Packet::Ptr packet) {
            if (packet.Get () != 0) {
                std::size_t packetSize = util::Serializable::Size (*packet);
                std::size_t fragmentSize =
                    maxCiphertextLength -
                    Packet::GetMaxFramingOverhead (packet->GetType (), maxCiphertextLength);
                // If the packet is too big, fragment it.
                // It will be reassembled on the other side.
                if (packetSize > fragmentSize) {
                    std::size_t fragmentCount = packetSize / fragmentSize;
                    if ((packetSize % fragmentSize) > 0) {
                        ++fragmentCount;
                    }
                    util::Buffer buffer = packet->Serialize ();
                    for (std::size_t fragmentNumber = 1; fragmentNumber <= fragmentCount; ++fragmentNumber) {
                        util::Buffer fragment (util::NetworkEndian, fragmentSize);
                        fragment.AdvanceWriteOffset (
                            buffer.Read (
                                fragment.GetWritePtr (),
                                fragment.GetDataAvailableForWriting ()));
                        // NOTE: Injecting new packets in to the SendPacket pipeline
                        // will eventually call our filter recursively. That's okay
                        // as the if above will fail and the new packet will continue
                        // down the pipeline (CallNextPacketFilter below).
                        tunnel.SendPacket (
                            Packet::Ptr (
                                new PacketFragmentPacket (
                                    fragmentNumber,
                                    fragmentCount,
                                    std::move (fragment))));
                    }
                    // Since we've consumed the given packet, discard it.
                    return Packet::Ptr ();
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
