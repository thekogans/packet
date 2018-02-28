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

#include "thekogans/util/RandomSource.h"
#include "thekogans/crypto/FrameHeader.h"
#include "thekogans/packet/PlaintextHeader.h"
#include "thekogans/packet/PacketFragmentHeader.h"
#include "thekogans/packet/Packet.h"

namespace thekogans {
    namespace packet {

        Packet::Map &Packet::GetMap () {
            static Map map;
            return map;
        }

        bool Packet::CheckId (util::ui16 id) {
            Map::iterator it = GetMap ().find (id);
            return it != GetMap ().end ();
        }

        Packet::UniquePtr Packet::Get (util::Buffer &packetHeaderAndData) {
            PacketHeader packetHeader;
            packetHeaderAndData >> packetHeader;
            return Get (packetHeader, packetHeaderAndData);
        }

        Packet::UniquePtr Packet::Get (
                const PacketHeader &packetHeader,
                util::Buffer &packetData) {
            UniquePtr packet;
            Map::iterator it = GetMap ().find (packetHeader.id);
            if (it != GetMap ().end ()) {
                if (packetHeader.IsCompressed ()) {
                    util::Buffer::UniquePtr uncompressed = packetData.Inflate ();
                    packet = it->second (packetHeader, *uncompressed);
                }
                else {
                    packet = it->second (packetHeader, packetData);
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to locate handler for packet: "
                    "id = %u, version = %u, fragment count = %u, length = %u.",
                    packetHeader.id,
                    packetHeader.version,
                    packetHeader.fragmentCount,
                    packetHeader.length);
            }
            return packet;
        }

        Packet::MapInitializer::MapInitializer (
                util::ui16 id,
                Factory factory) {
            std::pair<Map::iterator, bool> result =
                GetMap ().insert (Map::value_type (id, factory));
            if (!result.second) {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Packet with id: %u already registered.", id);
            }
        }

        namespace {
            inline util::ui8 GetRandom (util::ui8 *random) {
                util::ui8 randomLength;
                do {
                    randomLength = (util::ui8)util::GlobalRandomSource::Instance ().GetBytes (random,
                        util::GlobalRandomSource::Instance ().Getui32 () % PlaintextHeader::MAX_RANDOM_LENGTH);
                } while (randomLength == 0);
                return randomLength;
            }
        }

        void Packet::Serialize (
                const util::GUID &sessionId,
                util::ui32 sequenceNumber,
                crypto::Cipher &cipher,
                bool compress,
                util::ui32 maxFrameDataLength,
                std::vector<util::Buffer::UniquePtr> &frames) const {
            util::Buffer packetData (util::NetworkEndian, GetSize ());
            Write (packetData);
            util::Buffer::UniquePtr compressed;
            util::ui32 dataLength;
            util::ui16 flags;
            if (compress) {
                compressed = packetData.Deflate ();
                dataLength = compressed->GetDataAvailableForReading ();
                flags = PacketHeader::FLAGS_COMPRESSED;
            }
            else {
                dataLength = packetData.GetDataAvailableForReading ();
                flags = 0;
            }
            util::ui16 fragmentCount = dataLength / maxFrameDataLength;
            util::ui16 fragmentLength = dataLength % maxFrameDataLength;
            if (fragmentLength == 0) {
                fragmentLength = maxFrameDataLength;
            }
            else {
                ++fragmentCount;
            }
            frames.resize (fragmentCount);
            util::ui8 random[PlaintextHeader::MAX_RANDOM_LENGTH];
            util::ui8 randomLength = GetRandom (random);
            util::Buffer buffer (
                util::NetworkEndian,
                PlaintextHeader::SIZE + randomLength +
                PacketHeader::SIZE + maxFrameDataLength);
            buffer << PlaintextHeader (
                randomLength,
                PlaintextHeader::TYPE_PACKET_HEADER);
            buffer.Write (random, randomLength);
            buffer << PacketHeader (
                sessionId,
                sequenceNumber,
                GetId (),
                GetVersion (),
                flags,
                fragmentCount,
                dataLength);
            if (compress) {
                compressed->AdvanceReadOffset (
                    buffer.Write (
                        compressed->GetReadPtr (),
                        fragmentLength));
            }
            else {
                packetData.AdvanceReadOffset (
                    buffer.Write (
                        packetData.GetReadPtr (),
                        fragmentLength));
            }
            frames[0] = cipher.EncryptAndFrame (
                buffer.GetReadPtr (),
                buffer.GetDataAvailableForReading ());
            util::ui16 index = 1;
            for (util::ui32 offset = fragmentLength;
                    index < fragmentCount; ++index, offset += maxFrameDataLength) {
                randomLength = GetRandom (random);
                buffer.writeOffset = 0;
                buffer << PlaintextHeader (
                    randomLength,
                    PlaintextHeader::TYPE_PACKET_FRAGMENT_HEADER);
                buffer.Write (random, randomLength);
                buffer << PacketFragmentHeader (
                    sessionId,
                    sequenceNumber,
                    0,
                    index,
                    offset);
                if (compress) {
                    compressed->AdvanceReadOffset (
                        buffer.Write (
                            compressed->GetReadPtr (),
                            maxFrameDataLength));
                }
                else {
                    packetData.AdvanceReadOffset (
                        buffer.Write (
                            packetData.GetReadPtr (),
                            maxFrameDataLength));
                }
                frames[index] = cipher.EncryptAndFrame (
                    buffer.GetReadPtr (),
                    buffer.GetDataAvailableForReading ());
            }
        }

        util::Buffer::UniquePtr Packet::Serialize (
                const util::GUID &sessionId,
                util::ui32 sequenceNumber,
                crypto::Cipher &cipher,
                bool compress) const {
            util::Buffer::UniquePtr compressed;
            util::ui32 dataLength;
            util::ui16 flags;
            if (compress) {
                util::Buffer buffer (util::NetworkEndian, GetSize ());
                Write (buffer);
                compressed = buffer.Deflate ();
                dataLength = compressed->GetDataAvailableForReading ();
                flags = PacketHeader::FLAGS_COMPRESSED;
            }
            else {
                dataLength = GetSize ();
                flags = 0;
            }
            util::ui8 random[PlaintextHeader::MAX_RANDOM_LENGTH];
            util::ui8 randomLength = GetRandom (random);
            util::Buffer buffer (
                util::NetworkEndian,
                PlaintextHeader::SIZE + randomLength +
                PacketHeader::SIZE + dataLength);
            buffer << PlaintextHeader (
                randomLength,
                PlaintextHeader::TYPE_PACKET_HEADER);
            buffer.Write (random, randomLength);
            buffer << PacketHeader (
                sessionId,
                sequenceNumber,
                GetId (),
                GetVersion (),
                flags,
                1,
                dataLength);
            if (compress) {
                buffer.Write (
                    compressed->GetReadPtr (),
                    compressed->GetDataAvailableForReading ());
            }
            else {
                Write (buffer);
            }
            return cipher.EncryptAndFrame (
                buffer.GetReadPtr (),
                buffer.GetDataAvailableForReading ());
        }

    } // namespace packet
} // namespace thekogans
