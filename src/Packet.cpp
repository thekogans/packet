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
#include "thekogans/util/Exception.h"
#include "thekogans/util/Flags.h"
#include "thekogans/crypto/FrameHeader.h"
#include "thekogans/packet/PlaintextHeader.h"
#if defined (THEKOGANS_PACKET_TYPE_Static)
    #include "thekogans/packet/InitiateDiscoveryPacket.h"
    #include "thekogans/packet/BeaconPacket.h"
    #include "thekogans/packet/PingPacket.h"
    #include "thekogans/packet/ClientHelloPacket.h"
    #include "thekogans/packet/ServerHelloPacket.h"
    #include "thekogans/packet/PromoteConnectionPacket.h"
    #include "thekogans/packet/ClientKeyExchangePacket.h"
    #include "thekogans/packet/ServerKeyExchangePacket.h"
    #include "thekogans/packet/PacketFragmentPacket.h"
    #include "thekogans/packet/HeartbeatPacket.h"
    #include "thekogans/packet/DataPacket.h"
#endif // defined (THEKOGANS_PACKET_TYPE_Static)
#include "thekogans/packet/Packet.h"

namespace thekogans {
    namespace packet {

    #if defined (THEKOGANS_PACKET_TYPE_Static)
        void Packet::StaticInit () {
            InitiateDiscoveryPacket::StaticInit ();
            BeaconPacket::StaticInit ();
            PingPacket::StaticInit ();
            ClientHelloPacket::StaticInit ();
            ServerHelloPacket::StaticInit ();
            PromoteConnectionPacket::StaticInit ();
            ClientKeyExchangePacket::StaticInit ();
            ServerKeyExchangePacket::StaticInit ();
            PacketFragmentPacket::StaticInit ();
            HeartbeatPacket::StaticInit ();
            DataPacket::StaticInit ();
        }
    #endif // defined (THEKOGANS_PACKET_TYPE_Static)

        namespace {
            inline util::ui8 GetRandomLength () {
                util::ui8 randomLength;
                do {
                    randomLength = (util::ui8)(
                        util::RandomSource::Instance ()->Getui32 () %
                        (PlaintextHeader::MAX_RANDOM_LENGTH + 1));
                } while (randomLength == 0);
                return randomLength;
            }
        }

        util::Buffer::SharedPtr Packet::Serialize (
                crypto::Cipher::SharedPtr cipher,
                Session *session,
                bool compress) const {
            util::ui8 randomLength = cipher != nullptr ? GetRandomLength () : 0;
            util::NetworkBuffer::SharedPtr plaintext (
                new util::Buffer (
                    cipher == nullptr ? crypto::FrameHeader::SIZE : 0 +
                    PlaintextHeader::SIZE +
                    randomLength +
                    (session != nullptr ? Session::Header::SIZE : 0) +
                    GetSize ()));
            if (cipher == nullptr) {
                *plaintext << crypto::FrameHeader (crypto::ID::Empty, 0);
            }
            util::ui8 flags = 0;
            if (cipher != nullptr) {
                flags |= PlaintextHeader::FLAGS_ENCRYPTED;
            }
            if (session != nullptr) {
                flags |= PlaintextHeader::FLAGS_SESSION_HEADER;
            }
            if (compress) {
                flags |= PlaintextHeader::FLAGS_COMPRESSED;
            }
            *plaintext << PlaintextHeader (randomLength, flags);
            if (randomLength > 0) {
                plaintext->AdvanceWriteOffset (
                    util::RandomSource::Instance ()->GetBytes (
                        plaintext->GetWritePtr (),
                        randomLength));
            }
            if (session != nullptr) {
                plaintext << session->GetOutboundHeader ();
            }
            if (compress) {
                util::Buffer buffer (util::NetworkEndian, GetSize ());
                buffer << *this;
                util::Buffer::SharedPtr deflated = buffer.Deflate ();
                plaintext->Write (
                    deflated->GetReadPtr (), deflated->GetDataAvailableForReading ());
            }
            else {
                plaintext << *this;
            }
            if (cipher != nullptr) {
                return cipher->EncryptAndFrame (
                    plaintext->GetReadPtr (),
                    plaintext->GetDataAvailableForReading ());
            }
            else {
                util::TenantWriteBuffer buffer (
                    plaintext->endianness,
                    plaintext->data,
                    crypto::FrameHeader::SIZE);
                buffer << crypto::FrameHeader (
                    crypto::ID::Empty,
                    plaintext->GetDataAvailableForReading () - crypto::FrameHeader::SIZE);
                return plaintext;
            }
        }

        Packet::SharedPtr Packet::Deserialize (
                util::Buffer::SharedPtr frame,
                crypto::Cipher::SharedPtr cipher,
                Session *session) {
            util::Buffer::SharedPtr plaintext = cipher != nullptr ?
                cipher->Decrypt (
                    frame->GetReadPtr (),
                    frame->GetDataAvailableForReading ()) : frame;
            PlaintextHeader plaintextHeader;
            *plaintext >> plaintextHeader;
            plaintext->AdvanceReadOffset (plaintextHeader.randomLength);
            if (util::Flags8 (plaintextHeader.flags).Test (
                    PlaintextHeader::FLAGS_SESSION_HEADER)) {
                Session::Header sessionHeader;
                *plaintext >> sessionHeader;
                if (session == nullptr) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to verify session header (%s, " THEKOGANS_UTIL_UI64_FORMAT ").",
                        sessionHeader.id.ToString ().c_str (),
                        sessionHeader.sequenceNumber);

                }
                else if (!session->VerifyInboundHeader (sessionHeader)) {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Invalid session header (%s, " THEKOGANS_UTIL_UI64_FORMAT ") "
                        "for sesson (%s, " THEKOGANS_UTIL_UI64_FORMAT ", " THEKOGANS_UTIL_UI64_FORMAT "), "
                        "possible replay attack.",
                        sessionHeader.id.ToString ().c_str (),
                        sessionHeader.sequenceNumber,
                        session->id.ToString ().c_str (),
                        session->inboundSequenceNumber,
                        session->outboundSequenceNumber);
                }
            }
            if (util::Flags8 (plaintextHeader.flags).Test (
                    PlaintextHeader::FLAGS_COMPRESSED)) {
                plaintext = plaintext->Inflate ();
            }
            Packet::SharedPtr packet;
            *plaintext >> packet;
            return packet;
        }

    } // namespace packet
} // namespace thekogans
