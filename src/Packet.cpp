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
#include "thekogans/packet/PlaintextHeader.h"
#if defined (THEKOGANS_PACKET_TYPE_Static)
    #include "thekogans/packet/ClientKeyExchangePacket.h"
    #include "thekogans/packet/ServerKeyExchangePacket.h"
    #include "thekogans/packet/PacketFragmentPacket.h"
#endif // defined (THEKOGANS_PACKET_TYPE_Static)
#include "thekogans/packet/Packet.h"

namespace thekogans {
    namespace packet {

    #if defined (THEKOGANS_PACKET_TYPE_Static)
        void Packet::StaticInit () {
            ClientKeyExchangePacket::StaticInit ();
            ServerKeyExchangePacket::StaticInit ();
            PacketFragmentPacket::StaticInit ();
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
                crypto::Cipher &cipher,
                Session *session,
                bool compress) const {
            util::ui8 randomLength = GetRandomLength ();
            util::Buffer plaintext (
                util::NetworkEndian,
                PlaintextHeader::SIZE +
                randomLength +
                (session != 0 ? Session::Header::SIZE : 0) +
                GetSize ());
            util::ui8 flags = 0;
            if (session != 0) {
                flags |= PlaintextHeader::FLAGS_SESSION_HEADER;
            }
            if (compress) {
                flags |= PlaintextHeader::FLAGS_COMPRESSED;
            }
            plaintext << PlaintextHeader (randomLength, flags);
            if (plaintext.AdvanceWriteOffset (
                    util::RandomSource::Instance ()->GetBytes (
                        plaintext.GetWritePtr (),
                        randomLength)) == randomLength) {
                if (session != 0) {
                    plaintext << session->GetOutboundHeader ();
                }
                if (compress) {
                    util::Buffer buffer (util::NetworkEndian, GetSize ());
                    buffer << *this;
                    util::Buffer::SharedPtr deflated = buffer.Deflate ();
                    plaintext.Write (
                        deflated->GetReadPtr (), deflated->GetDataAvailableForReading ());
                }
                else {
                    plaintext << *this;
                }
                return cipher.EncryptAndFrame (
                    plaintext.GetReadPtr (),
                    plaintext.GetDataAvailableForReading ());
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Unable to get %u random bytes.",
                    randomLength);
            }
        }

        Packet::SharedPtr Packet::Deserialize (
                util::Buffer &ciphertext,
                crypto::Cipher &cipher,
                Session *session) {
            util::Buffer::SharedPtr plaintext = cipher.Decrypt (
                ciphertext.GetReadPtr (),
                ciphertext.GetDataAvailableForReading ());
            PlaintextHeader plaintextHeader;
            *plaintext >> plaintextHeader;
            plaintext->AdvanceReadOffset (plaintextHeader.randomLength);
            if (util::Flags8 (plaintextHeader.flags).Test (
                    PlaintextHeader::FLAGS_SESSION_HEADER)) {
                Session::Header sessionHeader;
                *plaintext >> sessionHeader;
                if (session == 0) {
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
