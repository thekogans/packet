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

#if !defined (__thekogans_packet_PlaintextHeader_h)
#define __thekogans_packet_PlaintextHeader_h

#include "thekogans/util/Types.h"
#include "thekogans/util/Constants.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/packet/Config.h"

namespace thekogans {
    namespace packet {

        /// \struct PlaintextHeader PlaintextHeader.h thekogans/packet/PlaintextHeader.h
        ///
        /// \brief
        /// PlaintextHeader serves two purposes. 1. It pads the \see{Packet} with random length
        /// data to make packet start identification difficult for would be attackers, and 2. It
        /// provides flags used in \see{Packet} precessing.

        struct _LIB_THEKOGANS_PACKET_DECL PlaintextHeader {
            enum {
                /// \brief
                /// Every payload begins with a random length random sequence
                /// to thwart histogram analysis and known plain-text attacks.
                MAX_RANDOM_LENGTH = 100
            };
            /// \brief
            /// Random vector length.
            util::ui8 randomLength;
            enum {
                /// \brief
                /// A \see{Session::Header} follows the random vector.
                FLAGS_SESSION_HEADER = 1,
                /// \brief
                /// \see{Packet} payload is compressed.
                FLAGS_COMPRESSED = 2
            };
            /// \brief
            /// \see{Packet} flags.
            util::ui8 flags;

            enum {
                /// \brief
                /// PlaintextHeader serialized size.
                SIZE = util::UI8_SIZE +
                    util::UI8_SIZE
            };

            /// \brief
            /// ctor.
            PlaintextHeader () :
                randomLength (0),
                flags (0) {}
            /// \brief
            /// ctor.
            /// \param[in] randomLength_ Random vector length.
            /// \param[in] flags_ Payload flags.
            PlaintextHeader (
                util::ui8 randomLength_,
                util::ui8 flags_) :
                randomLength (randomLength_),
                flags (flags_) {}
        };

        /// \brief
        /// PlaintextHeader serializer.
        /// \param[in] serializer Where to serialize the plaintext header.
        /// \param[in] plaintextHeader PlaintextHeader to serialize.
        /// \return serializer.
        inline util::Serializer &operator << (
                util::Serializer &serializer,
                const PlaintextHeader &plaintextHeader) {
            serializer <<
                plaintextHeader.randomLength <<
                plaintextHeader.flags;
            return serializer;
        }

        /// \brief
        /// PlaintextHeader deserializer.
        /// \param[in] serializer Where to deserialize the plaintext header.
        /// \param[in] plaintextHeader PlaintextHeader to deserialize.
        /// \return serializer.
        inline util::Serializer &operator >> (
                util::Serializer &serializer,
                PlaintextHeader &plaintextHeader) {
            serializer >>
                plaintextHeader.randomLength >>
                plaintextHeader.flags;
            return serializer;
        }

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_PlaintextHeader_h)
