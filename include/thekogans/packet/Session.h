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

#if !defined (__thekogans_packet_Session_h)
#define __thekogans_packet_Session_h

#include "thekogans/util/Types.h"
#include "thekogans/util/GUID.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/packet/Config.h"

namespace thekogans {
    namespace packet {

        /// \struct Session Session.h thekogans/packet/Session.h
        ///
        /// \brief
        /// Session adds replay protection. If you pass a Session to
        /// \see{Packet::Serialize}, it will be encrypted with the
        /// \see{Packet} payload. Since header ids are random
        /// \see{util::GUID}s, chances of any two matching are
        /// 1 in 2^128 (340,282,366,920,938,463,463,374,607,431,768,211,456).

        struct _LIB_THEKOGANS_PACKET_DECL Session {
            /// \struct Session::Header Session.h thekogans/packet/Session.h
            ///
            /// \brief
            /// Session header is added to \see{Packet} to prevent replay
            /// attacs.
            struct Header {
                /// \brief
                /// Session id.
                util::GUID id;
                /// \brief
                /// Will hold the current session outboundSequenceNumber.
                /// Will be compared to inboundSequenceNumber upon receipt.
                util::ui64 sequenceNumber;

                /// \enum
                /// Header size.
                enum {
                    SIZE = util::GUID_SIZE +
                        util::UI64_SIZE
                };

                /// \brief
                /// ctor.
                Header () :
                    id (util::GUID::Empty),
                    sequenceNumber (0) {}
                /// \brief
                /// ctor.
                /// \param[in] id_ Session id.
                /// \param[in] sequenceNumber_ Current session outboundSequenceNumber.
                Header (
                    util::GUID id_,
                    util::ui64 sequenceNumber_) :
                    id (id_),
                    sequenceNumber (sequenceNumber_) {}

                /// \brief
                /// Return the session header size.
                /// \return Session header size.
                inline std::size_t Size () const {
                    return SIZE;
                }
            };

            /// \brief
            /// Session id.
            util::GUID id;
            /// \brief
            /// Inbound \see{Packet} sequence number.
            util::ui64 inboundSequenceNumber;
            /// \brief
            /// Outbound \see{Packet} sequence number.
            util::ui64 outboundSequenceNumber;

            /// \enum
            /// Session size.
            enum {
                SIZE = util::GUID_SIZE + // id
                    util::UI64_SIZE + // inboundSequenceNumber
                    util::UI64_SIZE // outboundSequenceNumber
            };

            /// \brief
            /// ctor.
            Session () {
                Reset ();
            }

            /// \brief
            /// Return the session size.
            /// \return Session size.
            inline std::size_t Size () const {
                return SIZE;
            }

            /// \brief
            /// Verify an incoming Header to make sure it contains the
            /// inboundSequenceNumber we expect.
            /// \param[in] header Incoming Header.
            /// \return true == Header contain the correct id and
            /// inboundSequenceNumber.
            bool VerifyInboundHeader (const Header &header);

            /// \brief
            /// Return Header containing the next outboundSequenceNumber.
            /// \return Header containing the next outboundSequenceNumber.
            inline Header GetOutboundHeader () {
                return Header (id, outboundSequenceNumber++);
            }

            /// \brief
            /// Reset the session.
            void Reset ();
        };

        /// \brief
        /// Compare two session headers for equality.
        /// \param[in] header1 First session header to compare.
        /// \param[in] header2 Second session header to compare.
        /// \return true == the given headers are equal,
        /// false == the given headers are different.
        inline bool operator == (
                const Session::Header &header1,
                const Session::Header &header2) {
            return header1.id == header2.id &&
                header1.sequenceNumber == header2.sequenceNumber;
        }

        /// \brief
        /// Compare two session headers for inequality.
        /// \param[in] header1 First session header to compare.
        /// \param[in] header2 Second session header to compare.
        /// \return true == the given headers are different,
        /// false == the given headers are equal.
        inline bool operator != (
                const Session::Header &header1,
                const Session::Header &header2) {
            return header1.id != header2.id ||
                header1.sequenceNumber != header2.sequenceNumber;
        }

        /// \brief
        /// Session::Header serializer.
        /// \param[in] serializer Where to serialize the session header.
        /// \param[in] sessionHeader SessionHeader to serialize.
        /// \return serializer.
        inline util::Serializer &operator << (
                util::Serializer &serializer,
                const Session::Header &sessionHeader) {
            serializer << sessionHeader.id << sessionHeader.sequenceNumber;
            return serializer;
        }

        /// \brief
        /// Session::Header deserializer.
        /// \param[in] serializer Where to deserialize the frame header.
        /// \param[in] sessionHeader Session::Header to deserialize.
        /// \return serializer.
        inline util::Serializer &operator >> (
                util::Serializer &serializer,
                Session::Header &sessionHeader) {
            serializer >> sessionHeader.id >> sessionHeader.sequenceNumber;
            return serializer;
        }

        /// \brief
        /// Session serializer.
        /// \param[in] serializer Where to serialize the frame header.
        /// \param[in] session Session to serialize.
        /// \return serializer.
        inline util::Serializer &operator << (
                util::Serializer &serializer,
                const Session &session) {
            serializer <<
                session.id <<
                session.inboundSequenceNumber <<
                session.outboundSequenceNumber;
            return serializer;
        }

        /// \brief
        /// Session deserializer.
        /// \param[in] serializer Where to deserialize the frame header.
        /// \param[in] session Session to deserialize.
        /// \return serializer.
        inline util::Serializer &operator >> (
                util::Serializer &serializer,
                Session &session) {
            serializer >>
                session.id >>
                session.inboundSequenceNumber >>
                session.outboundSequenceNumber;
            return serializer;
        }

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_Session_h)
