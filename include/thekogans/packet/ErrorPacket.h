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

#if !defined (__thekogans_packet_ErrorPacket_h)
#define __thekogans_packet_ErrorPacket_h

#include "thekogans/util/Exception.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Packet.h"
#include "thekogans/packet/Packets.h"

namespace thekogans {
    namespace packet {

        /// \struct ErrorPacket ErrorPacket.h thekogans/packet/ErrorPacket.h
        ///
        /// \brief
        /// Encapsulates data that makes up the error packet. ErrorPacket packets
        /// contain exceptions describing the error.

        struct _LIB_THEKOGANS_PACKET_DECL ErrorPacket : public Packet {
            /// \brief
            /// Pull in \see{Packet} dynamic creation machinery.
            THEKOGANS_PACKET_DECLARE_PACKET (ErrorPacket)

            enum {
                /// \brief
                /// Packet id.
                ID = Packets::PACKET_ID_ERROR,
                /// \brief
                /// Packet version.
                VERSION = 1
            };

            /// \brief
            /// The error.
            util::Exception exception;

            /// \brief
            /// ctor.
            /// \param[in] exception_ The error.
            explicit ErrorPacket (const util::Exception &exception_) :
                exception (exception_) {}

        protected:
            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual util::ui32 GetSize () const {
                return util::Serializer::Size (exception.ToString (0));
            }

            /// \brief
            /// De-serialize the packet.
            /// \param[in] packetHeader Packet header.
            /// \param[in] buffer Packet contents.
            virtual void Read (
                const PacketHeader & /*packetHeader*/,
                util::Buffer &buffer);
            /// \brief
            /// Serialize the packet.
            /// \param[in] buffer Packet contents.
            virtual void Write (util::Buffer &buffer) const;

            /// \brief
            /// ErrorPacket is neither copy constructable nor assignable.
            THEKOGANS_PACKET_DISALLOW_COPY_AND_ASSIGN (ErrorPacket)
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_ErrorPacket_h)
