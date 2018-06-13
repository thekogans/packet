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

#if !defined (__thekogans_packet_PacketFragmentPacket_h)
#define __thekogans_packet_PacketFragmentPacket_h

#include "thekogans/util/Types.h"
#include "thekogans/util/SpinLock.h"
#include "thekogans/util/Buffer.h"
#include "thekogans/util/Serializer.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Packet.h"

namespace thekogans {
    namespace packet {

        /// \struct PacketFragmentPacket PacketFragmentPacket.h thekogans/packet/PacketFragmentPacket.h
        ///
        /// \brief
        /// PacketFragmentPacket packets are used to transport \see{Packet}s that are too big to
        /// fit in to a single frame.

        struct _LIB_THEKOGANS_PACKET_DECL PacketFragmentPacket : public Packet {
            /// \brief
            /// Pull in Packet dynamic creation machinery.
            THEKOGANS_UTIL_DECLARE_SERIALIZABLE (PacketFragmentPacket, util::SpinLock)

            /// \brief
            /// \see{Packet} chunk number.
            util::ui32 chunkNumber;
            /// \brief
            /// Total \see{Packet} chunk count.
            util::ui32 chunkCount;
            /// \brief
            /// \see{Packet} chunk.
            util::Buffer::UniquePtr buffer;

            /// \brief
            /// ctor.
            /// \param[in] chunkNumber_ \see{Packet} chunk number.
            /// \param[in] chunkCount_ Total \see{Packet} chunk count.
            /// \param[in] buffer_ \see{Packet} chunk.
            PacketFragmentPacket (
                util::ui32 chunkNumber_,
                util::ui32 chunkCount_,
                util::Buffer::UniquePtr buffer_) :
                chunkNumber (chunkNumber_),
                chunkCount (chunkCount_),
                buffer (std::move (buffer_)) {}

        protected:
            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual std::size_t Size () const {
                return
                    util::Serializer::Size (chunkNumber) +
                    util::Serializer::Size (chunkCount) +
                    util::Serializer::Size (*buffer);
            }

            /// \brief
            /// De-serialize the packet.
            /// \param[in] header Packet header.
            /// \param[in] serializer Packet contents.
            virtual void Read (
                const Header & /*header*/,
                util::Serializer &serializer);
            /// \brief
            /// Serialize the packet.
            /// \param[out] serializer Packet contents.
            virtual void Write (util::Serializer &serializer) const;

            /// \brief
            /// PacketFragmentPacket is neither copy constructable nor assignable.
            THEKOGANS_PACKET_DISALLOW_COPY_AND_ASSIGN (PacketFragmentPacket)
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_PacketFragmentPacket_h)
