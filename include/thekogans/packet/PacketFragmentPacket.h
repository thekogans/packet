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
#include "thekogans/util/SizeT.h"
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
            THEKOGANS_UTIL_DECLARE_SERIALIZABLE (PacketFragmentPacket)

            /// \brief
            /// \see{Packet} fragment number.
            util::SizeT fragmentNumber;
            /// \brief
            /// Total \see{Packet} fragment count.
            util::SizeT fragmentCount;
            /// \brief
            /// \see{Packet} fragment.
            util::Buffer fragment;

            /// \brief
            /// ctor.
            /// \param[in] fragmentNumber_ \see{Packet} fragment number.
            /// \param[in] fragmentCount_ Total \see{Packet} fragment count.
            /// \param[in] fragment_ \see{Packet} fragment.
            PacketFragmentPacket (
                std::size_t fragmentNumber_ = 0,
                std::size_t fragmentCount_ = 0,
                util::Buffer fragment_ = util::Buffer ()) :
                fragmentNumber (fragmentNumber_),
                fragmentCount (fragmentCount_),
                fragment (std::move (fragment_)) {}

        protected:
            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual std::size_t Size () const override {
                return
                    util::Serializer::Size (fragmentNumber) +
                    util::Serializer::Size (fragmentCount) +
                    util::Serializer::Size (fragment);
            }

            /// \brief
            /// De-serialize the packet.
            /// \param[in] header Packet header.
            /// \param[in] serializer Packet contents.
            virtual void Read (
                const BinHeader & /*header*/,
                util::Serializer &serializer) override;
            /// \brief
            /// Serialize the packet.
            /// \param[out] serializer Packet contents.
            virtual void Write (util::Serializer &serializer) const override;

            /// \brief
            /// "FragmentNumber"
            static const char * const ATTR_FRAGMENT_NUMBER;
            /// \brief
            /// "FragmentCount"
            static const char * const ATTR_FRAGMENT_COUNT;

            /// \brief
            /// Read a Serializable from an XML DOM.
            /// \param[in] node XML DOM representation of a Serializable.
            virtual void Read (
                const TextHeader & /*header*/,
                const pugi::xml_node &node) override;
            /// \brief
            /// Write a Serializable to the XML DOM.
            /// \param[out] node Parent node.
            virtual void Write (pugi::xml_node &node) const override;

            /// \brief
            /// Read a Serializable from an JSON DOM.
            /// \param[in] node JSON DOM representation of a Serializable.
            virtual void Read (
                const TextHeader & /*header*/,
                const util::JSON::Object &object) override;
            /// \brief
            /// Write a Serializable to the JSON DOM.
            /// \param[out] node Parent node.
            virtual void Write (util::JSON::Object &object) const override;

            /// \brief
            /// PacketFragmentPacket is neither copy constructable nor assignable.
            THEKOGANS_PACKET_DISALLOW_COPY_AND_ASSIGN (PacketFragmentPacket)
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_PacketFragmentPacket_h)
