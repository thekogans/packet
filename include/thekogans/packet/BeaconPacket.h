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

#if !defined (__thekogans_packet_BeaconPacket_h)
#define __thekogans_packet_BeaconPacket_h

#include <string>
#include "thekogans/util/Serializer.h"
#include "thekogans/packet/Config.h"
#include "thekogans/packet/Packet.h"

namespace thekogans {
    namespace packet {

        /// \struct BeaconPacket BeaconPacket.h thekogans/packet/BeaconPacket.h
        ///
        /// \brief
        /// Encapsulates data that makes up the beacon packet. Beacon packets
        /// are used to discover peers on the local sub-net. Upon receipt of a
        /// beacon, the host will unicast a \see{PingPacket} and either wait
        /// to be connected to or, initiate a connection (if it's channel ordinal
        /// is lower then the peer that sent the \see{PingPacket} packet).

        struct _LIB_THEKOGANS_PACKET_DECL BeaconPacket : public Packet {
            /// \brief
            /// Pull in Packet dynamic creation machinery.
            THEKOGANS_UTIL_DECLARE_SERIALIZABLE (BeaconPacket)

            /// \brief
            /// Host id.
            std::string hostId;

            /// \brief
            /// ctor.
            /// \param[in] hostId_ Peer host id.
            BeaconPacket (const std::string &hostId_) :
                hostId (hostId_) {}

        protected:
            /// \brief
            /// Return serialized packet size.
            /// \return Serialized packet size.
            virtual std::size_t Size () const override {
                return util::Serializer::Size (hostId);
            }

            /// \brief
            /// Write the serializable from the given serializer.
            /// \param[in] header
            /// \param[in] serializer Serializer to read the serializable from.
            virtual void Read (
                const BinHeader & /*header*/,
                util::Serializer &serializer) override;
            /// \brief
            /// Write the serializable to the given serializer.
            /// \param[out] serializer Serializer to write the serializable to.
            virtual void Write (util::Serializer &serializer) const override;

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
            /// BeaconPacket is neither copy constructable nor assignable.
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (BeaconPacket)
        };

        /// \brief
        /// Implement BeaconPacket extraction operators.
        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE_EXTRACTION_OPERATORS (BeaconPacket)

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_BeaconPacket_h)
