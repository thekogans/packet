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

#include "thekogans/packet/ClientKeyExchangePacket.h"

namespace thekogans {
    namespace packet {

        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (
            ClientKeyExchangePacket,
            1,
            util::SpinLock,
            8,
            util::DefaultAllocator::Global)

        void ClientKeyExchangePacket::Read (
                const BinHeader & /*header*/,
                util::Serializer &serializer) {
            serializer >> cipherSuite >> params;
        }

        void ClientKeyExchangePacket::Write (util::Serializer &serializer) const {
            serializer << cipherSuite << *params;
        }

        const char * const ClientKeyExchangePacket::ATTR_CIPHER_SUITE = "CipherSuite";
        const char * const ClientKeyExchangePacket::TAG_PARAMS = "Params";

        void ClientKeyExchangePacket::Read (
                const TextHeader & /*header*/,
                const pugi::xml_node &node) {
            cipherSuite = node.attribute (ATTR_CIPHER_SUITE).value ();
            pugi::xml_node paramsNode = node.child (TAG_PARAMS);
            paramsNode >> params;
        }

        void ClientKeyExchangePacket::Write (pugi::xml_node &node) const {
            node.append_attribute (ATTR_CIPHER_SUITE).set_value (cipherSuite.c_str ());
            pugi::xml_node paramsNode = node.append_child (TAG_PARAMS);
            paramsNode << *params;
        }

        void ClientKeyExchangePacket::Read (
                const TextHeader & /*header*/,
                const util::JSON::Object &object) {
            // FIXME: implement
            assert (0);
        }

        void ClientKeyExchangePacket::Write (util::JSON::Object &object) const {
            // FIXME: implement
            assert (0);
        }

    } // namespace packet
} // namespace thekogans
