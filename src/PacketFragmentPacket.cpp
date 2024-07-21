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

#include "thekogans/util/StringUtils.h"
#include "thekogans/util/Base64.h"
#include "thekogans/packet/PacketFragmentPacket.h"

namespace thekogans {
    namespace packet {

        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (PacketFragmentPacket, 1)

        void PacketFragmentPacket::Read (
                const BinHeader & /*header*/,
                util::Serializer &serializer) {
            serializer >> fragmentNumber >> fragmentCount >> fragment;
        }

        void PacketFragmentPacket::Write (util::Serializer &serializer) const {
            serializer << fragmentNumber << fragmentCount << fragment;
        }

        const char * const PacketFragmentPacket::ATTR_FRAGMENT_NUMBER = "FragmentNumber";
        const char * const PacketFragmentPacket::ATTR_FRAGMENT_COUNT = "FragmentCount";

        void PacketFragmentPacket::Read (
                const TextHeader & /*header*/,
                const pugi::xml_node &node) {
            fragmentNumber = util::stringToui64 (node.attribute (ATTR_FRAGMENT_NUMBER).value ());
            fragmentCount = util::stringToui64 (node.attribute (ATTR_FRAGMENT_COUNT).value ());
            const char *encodedFragment = node.text ().get ();
            fragment = util::Base64::Decode (encodedFragment, strlen (encodedFragment));
        }

        void PacketFragmentPacket::Write (pugi::xml_node &node) const {
            node.append_attribute (ATTR_FRAGMENT_NUMBER).set_value (
                util::ui64Tostring (fragmentNumber).c_str ());
            node.append_attribute (ATTR_FRAGMENT_COUNT).set_value (
                util::ui64Tostring (fragmentCount).c_str ());
            node.append_child (pugi::node_pcdata).set_value (
                util::Base64::Encode (
                    fragment.GetReadPtr (),
                    fragment.GetDataAvailableForReading ()).Tostring ().c_str ());
        }

        void PacketFragmentPacket::Read (
                const TextHeader & /*header*/,
                const util::JSON::Object & /*object*/) {
            // FIXME: implement
            assert (0);
        }

        void PacketFragmentPacket::Write (util::JSON::Object & /*object*/) const {
            // FIXME: implement
            assert (0);
        }

    } // namespace packet
} // namespace thekogans
