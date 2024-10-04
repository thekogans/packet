// Copyright 2011 Boris Kogan (boris@thekogans.net)
//
// This file is part of libthekogans_util.
//
// libthekogans_util is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// libthekogans_util is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with libthekogans_util. If not, see <http://www.gnu.org/licenses/>.

#include "thekogans/packet/BeaconPacket.h"

namespace thekogans {
    namespace packet {

        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (BeaconPacket, 1)

        void BeaconPacket::Read (
                const BinHeader &header,
                util::Serializer &serializer) {
            serializer >> hostId;
        }

        void BeaconPacket::Write (util::Serializer &serializer) const {
            serializer << hostId;
        }

        namespace {
            const char * const ATTR_HOST_ID = "hostId";
        }

        void BeaconPacket::Read (
                const TextHeader &header,
                const pugi::xml_node &node) {
            hostId = node.attribute (ATTR_HOST_ID).value ();
        }

        void BeaconPacket::Write (pugi::xml_node &node) const {
            node.append_attribute (ATTR_HOST_ID).set_value (
                util::EncodeXMLCharEntities (hostId).c_str ());
        }

        void BeaconPacket::Read (
                const TextHeader &header,
                const util::JSON::Object &object) {
            hostId = object.Get<util::JSON::String> (ATTR_HOST_ID)->value ();
        }

        void BeaconPacket::Write (util::JSON::Object &object) const {
            object.Add<const std::string &> (ATTR_HOST_ID, hostId);
        }

    } // namespace packet
} // namespace thekogans
