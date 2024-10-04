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

#include "logitech/packet/HeartbeatPacket.h"

namespace thekogans {
    namespace packet {

        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (HeartbeatPacket, 1)

        void HeartbeatPacket::Read (
                const BinHeader & /*header*/,
                util::Serializer &serializer) {
            serializer >> lastReceivedPacketTime >> currentTime;
        }

        void HeartbeatPacket::Write (util::Serializer &serializer) const {
            serializer << lastReceivedPacketTime << currentTime;
        }

        namespace {
            const char * const ATTR_LAST_RECEIVED_PACKET_TIME = "lastReceivedPacketTime";
            const char * const ATTR_CURRENT_TIME = "currentTime";
        }

        void HeartbeatPacket::Read (
                const TextHeader & /*header*/,
                const pugi::xml_node &node) {
            lastReceivedPacketTime = util::stringToi64 (
                node.attribute (ATTR_LAST_RECEIVED_PACKET_TIME).value ());
            currentTime = util::stringToi64 (node.attribute (ATTR_CURRENT_TIME).value ());
        }

        void HeartbeatPacket::Write (pugi::xml_node &node) const {
            node.append_attribute (ATTR_LAST_RECEIVED_PACKET_TIME).set_value (
                util::i64Tostring (lastReceivedPacketTime).c_str ());
            node.append_attribute (ATTR_CURRENT_TIME).set_value (
                util::i64Tostring (currentTime).c_str ());
        }

        void HeartbeatPacket::Read (
                const TextHeader & /*header*/,
                const util::JSON::Object &object) {
            lastReceivedPacketTime = object.Get<util::JSON::Number> (
                ATTR_LAST_RECEIVED_PACKET_TIME)->To<util::i64> ();
            currentTime = object.Get<util::JSON::Number> (ATTR_CURRENT_TIME)->To<util::i64> ();
        }

        void HeartbeatPacket::Write (util::JSON::Object &object) const {
            object.Add (ATTR_LAST_RECEIVED_PACKET_TIME, lastReceivedPacketTime);
            object.Add (ATTR_CURRENT_TIME, currentTime);
        }

    } // namespace packet
} // namespace thekogans
