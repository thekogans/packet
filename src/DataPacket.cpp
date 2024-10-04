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

#include "thekogans/marconi/DataPacket.h"

namespace thekogans {
    namespace packet {

        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (DataPacket, 1)

        void DataPacket::Read (
                const BinHeader & /*header*/,
                util::Serializer &serializer) {
            serializer >> hostId >> chunkNumber >> chunkCount >> buffer;
        }

        void DataPacket::Write (util::Serializer &serializer) const {
            serializer << hostId << chunkNumber << chunkCount << buffer;
        }

        namespace {
            const char * const ATTR_HOST_ID = "hostId";
            const char * const ATTR_CHUNK_NUMBER = "chunkNumber";
            const char * const ATTR_CHUNK_COUNT = "chunkCount";
            const char * const TAG_BUFFER = "buffer";
        }

        void DataPacket::Read (
                const TextHeader & /*header*/,
                const pugi::xml_node &node) {
            hostId = node.attribute (ATTR_HOST_ID).value ();
            chunkNumber = util::stringToui64 (node.attribute (ATTR_CHUNK_NUMBER).value ());
            chunkCount = util::stringToui64 (node.attribute (ATTR_CHUNK_COUNT).value ());
            pugi::xml_node child = node.child (TAG_BUFFER);
            child >> buffer;
        }

        void DataPacket::Write (pugi::xml_node &node) const {
            node.append_attribute (ATTR_HOST_ID).set_value (
                util::EncodeXMLCharEntities (hostId).c_str ());
            node.append_attribute (ATTR_CHUNK_NUMBER).set_value (
                util::ui64Tostring (chunkNumber).c_str ());
            node.append_attribute (ATTR_CHUNK_COUNT).set_value (
                util::ui64Tostring (chunkCount).c_str ());
            pugi::xml_node child = node.append_child (TAG_BUFFER);
            child << buffer;
        }

        void DataPacket::Read (
                const TextHeader & /*header*/,
                const util::JSON::Object &object) {
            hostId = object.Get<util::JSON::String> (ATTR_HOST_ID)->value;
            chunkNumber = object.Get<util::JSON::Number> (ATTR_CHUNK_NUMBER)->To<util::ui64> ();
            chunkCount = object.Get<util::JSON::Number> (ATTR_CHUNK_COUNT)->To<util::ui64> ();
            util::JSON::Object::SharedPtr bufferObject = object.Get<util::JSON::Object> (TAG_BUFFER);
            if (bufferObject != nullptr) {
                *bufferObject >> buffer;
            }
        }

        void DataPacket::Write (util::JSON::Object &object) const {
            object.Add<const std::string &> (ATTR_HOST_ID, hostId);
            object.Add (ATTR_CHUNK_NUMBER, (util::ui64)chunkNumber);
            object.Add (ATTR_CHUNK_COUNT, (util::ui64)chunkCount);
            util::JSON::Object::SharedPtr bufferObject (new util::JSON::Object);
            *bufferObject << buffer;
            object.Add (TAG_BUFFER, bufferObject);
        }

    } // namespace packet
} // namespace thekogans
