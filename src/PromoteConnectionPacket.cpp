// PromoteConnectionPacket.cpp - Packet
//
// Created by Boris Kogan on 4/25/2016.
// Copyright (c) 2016 Thekogans, Inc. All rights reserved.

#include "thekogans/packet/PromoteConnectionPacket.h"

namespace thekogans {
    namespace packet {

        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (PromoteConnectionPacket, 1)

        void PromoteConnectionPacket::Read (
                const BinHeader & /*header*/,
                util::Serializer &serializer) {
            serializer >> hostId;
        }

        void PromoteConnectionPacket::Write (
                util::Serializer &serializer) const {
            serializer << hostId;
        }

        namespace {
            const char * const ATTR_HOST_ID = "hostId";
        }

        void PromoteConnectionPacket::Read (
                const TextHeader & /*header*/,
                const pugi::xml_node &node) {
            hostId = node.attribute (ATTR_HOST_ID).value ();
        }

        void PromoteConnectionPacket::Write (pugi::xml_node &node) const {
            node.append_attribute (ATTR_HOST_ID).set_value (
                util::EncodeXMLCharEntities (hostId).c_str ());
        }

        void PromoteConnectionPacket::Read (
                const TextHeader & /*header*/,
                const util::JSON::Object &object) {
            hostId = object.Get<util::JSON::String> (ATTR_HOST_ID)->value;
        }

        void PromoteConnectionPacket::Write (util::JSON::Object &object) const {
            object.Add<const std::string &> (ATTR_HOST_ID, hostId);
        }

    } // namespace packet
} // namespace thekogans
