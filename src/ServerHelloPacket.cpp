// ServerHelloPacket.cpp - Packet
//
// Created by Boris Kogan on 4/25/2016.
// Copyright (c) 2016 Thekogans, Inc. All rights reserved.

#include "thekogans/packet/ServerHelloPacket.h"

namespace thekogans {
    namespace packet {

        THEKOGANS_UTIL_IMPLEMENT_SERIALIZABLE (ServerHelloPacket, 1)

        void ServerHelloPacket::Read (
                const BinHeader & /*header*/,
                util::Serializer &serializer) {
            serializer >> hostId >> session >> cipherSuite >> params;
        }

        void ServerHelloPacket::Write (util::Serializer &serializer) const {
            serializer << hostId << session << cipherSuite << *params;
        }

        void ServerHelloPacket::Read (
                const TextHeader & /*header*/,
                const pugi::xml_node &node) {
            // FIXME: implement
            assert (0);
        }

        void ServerHelloPacket::Write (pugi::xml_node &node) const {
            // FIXME: implement
            assert (0);
        }

        void ServerHelloPacket::Read (
                const TextHeader & /*header*/,
                const util::JSON::Object &object) {
            // FIXME: implement
            assert (0);
        }

        void ServerHelloPacket::Write (util::JSON::Object &object) const {
            // FIXME: implement
            assert (0);
        }

    } // namespace packet
} // namespace thekogans
