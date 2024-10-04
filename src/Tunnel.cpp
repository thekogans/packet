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

#include <thekogans/util/Exception.h>
#include <thekogans/util/LoggerMgr.h>
#include <thekogans/util/StringUtils.h>
#include <thekogans/util/LockGuard.h>
#include <thekogans/crypto/EC.h>
#include <thekogans/crypto/DH.h>
#include "thekogans/packet/ClientHelloPacket.h"
#include "thekogans/packet/ServerHelloPacket.h"
#include "thekogans/packet/PromoteConnectionPacket.h"
#include <thekogans/packet/ClientKeyExchangePacket.h>
#include <thekogans/packet/ServerKeyExchangePacket.h>
#include "thekogans/packet/DataPacket.h"
#include "thekogans/packet/HeartbeatPacket.h"
#include "thekogans/packet/Tunnel.h"

using namespace thekogans;

namespace thekogans {
    namespace packet {

        namespace {
            void AddKeyExchangeParams (crypto::KeyRing &keyRing) {
                const crypto::CipherSuite &cipherSuite = keyRing->GetCipherSuite ();
                if (cipherSuite.keyExchange == crypto::CipherSuite::KEY_EXCHANGE_ECDHE) {
                    // FIXME: add other params.
                    keyRing->AddKeyExchangeParams (crypto::EC::ParamsFromX25519Curve ());
                }
                else if (cipherSuite.keyExchange == crypto::CipherSuite::KEY_EXCHANGE_DHE) {
                    // FIXME: add other params.
                    keyRing->AddKeyExchangeParams (
                        crypto::DH::ParamsFromRFC3526Prime (
                            crypto::DH::RFC3526_PRIME_8192));
                }
            }
            AddKeyExchangeParams (*keyRing);
        }

        Tunnel::Tunnel (
                stream::TCPSocket::SharedPtr tcpSocket_,
                crypto::KeyRing::SharedPtr keyRing_) :
                tcpSocket (tcpSocket_),
                keyRing (keyRing_),
                state (STATE_WAITING_FOR_CONNECT),
                lastSentPacketTime (util::GetCurrentTime ()),
                lastReceivedPacketTime (lastSentPacketTime) {
            util::Subscriber<stream::StreamEvents>::Subscribe (*tcpSocket);
            util::Subscriber<stream::TCPSocketEvents>::Subscribe (*tcpSocket);
        }

        void Tunnel::SendPacket (
                Packet::SharedPtr packet,
                bool compress) {
            if (state == STATE_WAITING_FOR_DATA) {
                util::Buffer buffer (util::NetworkEndian, packet->GetSize ());
                buffer << packet;
                std::size_t packetSize = buffer.GetDataAvailableForReading ();
                std::size_t chunkSize =
                    parser.GetMaxCiphertextLength () -
                    Packet::GetMaxFramingOverhead (
                        DataPacket::TYPE,
                        parser.GetMaxCiphertextLength ());
                // If the buffer is too big, fragment it.
                // It will be reassembled on the other side.
                if (packetSize > chunkSize) {
                    std::size_t chunkCount = packetSize / chunkSize;
                    if ((packetSize % chunkSize) > 0) {
                        ++chunkCount;
                    }
                    util::LockGuard<util::SpinLock> guard (spinLock);
                    for (std::size_t chunkNumber = 1; chunkNumber <= chunkCount; ++chunkNumber) {
                        util::Buffer::SharedPtr chunk (
                            new util::Buffer (util::NetworkEndian, chunkSize));
                        chunk->AdvanceWriteOffset (
                            buffer.Read (
                                chunk.GetWritePtr (),
                                chunk.GetDataAvailableForWriting ()));
                        tcpSocket->Write (
                            DataPacket (
                                util::SystemInfo::Instance ().GetHostName (),
                                chunkNumber,
                                chunkCount,
                                std::move (chunk)).Serialize (
                                    *keyRing->GetRandomCipher (),
                                    &session,
                                    compress));
                    }
                }
                else {
                    tcpSocket->Write (
                        DataPacket (
                            util::SystemInfo::Instance ().GetHostName (),
                            1,
                            1,
                            std::move (buffer)).Serialize (
                                *keyRing->GetRandomCipher (),
                                &session,
                                compress));
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid tunnel state: (%u, %u).",
                    state,
                    STATE_WAITING_FOR_DATA);
            }
        }

        void Tunnel::InitiateKeyExchange (const crypto::ID &paramsOrKeyId) {
            if (state == STATE_WAITING_FOR_DATA) {
                crypto::KeyExchange::SharedPtr keyExchange =
                    keyRing->AddKeyExchange (paramsOrKeyId);
                if (keyExchange != nullptr) {
                    tcpSocket->Write (
                        ClientKeyExchangePacket (
                            keyRing->GetCipherSuite ().ToString (),
                            keyExchange->GetParams ()).Serialize (
                                *keyRing->GetRandomCipher (), &session));
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Unable to get key exchange for id: %s.",
                        paramsOrKeyId.ToHexString ().c_str ());
                }
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid tunnel state: (%u, %u).",
                    state,
                    STATE_WAITING_FOR_DATA);
            }
        }

        void Tunnel::SendHeartbeat () {
            if (state == STATE_WAITING_FOR_DATA) {
                // Send a heartbeat packet to the peer. If the peer is
                // unreachable we will know soon enough and will shut
                // down the tunnel.
                HeartbeatPacket heartbeat (lastReceivedPacketTime);
                tcpSocket->Write (
                    heartbeat.Serialize (
                        *keyRing->GetRandomCipher (),
                        &session));
            }
            else {
                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                    "Invalid tunnel state: (%u, %u).",
                    state,
                    STATE_WAITING_FOR_DATA);
            }
        }

        void Tunnel::OnStreamRead (
                stream::Stream::SharedPtr stream,
                util::Buffer::SharedPtr buffer) throw () {
            lastReceivedPacketTime = util::GetCurrentTime ();
            THEKOGANS_UTIL_TRY {
                jobQueue.EnqJob (
                    [this, buffer] (
                            const RunLoop::Job & /*job*/,
                            const std::atomic<bool> & /*done*/) {
                        if (!job.ShouldStop (done)) {
                            THEKOGANS_UTIL_TRY {
                                tunnel->parser.HandleBuffer (buffer, *tunnel);
                            }
                            THEKOGANS_UTIL_CATCH (util::Exception) {
                                tunnel->OnStreamError (streqam, exception);
                            }
                        }
                    }
                );
            }
            THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_PACKET)
        }

        void Tunnel::OnStreamWrite (
                stream::Stream & /*stream*/,
                util::Buffer /*buffer*/) throw () {
            lastSentPacketTime = util::GetCurrentTime ();
        }

        void Tunnel::OnTCPSocketConnected (
                stream::TCPSocket::SharedPtr tcpSocket) throw () {
            THEKOGANS_UTIL_TRY {
                if (state == STATE_WAITING_FOR_CONNECT) {
                    Device::SharedPtr device =
                        DeviceMgr::Instance ().GetDevice (deviceId, deviceSerialNumber);
                    if (device != nullptr) {
                        crypto::KeyExchange::SharedPtr keyExchange =
                            keyRing->AddKeyExchange (paramsOrKeyId);
                        if (keyExchange != nullptr) {
                            {
                                util::LockGuard<util::SpinLock> guard (spinLock);
                                tcpSocket->Write (
                                    ClientHelloPacket (
                                        util::SystemInfo::Instance ().GetHostName (),
                                        keyRing->GetCipherSuite ().ToString (),
                                        keyExchange->GetParams ()).Serialize (
                                            device->GetCipher (), 0));
                            }
                            state = STATE_WAITING_FOR_SERVER_HELLO;
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unknown key exchange id: %s.",
                                paramsOrKeyId.ToHexString ().c_str ());
                        }
                    }
                    else {
                        THEKOGANS_UTIL_LOG_SUBSYSTEM_DEBUG (
                            THEKOGANS_PACKET,
                            "Unble to locate device: (%u, %u).",
                            deviceId,
                            deviceSerialNumber);
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Invalid tunnel state: (%u, %u).",
                        state,
                        STATE_WAITING_FOR_CONNECT);
                }
            }
            THEKOGANS_UTIL_CATCH_AND_LOG_SUBSYSTEM (THEKOGANS_PACKET)
        }

        crypto::Cipher::SharedPtr Tunnel::GetCipherForKeyId (
                const crypto::ID &keyId) throw () {
            return keyRing->GetCipher (keyId);
        }

        Session *Tunnel::GetCurrentSession () throw () {
            return state == STATE_WAITING_FOR_DATA ? &session : 0;
        }

        void Tunnel::HandlePacket (
                Packet::SharedPtr packet,
                crypto::Cipher::SharedPtr cipher) throw () {
            THEKOGANS_UTIL_TRY {
                if (packet->GetType () == ClientHelloPacket::TYPE) {
                    if (state == STATE_WAITING_FOR_CLIENT_HELLO) {
                        ClientHelloPacket *clientHello =
                            static_cast<ClientHelloPacket *> (packet.Get ());
                        crypto::KeyExchange::SharedPtr keyExchange =
                            keyRing->CreateKeyExchange (clientHello->params);
                        if (keyExchange != nullptr) {
                            keyRing->AddCipherKey (
                                keyExchange->DeriveSharedSymmetricKey (clientHello->params));
                            {
                                util::LockGuard<util::SpinLock> guard (spinLock);
                                // NOTE: We use device's cipher to encrypt the ServerHelloPacket.
                                // After the peer has processed the ServerHelloPacket packet, both
                                // hosts switch to using the newly negotiated cipher.
                                // NOTE: We swap our sessions inbound and outbound sequence numbers
                                // because the client expects them in reverse order.
                                tcpSocket->Write (
                                    ServerHelloPacket (
                                        util::SystemInfo::Instance ().GetHostName (),
                                        session.GetPeerSession (),
                                        clientHello->cipherSuite,
                                        keyExchange->GetParams ()).Serialize (*cipher, 0));
                            }
                            state = STATE_WAITING_FOR_PROMOTE_CONNECTION;
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to create the key exchange: %s.",
                                clientHello->params->id.ToHexString ().c_str ());
                        }
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Invalid tunnel state (%u, %u).",
                            state,
                            STATE_WAITING_FOR_CLIENT_HELLO);
                    }
                }
                else if (packet->GetType () == ServerHelloPacket::TYPE) {
                    if (state == STATE_WAITING_FOR_SERVER_HELLO) {
                        ServerHelloPacket *serverHello =
                            static_cast<ServerHelloPacket *> (packet.Get ());
                        if (hostId == serverHello->hostId) {
                            session = serverHello->session;
                            crypto::KeyExchange::SharedPtr keyExchange =
                                keyRing->GetKeyExchange (serverHello->params->id);
                            if (keyExchange != nullptr) {
                                keyRing->AddCipherKey (
                                    keyExchange->DeriveSharedSymmetricKey (serverHello->params));
                                {
                                    util::LockGuard<util::SpinLock> guard (spinLock);
                                    tcpSocket->Write (
                                        PromoteConnectionPacket (
                                            util::SystemInfo::Instance ().GetHostName ()).Serialize (
                                                *cipher, 0));
                                }
                                ConnectionMgr::Instance ().PromotePendingConnection (*this, true);
                                state = STATE_WAITING_FOR_DATA;
                            }
                            else {
                                THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                    "Unable to locate the key exchange: %s.",
                                    serverHello->params->id.ToHexString ().c_str ());
                            }
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "hostId missmatch; expecting: %s, got %s.",
                                hostId.c_str (),
                                serverHello->hostId.c_str ());
                        }
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Invalid tunnel state (%u, %u).",
                            state,
                            STATE_WAITING_FOR_SERVER_HELLO);
                    }
                }
                else if (packet->GetType () == PromoteConnectionPacket::TYPE) {
                    if (state == STATE_WAITING_FOR_PROMOTE_CONNECTION) {
                        PromoteConnectionPacket *promoteConnection =
                            static_cast<PromoteConnectionPacket *> (packet.Get ());
                        if (hostId == promoteConnection->hostId) {
                            ConnectionMgr::Instance ().PromotePendingConnection (*this, false);
                            state = STATE_WAITING_FOR_DATA;
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "hostId missmatch; expecting: %s, got %s.",
                                hostId.c_str (),
                                promoteConnection->hostId.c_str ());
                        }
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Invalid tunnel state (%u, %u).",
                            state,
                            STATE_WAITING_FOR_SERVER_HELLO);
                    }
                }
                else if (packet->GetType () == ClientKeyExchangePacket::TYPE) {
                    if (state == STATE_WAITING_FOR_DATA) {
                        ClientKeyExchangePacket *clientKeyExchange =
                            static_cast<ClientKeyExchangePacket *> (packet.Get ());
                        crypto::KeyExchange::SharedPtr keyExchange =
                            keyRing->CreateKeyExchange (clientKeyExchange->params);
                        if (keyExchange != nullptr) {
                            keyRing->AddCipherKey (
                                keyExchange->DeriveSharedSymmetricKey (clientKeyExchange->params));
                            {
                                util::LockGuard<util::SpinLock> guard (spinLock);
                                WriteBuffer (
                                    ServerKeyExchangePacket (
                                        clientKeyExchange->cipherSuite,
                                        keyExchange->GetParams ()).Serialize (*cipher, &session));
                            }
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to create the key exchange: %s.",
                                clientKeyExchange->params->id.ToHexString ().c_str ());
                        }
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Invalid tunnel state (%u, %u).",
                            state,
                            STATE_WAITING_FOR_CLIENT_HELLO);
                    }
                }
                else if (packet->GetType () == ServerKeyExchangePacket::TYPE) {
                    if (state == STATE_WAITING_FOR_DATA) {
                        ServerKeyExchangePacket *serverKeyExchange =
                            static_cast<ServerKeyExchangePacket *> (packet.Get ());
                        crypto::KeyExchange::SharedPtr keyExchange =
                            keyRing->GetKeyExchange (serverKeyExchange->params->id);
                        if (keyExchange != nullptr) {
                            keyRing->AddCipherKey (
                                keyExchange->DeriveSharedSymmetricKey (serverKeyExchange->params));
                        }
                        else {
                            THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                                "Unable to locate the key exchange: %s.",
                                serverKeyExchange->params->id.ToHexString ().c_str ());
                        }
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Invalid tunnel state (%u, %u).",
                            state,
                            STATE_WAITING_FOR_SERVER_HELLO);
                    }
                }
                else if (packet->GetType () == DataPacket::TYPE) {
                    if (state == STATE_WAITING_FOR_DATA) {
                        DataPacket *Data =
                            static_cast<DataPacket *> (packet.Get ());
                        // reassemble the fragmented packet.
                        if (Data->chunkCount > 1) {
                            if (Data->chunkNumber == 1) {
                                DataBuffer = util::Buffer (
                                    util::NetworkEndian,
                                    Data->chunkCount * parser.GetMaxCiphertextLength ());
                            }
                            DataBuffer.Write (
                                Data->buffer.GetReadPtr (),
                                Data->buffer.GetDataAvailableForReading ());
                            if (Data->chunkNumber == Data->chunkCount) {
                                Data->buffer = std::move (DataBuffer);
                            }
                        }
                        if (Data->chunkNumber == Data->chunkCount) {
                            Packet::SharedPtr packet;
                            Data->buffer >> packet;
                            if (!FilterSyncOpPacket (Data->hostId, packet)) {
                                Info::Instance ().HandlePacket (
                                    Data->hostId,
                                    packet);
                            }
                        }
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Invalid tunnel state (%u, %u).",
                            state,
                            STATE_WAITING_FOR_DATA);
                    }
                }
                else if (packet->GetType () == HeartbeatPacket::TYPE) {
                    if (state == STATE_WAITING_FOR_DATA) {
                        HeartbeatPacket *heartbeat =
                            static_cast<HeartbeatPacket *> (packet.Get ());
                        Info::Instance ().HandleHeartbeat (
                            hostId,
                            heartbeat->lastReceivedPacketTime,
                            heartbeat->currentTime);
                    }
                    else {
                        THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                            "Invalid tunnel state: (%u, %u).",
                            state,
                            STATE_WAITING_FOR_DATA);
                    }
                }
                else {
                    THEKOGANS_UTIL_THROW_STRING_EXCEPTION (
                        "Received an unknown packet, id: %s.",
                        packet->GetType ().c_str ());
                }
            }
            THEKOGANS_UTIL_CATCH (util::Exception) {
                // Network errors are seldom recoverable. Do the only
                // sensible thing here and shut down the tunnel. This
                // policy has an added bonus that DDOS attacks will be
                // detected and shutdown early.
                // NOTE: Event handlers will be notified of both the
                // exception and the connection close. It's up to the
                // individual handler to use whatever policy it deems
                // necessary (including initiating rediscovery).
                HandleError (exception);
            }
        }

    } // namespace packet
} // namespace thekogans
