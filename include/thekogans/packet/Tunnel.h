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

#if !defined (__thekogans_packet_Tunnel_h)
#define __thekogans_packet_Tunnel_h

#include <ctime>
#include <memory>
#include <string>
#include <thekogans/util/GUID.h>
#include <thekogans/util/Constants.h>
#include <thekogans/util/Heap.h>
#include <thekogans/util/SpinLock.h>
#include <thekogans/util/Event.h>
#include <thekogans/util/JobQueue.h>
#include <thekogans/util/Buffer.h>
#include <thekogans/util/IntrusiveList.h>
#include <thekogans/util/SystemInfo.h>
#include <thekogans/crypto/Cipher.h>
#include <thekogans/crypto/KeyRing.h>
#include <thekogans/crypto/KeyExchange.h>
#include <thekogans/stream/AsyncIoEventSink.h>
#include <thekogans/stream/TCPSocket.h>
#include <thekogans/stream/Address.h>
#include <thekogans/packet/FrameParser.h>
#include <thekogans/packet/Session.h>
#include "thekogans/packet/Config.h"

namespace thekogans {
    namespace packet {

        struct DiscoveryMgr;
        struct ConnectionMgr;

        /// \struct Tunnel Tunnel.h thekogans/packet/Tunnel.h
        ///
        /// \brief
        /// Tunnel represents a secure TCP channel between two hosts.
        /// It can carry traffic (\see{ClientDataPacket} and \see{DataPacket})
        /// for multiple \see{Client}s. Tunnels are what define the Flow network.

        struct _LIB_THEKOGANS_PACKET_DECL Tunnel :
                public util::Subscriber<stream::StreamEvents>,
                public util::Subscriber<stream::TCPSocketEvents>,
                public FrameParser::PacketHandler {
            /// \brief
            /// Convenient typedef for util::RefCounted::SharedPtr<Tunnel>.
            THEKOGANS_UTIL_DECLARE_REF_COUNTED_POINTERS (Tunnel)

        private:
            stream::TCPSocket::SharedPtr socket;
            /// \enum
            /// Helps to maintain causality. Establishing a secure tunnel
            /// requires a handshake, and that requires a state machine.
            enum {
                /// \brief
                /// Waiting for peer to accept our connection request.
                STATE_WAITING_FOR_CONNECT,
                /// \brief
                /// Waiting for the \see{ClientHelloPacket} packet.
                STATE_WAITING_FOR_CLIENT_HELLO,
                /// \brief
                /// Waiting for the \see{ServerHelloPacket} packet.
                STATE_WAITING_FOR_SERVER_HELLO,
                /// \brief
                /// Waiting for the \see{PromoteConnectionPacket} packet.
                STATE_WAITING_FOR_PROMOTE_CONNECTION,
                /// \brief
                /// Ready to send and receive data (\see{DataPacket})
                /// through the tunnel.
                STATE_WAITING_FOR_DATA
            } state;
            /// \brief
            /// Keeps track of the last packet sent time. Used to test
            /// the health of an idle tunnel (\see{HeartbeatPacket}).
            util::TimeSpec lastSentPacketTime;
            /// \brief
            /// Keeps track of the last packet received time. Used to test
            /// the health of an idle tunnel (\see{HeartbeatPacket}).
            util::TimeSpec lastReceivedPacketTime;
            /// \brief
            /// Current session info.
            Session session;
            /// \brief
            /// Tunnel's packet parser.
            FrameParser parser;
            /// \brief
            /// For multi-chunk \see{DataPacket} packets, will collect the chunks.
            util::Buffer packetBuffer;
            /// \brief
            /// Synchronization lock.
            util::SpinLock spinLock;

        public:
            /// \brief
            /// ctor for initiating a connection to a remote peer.
            Tunnel (
                stream::TCPSocket::SharedPtr socket_,
                crypto::KeyRing::SharedPtr keyRing_);

            inline stream::TCPSocket::SharedPtr GetSocket () const {
                return socket;
            }

            /// \brief
            /// Used by clients to send a packet of data through the tunnel.
            /// \param[in] packet \see{Packet} to send.
            /// \param[in] compress true == Deflate the packet.
            void SendPacket (
                Packet::SharedPtr packet,
                bool compress = false);

        private:
            /// \brief
            /// Send \see{ClientKeyExchangePacket} to the peer.
            /// \param[in] paramsOrKeyId For [EC]DHE, represents the \see{crypto::Params}
            /// id used for key exchange. For RSA, represents the \see{crypto::AsymmetricKey}
            /// public key used to encrypt a \see{crypto::SymmetricKey}.
            void InitiateKeyExchange (const crypto::ID &paramsOrKeyId);

            /// \brief
            /// \see{HeartbeatPacket} packets are used to probe the health
            /// of the connection. They are initiated by \see{ConnectionMgr}
            /// when it has determined (by using lastPacketTime) that
            /// a tunnel has been idle for a predetermined interval.
            void SendHeartbeat ();

            // stream::StreamEvents
            /// \brief
            /// Data has arrived on a Tunnel.
            /// \param[in] stream Tunnel on which data has arrived.
            /// \param[in] buffer New data.
            virtual void OnStreamRead (
                stream::Stream::SharedPtr stream,
                util::Buffer::SharedPtr buffer) throw () override;
            /// \brief
            /// Called when data was written to a stream.
            /// \param[in] stream Stream where data was written.
            /// \param[in] buffer The written data.
            virtual void OnStreamWrite (
                stream::Stream::SharedPtr /*stream*/,
                util::Buffer::SharedPtr /*buffer*/) throw () override;
            // stream::TCPSocketEvents
            /// \brief
            /// Called to inform that a new Tunnel connected.
            /// \param[in] tcpSocket Tunnel that connected.
            virtual void OnTCPSocketConnected (
                stream::TCPSocket::SharedPtr tcpSocket) throw () override;

            // FrameParser::PacketHandler
            /// \brief
            /// Called by the parser to get the cipher for a given key id.
            /// \param[in] keyId \see{crypto::SymmetricKey} id.
            /// \return \see{crypto::Cipher} corresponding to
            /// the given key id.
            virtual crypto::Cipher::SharedPtr GetCipherForKeyId (
                const crypto::ID &keyId) throw () override;
            /// \brief
            /// Called by the parser to get the current \see{Session}.
            /// \return Current session (0 if not using sessions).
            virtual Session *GetCurrentSession () throw () override;
            /// \brief
            /// Called by the parser to let the handler know a packet was parsed.
            /// \param[in] packet New \see{Packet}.
            /// \param[in] cipher \see{crypto::Cipher}
            /// that was used to decrypt this packet.
            virtual void HandlePacket (
                Packet::SharedPtr packet,
                crypto::Cipher::SharedPtr cipher) throw () override;

            /// \brief
            /// \see{DiscoveryMgr} needs access to the private ctor.
            friend struct DiscoveryMgr;
            /// \brief
            /// \see{ConnectionMgr} needs access to \see{SendHeartbeat}.
            friend struct ConnectionMgr;

            /// \brief
            /// Tunnel is neither copy constructable nor assignable.
            THEKOGANS_UTIL_DISALLOW_COPY_AND_ASSIGN (Tunnel)
        };

    } // namespace packet
} // namespace thekogans

#endif // !defined (__thekogans_packet_Tunnel_h)
