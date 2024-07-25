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

#if !defined (__thekogans_packet_Config_h)
#define __thekogans_packet_Config_h

#if !defined (__cplusplus)
    #error libthekogans_packet requires C++ compilation (use a .cpp suffix)
#endif // !defined (__cplusplus)

#include "thekogans/util/Environment.h"

#if defined (TOOLCHAIN_OS_Windows)
    #define _LIB_THEKOGANS_PACKET_API __stdcall
    #if defined (THEKOGANS_PACKET_TYPE_Shared)
        #if defined (_LIB_THEKOGANS_PACKET_BUILD)
            #define _LIB_THEKOGANS_PACKET_DECL __declspec (dllexport)
        #else // defined (_LIB_THEKOGANS_PACKET_BUILD)
            #define _LIB_THEKOGANS_PACKET_DECL __declspec (dllimport)
        #endif // defined (_LIB_THEKOGANS_PACKET_BUILD)
    #else // defined (THEKOGANS_PACKET_TYPE_Shared)
        #define _LIB_THEKOGANS_PACKET_DECL
    #endif // defined (THEKOGANS_PACKET_TYPE_Shared)
    #if defined (_MSC_VER)
        #pragma warning (disable: 4251)  // using non-exported as public in exported
        #pragma warning (disable: 4786)
    #endif // defined (_MSC_VER)
#else // defined (TOOLCHAIN_OS_Windows)
    #define _LIB_THEKOGANS_PACKET_API
    #define _LIB_THEKOGANS_PACKET_DECL
#endif // defined (TOOLCHAIN_OS_Windows)

/// \def THEKOGANS_PACKET
/// Logging subsystem name.
#define THEKOGANS_PACKET "thekogans_packet"

#endif // !defined (__thekogans_packet_Config_h)
