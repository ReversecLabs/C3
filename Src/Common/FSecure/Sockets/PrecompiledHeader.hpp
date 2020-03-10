#pragma once

// Standard library includes.
#include <queue>
#include <mutex>
#include <atomic>
#include <thread>
#include <functional>
#include <cstdint>

// Windows includes.
#include <ws2tcpip.h>																									//< Windows Sockets.

// Static libraries.
#pragma comment(lib, "Ws2_32.lib")																						//< Windows Sockets.
