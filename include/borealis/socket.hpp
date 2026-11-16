#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

/**
 * Low-level BSD-style sockets: the portable layer under borealis::net, for code written against the
 * sockets API (non-blocking calls that report would-block, readiness polling, datagrams with their
 * peers). Platform differences (Winsock, POSIX, SIGPIPE, UDP connection resets) are handled here.
 *
 * Calls never throw. A failed call returns an Error; Error::WouldBlock and Error::InProgress are the
 * non-blocking results. Addresses and ports are in host byte order.
 */
namespace borealis::socket {

enum class Error {
    None,
    WouldBlock, // a non-blocking call that would wait
    InProgress, // a non-blocking connect that has started
    Interrupted,
    Invalid,     // a bad argument or a closed socket
    Unsupported, // sockets are not available on this platform
    Resolve,
    Refused,
    Unreachable,
    Reset,
    AddressInUse,
    Permission,
    Timeout,
    Network,
};

enum class Family { IPv4, IPv6 };
enum class Type { Stream, Datagram };

struct Address {
    Family family = Family::IPv4;
    /** IPv4 in the first four bytes, most significant first (127.0.0.1 is {127, 0, 0, 1}). */
    std::array<uint8_t, 16> bytes{};
    uint16_t port = 0;

    static Address ipv4(uint32_t address, uint16_t port) noexcept;
    /** The IPv4 address as a host-order number (the first byte the most significant). */
    uint32_t ipv4_value() const noexcept;
    bool operator==(const Address&) const = default;
};

/** "1.2.3.4" or "::1"; empty when it is neither. */
std::optional<Address> parse_address(std::string_view text, uint16_t port = 0);
std::string format_address(const Address& address, bool withPort = false);

/** Whether sockets work on this platform. */
bool available() noexcept;

/** The host's addresses for a name (blocking; numeric names do not look anything up). */
std::vector<Address> resolve(std::string_view host, Family family = Family::IPv4, Error* error = nullptr);

/** The address this host would use toward the internet (nothing is sent), for peers that report it. */
std::optional<Address> local_address(Family family = Family::IPv4);

struct PollEntry;
class Socket;

/** Waits until an entry is ready or the timeout passes (0: no wait; negative: forever); the count of ready entries, or -1. */
int poll(std::span<PollEntry> entries, std::chrono::milliseconds timeout, Error* error = nullptr) noexcept;

class Socket {
public:
    Socket() = default;
    ~Socket();
    Socket(Socket&& other) noexcept;
    Socket& operator=(Socket&& other) noexcept;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;

    /** A new socket (blocking until set_nonblocking). */
    static Socket open(Family family, Type type, Error* error = nullptr);

    bool valid() const noexcept;
    void close() noexcept;

    Error set_nonblocking(bool enabled) noexcept;
    Error set_reuse_address(bool enabled) noexcept;
    Error set_broadcast(bool enabled) noexcept;
    Error set_no_delay(bool enabled) noexcept;
    Error set_receive_buffer(int bytes) noexcept;
    Error set_send_buffer(int bytes) noexcept;
    std::optional<int> receive_buffer() const noexcept;
    std::optional<int> send_buffer() const noexcept;

    Error bind(const Address& address) noexcept;
    Error listen(int backlog) noexcept;
    /** A pending connection, or Error::WouldBlock. */
    Socket accept(Address* peer, Error* error) noexcept;
    /** Error::InProgress for a non-blocking socket: poll for writable, then check pending_error. */
    Error connect(const Address& address) noexcept;
    /** The error of a finished non-blocking connect (SO_ERROR), Error::None if it succeeded. */
    Error pending_error() const noexcept;
    Error shutdown_send() noexcept;

    std::optional<Address> local() const noexcept;
    std::optional<Address> peer() const noexcept;

    /** Bytes sent or received (0 on a receive: the peer closed), or the error. */
    std::ptrdiff_t send(std::span<const std::byte> data, Error* error) noexcept;
    std::ptrdiff_t receive(std::span<std::byte> data, Error* error, bool peek = false) noexcept;
    std::ptrdiff_t send_to(std::span<const std::byte> data, const Address& to, Error* error) noexcept;
    std::ptrdiff_t receive_from(std::span<std::byte> data, Address* from, Error* error, bool peek = false) noexcept;

    /** Bytes ready to read without waiting (FIONREAD). */
    std::optional<size_t> available_bytes() const noexcept;

    /** The platform's error text for the last failed call on this thread. */
    static std::string last_error_message();

private:
    friend int poll(std::span<PollEntry> entries, std::chrono::milliseconds timeout, Error* error) noexcept;
    std::intptr_t m_handle = -1;
    Family m_family = Family::IPv4;
};

/** Readiness bits for poll. */
enum PollEvents : uint32_t {
    PollRead = 1 << 0,
    PollWrite = 1 << 1,
    PollError = 1 << 2,  // result only
    PollHangup = 1 << 3, // result only
    PollInvalid = 1 << 4, // result only: not a socket
};

struct PollEntry {
    const Socket* socket = nullptr;
    uint32_t events = 0;  // PollRead | PollWrite
    uint32_t revents = 0; // filled by poll
};

} // namespace borealis::socket
