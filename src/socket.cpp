#include "borealis/socket.hpp"

#include "net/platform.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <utility>

namespace borealis::socket {

namespace platform = borealis::net::detail::platform;

namespace {

using platform::NativeSocket;

NativeSocket native(std::intptr_t handle) noexcept {
    return static_cast<NativeSocket>(handle);
}

bool initialize() noexcept {
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] { ok = platform::available() && platform::initialize(); });
    return ok;
}

Error map_error(int error, bool connecting = false) noexcept {
    if (platform::would_block(error)) {
        return connecting ? Error::InProgress : Error::WouldBlock;
    }
    if (connecting && platform::connect_in_progress(error)) {
        return Error::InProgress;
    }
    if (platform::interrupted(error)) {
        return Error::Interrupted;
    }
    switch (platform::map_socket_error(error)) {
    case net::Error::Refused:
        return Error::Refused;
    case net::Error::Unreachable:
        return Error::Unreachable;
    case net::Error::Reset:
        return Error::Reset;
    case net::Error::AddressInUse:
        return Error::AddressInUse;
    case net::Error::Permission:
        return Error::Permission;
    case net::Error::Timeout:
        return Error::Timeout;
    default:
        return Error::Network;
    }
}

Error last_error(bool connecting = false) noexcept {
    return map_error(platform::last_socket_error(), connecting);
}

void set(Error* out, Error value) noexcept {
    if (out != nullptr) {
        *out = value;
    }
}

int family_of(Family family) noexcept {
    return family == Family::IPv6 ? AF_INET6 : AF_INET;
}

platform::SockLength to_native(const Address& address, sockaddr_storage* out) noexcept {
    std::memset(out, 0, sizeof(*out));
    if (address.family == Family::IPv6) {
        auto* in6 = reinterpret_cast<sockaddr_in6*>(out);
        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons(address.port);
        std::memcpy(&in6->sin6_addr, address.bytes.data(), 16);
        return sizeof(sockaddr_in6);
    }
    auto* in4 = reinterpret_cast<sockaddr_in*>(out);
    in4->sin_family = AF_INET;
    in4->sin_port = htons(address.port);
    std::memcpy(&in4->sin_addr, address.bytes.data(), 4);
    return sizeof(sockaddr_in);
}

std::optional<Address> from_native(const sockaddr* address) noexcept {
    Address out;
    if (address->sa_family == AF_INET) {
        const auto* in4 = reinterpret_cast<const sockaddr_in*>(address);
        out.family = Family::IPv4;
        std::memcpy(out.bytes.data(), &in4->sin_addr, 4);
        out.port = ntohs(in4->sin_port);
        return out;
    }
    if (address->sa_family == AF_INET6) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(address);
        out.family = Family::IPv6;
        std::memcpy(out.bytes.data(), &in6->sin6_addr, 16);
        out.port = ntohs(in6->sin6_port);
        return out;
    }
    return std::nullopt;
}

Error option_int(std::intptr_t handle, int level, int name, int value) noexcept {
    if (handle == -1) {
        return Error::Invalid;
    }
    return platform::set_socket_option(native(handle), level, name, &value, sizeof(value)) ? Error::None : last_error();
}

std::optional<int> get_option_int(std::intptr_t handle, int level, int name) noexcept {
    if (handle == -1) {
        return std::nullopt;
    }
    int value = 0;
    platform::SockLength length = sizeof(value);
    if (getsockopt(native(handle), level, name, reinterpret_cast<char*>(&value), &length) != 0) {
        return std::nullopt;
    }
    return value;
}

} // namespace

Address Address::ipv4(uint32_t address, uint16_t port) noexcept {
    Address out;
    out.bytes[0] = static_cast<uint8_t>(address >> 24);
    out.bytes[1] = static_cast<uint8_t>(address >> 16);
    out.bytes[2] = static_cast<uint8_t>(address >> 8);
    out.bytes[3] = static_cast<uint8_t>(address);
    out.port = port;
    return out;
}

uint32_t Address::ipv4_value() const noexcept {
    return (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16) | (uint32_t(bytes[2]) << 8) | bytes[3];
}

std::optional<Address> parse_address(std::string_view text, uint16_t port) {
    if (!initialize()) {
        return std::nullopt;
    }
    const std::string copy{text};
    Address out;
    out.port = port;
    if (inet_pton(AF_INET, copy.c_str(), out.bytes.data()) == 1) {
        out.family = Family::IPv4;
        return out;
    }
    if (inet_pton(AF_INET6, copy.c_str(), out.bytes.data()) == 1) {
        out.family = Family::IPv6;
        return out;
    }
    return std::nullopt;
}

std::string format_address(const Address& address, bool withPort) {
    if (!initialize()) {
        return {};
    }
    char text[INET6_ADDRSTRLEN]{};
    inet_ntop(family_of(address.family), address.bytes.data(), text, sizeof(text));
    if (!withPort) {
        return text;
    }
    return address.family == Family::IPv6 ? "[" + std::string{text} + "]:" + std::to_string(address.port) :
                                            std::string{text} + ":" + std::to_string(address.port);
}

bool available() noexcept {
    return initialize();
}

std::vector<Address> resolve(std::string_view host, Family family, Error* error) {
    std::vector<Address> out;
    if (!initialize()) {
        set(error, Error::Unsupported);
        return out;
    }
    addrinfo hints{};
    hints.ai_family = family_of(family);
    addrinfo* list = nullptr;
    const std::string name{host};
    if (getaddrinfo(name.c_str(), nullptr, &hints, &list) != 0) {
        set(error, Error::Resolve);
        return out;
    }
    for (const addrinfo* entry = list; entry != nullptr; entry = entry->ai_next) {
        if (const auto address = from_native(entry->ai_addr)) {
            if (std::find(out.begin(), out.end(), *address) == out.end()) {
                out.push_back(*address);
            }
        }
    }
    freeaddrinfo(list);
    set(error, out.empty() ? Error::Resolve : Error::None);
    return out;
}

std::optional<Address> local_address(Family family) {
    // A datagram socket "connected" toward a public address takes the route's local address; nothing
    // is sent
    Socket probe = Socket::open(family, Type::Datagram);
    if (!probe.valid()) {
        return std::nullopt;
    }
    const auto target = family == Family::IPv6 ? parse_address("2001:4860:4860::8888", 53)
                                               : parse_address("8.8.8.8", 53);
    if (!target || probe.connect(*target) != Error::None) {
        return std::nullopt;
    }
    auto local = probe.local();
    if (local) {
        local->port = 0;
    }
    return local;
}

Socket::~Socket() {
    close();
}

Socket::Socket(Socket&& other) noexcept
    : m_handle(std::exchange(other.m_handle, -1)), m_family(other.m_family) {}

Socket& Socket::operator=(Socket&& other) noexcept {
    if (this != &other) {
        close();
        m_handle = std::exchange(other.m_handle, -1);
        m_family = other.m_family;
    }
    return *this;
}

Socket Socket::open(Family family, Type type, Error* error) {
    Socket out;
    if (!initialize()) {
        set(error, Error::Unsupported);
        return out;
    }
    const NativeSocket handle = ::socket(family_of(family), type == Type::Stream ? SOCK_STREAM : SOCK_DGRAM,
        type == Type::Stream ? IPPROTO_TCP : IPPROTO_UDP);
    if (handle == platform::InvalidSocket) {
        set(error, last_error());
        return out;
    }
    platform::configure_common_socket(handle);
    if (type == Type::Datagram) {
        platform::configure_datagram_socket(handle);
    }
    out.m_handle = static_cast<std::intptr_t>(handle);
    out.m_family = family;
    set(error, Error::None);
    return out;
}

bool Socket::valid() const noexcept {
    return m_handle != -1;
}

void Socket::close() noexcept {
    if (m_handle != -1) {
        platform::close_socket(native(m_handle));
        m_handle = -1;
    }
}

Error Socket::set_nonblocking(bool enabled) noexcept {
    if (m_handle == -1) {
        return Error::Invalid;
    }
    return platform::set_nonblocking_mode(native(m_handle), enabled) ? Error::None : last_error();
}

Error Socket::set_reuse_address(bool enabled) noexcept {
    return option_int(m_handle, SOL_SOCKET, SO_REUSEADDR, enabled ? 1 : 0);
}

Error Socket::set_broadcast(bool enabled) noexcept {
    return option_int(m_handle, SOL_SOCKET, SO_BROADCAST, enabled ? 1 : 0);
}

Error Socket::set_no_delay(bool enabled) noexcept {
    return option_int(m_handle, IPPROTO_TCP, TCP_NODELAY, enabled ? 1 : 0);
}

Error Socket::set_receive_buffer(int bytes) noexcept {
    return option_int(m_handle, SOL_SOCKET, SO_RCVBUF, bytes);
}

Error Socket::set_send_buffer(int bytes) noexcept {
    return option_int(m_handle, SOL_SOCKET, SO_SNDBUF, bytes);
}

std::optional<int> Socket::receive_buffer() const noexcept {
    return get_option_int(m_handle, SOL_SOCKET, SO_RCVBUF);
}

std::optional<int> Socket::send_buffer() const noexcept {
    return get_option_int(m_handle, SOL_SOCKET, SO_SNDBUF);
}

Error Socket::bind(const Address& address) noexcept {
    if (m_handle == -1) {
        return Error::Invalid;
    }
    sockaddr_storage storage;
    const auto length = to_native(address, &storage);
    return ::bind(native(m_handle), reinterpret_cast<const sockaddr*>(&storage), length) == 0 ? Error::None
                                                                                              : last_error();
}

Error Socket::listen(int backlog) noexcept {
    if (m_handle == -1) {
        return Error::Invalid;
    }
    return ::listen(native(m_handle), backlog) == 0 ? Error::None : last_error();
}

Socket Socket::accept(Address* peer, Error* error) noexcept {
    Socket out;
    if (m_handle == -1) {
        set(error, Error::Invalid);
        return out;
    }
    sockaddr_storage storage{};
    platform::SockLength length = sizeof(storage);
    const NativeSocket handle = ::accept(native(m_handle), reinterpret_cast<sockaddr*>(&storage), &length);
    if (handle == platform::InvalidSocket) {
        set(error, last_error());
        return out;
    }
    platform::configure_common_socket(handle);
    out.m_handle = static_cast<std::intptr_t>(handle);
    out.m_family = m_family;
    if (peer != nullptr) {
        if (const auto address = from_native(reinterpret_cast<const sockaddr*>(&storage))) {
            *peer = *address;
        }
    }
    set(error, Error::None);
    return out;
}

Error Socket::connect(const Address& address) noexcept {
    if (m_handle == -1) {
        return Error::Invalid;
    }
    sockaddr_storage storage;
    const auto length = to_native(address, &storage);
    platform::prepare_connect(native(m_handle), reinterpret_cast<const sockaddr*>(&storage));
    return ::connect(native(m_handle), reinterpret_cast<const sockaddr*>(&storage), length) == 0
               ? Error::None
               : last_error(true);
}

Error Socket::pending_error() const noexcept {
    if (m_handle == -1) {
        return Error::Invalid;
    }
    const int error = platform::socket_error(native(m_handle));
    return error == 0 ? Error::None : map_error(error);
}

Error Socket::shutdown_send() noexcept {
    if (m_handle == -1) {
        return Error::Invalid;
    }
    platform::shutdown_send(native(m_handle));
    return Error::None;
}

std::optional<Address> Socket::local() const noexcept {
    if (m_handle == -1) {
        return std::nullopt;
    }
    sockaddr_storage storage{};
    platform::SockLength length = sizeof(storage);
    if (getsockname(native(m_handle), reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
        return std::nullopt;
    }
    return from_native(reinterpret_cast<const sockaddr*>(&storage));
}

std::optional<Address> Socket::peer() const noexcept {
    if (m_handle == -1) {
        return std::nullopt;
    }
    sockaddr_storage storage{};
    platform::SockLength length = sizeof(storage);
    if (getpeername(native(m_handle), reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
        return std::nullopt;
    }
    return from_native(reinterpret_cast<const sockaddr*>(&storage));
}

std::ptrdiff_t Socket::send(std::span<const std::byte> data, Error* error) noexcept {
    if (m_handle == -1) {
        set(error, Error::Invalid);
        return -1;
    }
    const std::ptrdiff_t sent = platform::send_bytes(native(m_handle), data.data(), data.size());
    set(error, sent < 0 ? last_error() : Error::None);
    return sent;
}

std::ptrdiff_t Socket::receive(std::span<std::byte> data, Error* error, bool peek) noexcept {
    if (m_handle == -1) {
        set(error, Error::Invalid);
        return -1;
    }
    const std::ptrdiff_t received =
        peek ? ::recv(native(m_handle), reinterpret_cast<char*>(data.data()), static_cast<int>(data.size()), MSG_PEEK)
             : platform::receive_bytes(native(m_handle), data.data(), data.size());
    set(error, received < 0 ? last_error() : Error::None);
    return received;
}

std::ptrdiff_t Socket::send_to(std::span<const std::byte> data, const Address& to, Error* error) noexcept {
    if (m_handle == -1) {
        set(error, Error::Invalid);
        return -1;
    }
    sockaddr_storage storage;
    const auto length = to_native(to, &storage);
    const std::ptrdiff_t sent = platform::send_datagram(native(m_handle), data.data(), data.size(),
        reinterpret_cast<const sockaddr*>(&storage), length);
    set(error, sent < 0 ? last_error() : Error::None);
    return sent;
}

std::ptrdiff_t Socket::receive_from(std::span<std::byte> data, Address* from, Error* error, bool peek) noexcept {
    if (m_handle == -1) {
        set(error, Error::Invalid);
        return -1;
    }
    sockaddr_storage storage{};
    platform::SockLength length = sizeof(storage);
    const std::ptrdiff_t received =
        peek ? ::recvfrom(native(m_handle), reinterpret_cast<char*>(data.data()), static_cast<int>(data.size()),
                   MSG_PEEK, reinterpret_cast<sockaddr*>(&storage), &length)
             : platform::receive_datagram(native(m_handle), data.data(), data.size(),
                   reinterpret_cast<sockaddr*>(&storage), &length);
    if (received < 0) {
        set(error, last_error());
        return received;
    }
    if (from != nullptr) {
        if (const auto address = from_native(reinterpret_cast<const sockaddr*>(&storage))) {
            *from = *address;
        }
    }
    set(error, Error::None);
    return received;
}

std::optional<size_t> Socket::available_bytes() const noexcept {
    if (m_handle == -1) {
        return std::nullopt;
    }
    const long bytes = platform::readable_bytes(native(m_handle));
    return bytes < 0 ? std::nullopt : std::optional<size_t>(static_cast<size_t>(bytes));
}

std::string Socket::last_error_message() {
    return platform::socket_error_message(platform::last_socket_error());
}

int poll(std::span<PollEntry> entries, std::chrono::milliseconds timeout, Error* error) noexcept {
    // Only entries with a socket go to the platform (WSAPoll does not skip invalid descriptors)
    std::vector<platform::PollDescriptor> descriptors;
    std::vector<size_t> indices;
    int invalid = 0;
    for (size_t i = 0; i < entries.size(); i++) {
        entries[i].revents = 0;
        if (entries[i].socket == nullptr || entries[i].socket->m_handle == -1) {
            entries[i].revents = PollInvalid;
            invalid++;
            continue;
        }
        platform::PollDescriptor descriptor{};
        descriptor.fd = native(entries[i].socket->m_handle);
        descriptor.events = static_cast<short>(((entries[i].events & PollRead) ? POLLIN : 0) |
                                               ((entries[i].events & PollWrite) ? POLLOUT : 0));
        descriptors.push_back(descriptor);
        indices.push_back(i);
    }
    if (descriptors.empty()) {
        set(error, Error::None);
        return invalid;
    }
    const int ready = platform::poll(descriptors, invalid != 0 ? std::chrono::milliseconds(0) : timeout);
    if (ready < 0) {
        set(error, last_error());
        return -1;
    }
    for (size_t k = 0; k < descriptors.size(); k++) {
        const short r = descriptors[k].revents;
        entries[indices[k]].revents = ((r & POLLIN) ? PollRead : 0) | ((r & POLLOUT) ? PollWrite : 0) |
                                      ((r & POLLERR) ? PollError : 0) | ((r & POLLHUP) ? PollHangup : 0) |
                                      ((r & POLLNVAL) ? PollInvalid : 0);
    }
    set(error, Error::None);
    return ready + invalid;
}

} // namespace borealis::socket
