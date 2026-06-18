#include "UrlRequest_Base.h"

#include <curl/curl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <array>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <cassert>
#include <optional>
#include <sstream>

namespace
{
    void curl_check(CURLcode code)
    {
        if (code != CURLE_OK)
        {
            throw std::runtime_error{(std::stringstream{} << "CURL call failed with code (" << code << ")").str()};
        }
    }

    // Stable symbolic names for the CURLcodes most likely to be diagnostic in the field.
    // Restricted to constants that have existed in libcurl for a long time so this compiles
    // against older system curl headers; anything else gets a synthesized "CURLE_<n>" token.
    std::string curl_error_symbol(CURLcode code)
    {
        switch (code)
        {
            case CURLE_UNSUPPORTED_PROTOCOL: return "CURLE_UNSUPPORTED_PROTOCOL";
            case CURLE_URL_MALFORMAT: return "CURLE_URL_MALFORMAT";
            case CURLE_COULDNT_RESOLVE_PROXY: return "CURLE_COULDNT_RESOLVE_PROXY";
            case CURLE_COULDNT_RESOLVE_HOST: return "CURLE_COULDNT_RESOLVE_HOST";
            case CURLE_COULDNT_CONNECT: return "CURLE_COULDNT_CONNECT";
            case CURLE_REMOTE_ACCESS_DENIED: return "CURLE_REMOTE_ACCESS_DENIED";
            case CURLE_PARTIAL_FILE: return "CURLE_PARTIAL_FILE";
            case CURLE_HTTP_RETURNED_ERROR: return "CURLE_HTTP_RETURNED_ERROR";
            case CURLE_WRITE_ERROR: return "CURLE_WRITE_ERROR";
            case CURLE_UPLOAD_FAILED: return "CURLE_UPLOAD_FAILED";
            case CURLE_READ_ERROR: return "CURLE_READ_ERROR";
            case CURLE_OUT_OF_MEMORY: return "CURLE_OUT_OF_MEMORY";
            case CURLE_OPERATION_TIMEDOUT: return "CURLE_OPERATION_TIMEDOUT";
            case CURLE_RANGE_ERROR: return "CURLE_RANGE_ERROR";
            case CURLE_HTTP_POST_ERROR: return "CURLE_HTTP_POST_ERROR";
            case CURLE_SSL_CONNECT_ERROR: return "CURLE_SSL_CONNECT_ERROR";
            case CURLE_BAD_DOWNLOAD_RESUME: return "CURLE_BAD_DOWNLOAD_RESUME";
            case CURLE_FILE_COULDNT_READ_FILE: return "CURLE_FILE_COULDNT_READ_FILE";
            case CURLE_TOO_MANY_REDIRECTS: return "CURLE_TOO_MANY_REDIRECTS";
            case CURLE_GOT_NOTHING: return "CURLE_GOT_NOTHING";
            case CURLE_SEND_ERROR: return "CURLE_SEND_ERROR";
            case CURLE_RECV_ERROR: return "CURLE_RECV_ERROR";
            case CURLE_SSL_CERTPROBLEM: return "CURLE_SSL_CERTPROBLEM";
            case CURLE_SSL_CIPHER: return "CURLE_SSL_CIPHER";
            case CURLE_PEER_FAILED_VERIFICATION: return "CURLE_PEER_FAILED_VERIFICATION";
            case CURLE_BAD_CONTENT_ENCODING: return "CURLE_BAD_CONTENT_ENCODING";
            case CURLE_SSL_CACERT_BADFILE: return "CURLE_SSL_CACERT_BADFILE";
            case CURLE_REMOTE_FILE_NOT_FOUND: return "CURLE_REMOTE_FILE_NOT_FOUND";
            case CURLE_ABORTED_BY_CALLBACK: return "CURLE_ABORTED_BY_CALLBACK";
            default: return "CURLE_" + std::to_string(static_cast<int>(code));
        }
    }

    void curl_check(CURLUcode code)
    {
        if (code != CURLUE_OK)
        {
            throw std::runtime_error{(std::stringstream{} << "CURLU call failed with code (" << code << ")").str()};
        }
    }
}

namespace UrlLib
{
    class UrlRequest::Impl : public ImplBase
    {
    public:
        ~Impl()
        {
            Cleanup();
        }

        void Open(UrlMethod method, const std::string& url)
        {
            Cleanup();

            ResetForOpen();
            m_responseBuffer.clear();

            m_method = method;

            if (m_method == UrlMethod::Post)
            {
                // TODO: Implement POST
                throw std::runtime_error{"Not implemented"};
            }

            m_curl = curl_easy_init();
            if (m_curl)
            {
                m_curlu = curl_url();
                if (!m_curlu)
                {
                    throw std::runtime_error{"Out of memory"};
                }

                CURLUcode rc = curl_url_set(m_curlu, CURLUPART_URL, url.data(), CURLU_URLENCODE | CURLU_NON_SUPPORT_SCHEME | CURLU_ALLOW_SPACE);
                if (rc != CURLUE_OK)
                {
                    throw std::runtime_error{"Unable to build URL"};
                }

                char* scheme{};
                auto schemeScope = gsl::finally([&scheme] { curl_free(scheme); });
                if (curl_url_get(m_curlu, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK)
                {
                    if (std::strcmp(scheme, "app") == 0)
                    {
                        curl_check(curl_url_set(m_curlu, CURLUPART_SCHEME, "file", 0));

                        char exe[1024];
                        int ret = readlink("/proc/self/exe", exe, std::size(exe) - 1);
                        if (ret == -1)
                        {
                            throw std::runtime_error{"Unable to get executable location"};
                        }
                        exe[ret] = 0;

                        char* host{};
                        auto hostScope = gsl::finally([&host] { curl_free(host); });
                        curl_check(curl_url_get(m_curlu, CURLUPART_HOST, &host, 0));

                        char* path{};
                        auto pathScope = gsl::finally([&path] { curl_free(path); });
                        curl_check(curl_url_get(m_curlu, CURLUPART_PATH, &path, 0));

                        auto newPath = std::filesystem::path{exe}.parent_path() / host / (path + 1);
                        curl_check(curl_url_set(m_curlu, CURLUPART_PATH, reinterpret_cast<const char*>(newPath.generic_u8string().data()), 0));

                        m_file = true;
                    }
                    else if (std::strcmp(scheme, "file") == 0)
                    {
                        m_file = true;
                    }
                }

                curl_check(curl_easy_setopt(m_curl, CURLOPT_CURLU, m_curlu));
                curl_check(curl_easy_setopt(m_curl, CURLOPT_HEADERDATA, this));
                curl_check(curl_easy_setopt(m_curl, CURLOPT_HEADERFUNCTION, HeaderCallback));
                curl_check(curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1L));
                // Request-specific failure detail (host/port/path specifics) lands here during
                // curl_easy_perform; see the error handling in PerformAsync.
                curl_check(curl_easy_setopt(m_curl, CURLOPT_ERRORBUFFER, m_curlErrorBuffer.data()));

                // Observe Abort(): curl_easy_perform runs synchronously on a worker thread and does
                // not watch m_cancellationSource on its own. Two cooperating mechanisms cancel it:
                //
                // 1. A progress callback that returns non-zero once cancelled, making
                //    curl_easy_perform return CURLE_ABORTED_BY_CALLBACK. libcurl invokes it during
                //    DNS/connect and whenever it services socket activity, so this alone aborts a
                //    request that is actively transferring or still connecting.
                // 2. Socket interruption: while waiting for a response from a connected-but-idle peer
                //    (no bytes flowing), libcurl's internal poll can block without ticking the
                //    progress callback, so the open-socket callback records the transfer socket and
                //    the cancellation listener shutdown()s it. That wakes the poll; libcurl then
                //    services the socket, runs the progress callback, and returns
                //    CURLE_ABORTED_BY_CALLBACK. cancelled() and the socket handle are atomics, safe to
                //    touch from the aborting thread while perform() runs on the worker.
                curl_check(curl_easy_setopt(m_curl, CURLOPT_NOPROGRESS, 0L));
                curl_check(curl_easy_setopt(m_curl, CURLOPT_XFERINFODATA, &m_cancellationSource));
                curl_check(curl_easy_setopt(m_curl, CURLOPT_XFERINFOFUNCTION,
                    +[](void* clientp, curl_off_t, curl_off_t, curl_off_t, curl_off_t) -> int {
                        return static_cast<const arcana::cancellation_source*>(clientp)->cancelled() ? 1 : 0;
                    }));
                curl_check(curl_easy_setopt(m_curl, CURLOPT_OPENSOCKETDATA, this));
                curl_check(curl_easy_setopt(m_curl, CURLOPT_OPENSOCKETFUNCTION, &OpenSocketCallback));
                curl_check(curl_easy_setopt(m_curl, CURLOPT_CLOSESOCKETDATA, this));
                curl_check(curl_easy_setopt(m_curl, CURLOPT_CLOSESOCKETFUNCTION, &CloseSocketCallback));
            }
        }

        arcana::task<void, std::exception_ptr> SendAsync()
        {
            switch (m_responseType)
            {
                case UrlResponseType::String:
                {
                    return PerformAsync(m_responseString);
                }
                case UrlResponseType::Buffer:
                {
                    return PerformAsync(m_responseBuffer);
                }
            }

            throw std::runtime_error{"Invalid response type"};
        }

        gsl::span<const std::byte> ResponseBuffer() const
        {
            return m_responseBuffer;
        }

    private:
        void Cleanup()
        {
            if (m_thread.has_value())
            {
                // Backstop so destruction never deadlocks on join(): if the worker is still blocked
                // in curl_easy_perform against a hung peer and Abort() was not called explicitly,
                // interrupt the transfer socket so perform() returns.
                const curl_socket_t socket = m_socket.load();
                if (socket != CURL_SOCKET_BAD)
                {
                    ::shutdown(socket, SHUT_RDWR);
                }
                m_thread->join();
                m_thread = {};
            }

            // The listener captures `this` and reads m_socket; drop it before those are gone.
            m_cancellationTicket.reset();

            if (m_curlu)
            {
                curl_url_cleanup(m_curlu);
                m_curlu = nullptr;
            }

            if (m_curl)
            {
                curl_easy_cleanup(m_curl);
                m_curl = nullptr;
            }
        }

        // Records the transfer socket so Abort() can interrupt a blocking poll. libcurl invokes this
        // on the worker thread to create the socket; the default behavior is replicated and the
        // handle stored atomically.
        static curl_socket_t OpenSocketCallback(void* clientp, curlsocktype /*purpose*/, struct curl_sockaddr* address)
        {
            auto* self = static_cast<Impl*>(clientp);
            const curl_socket_t socket = ::socket(address->family, address->socktype, address->protocol);
            self->m_socket.store(socket); // CURL_SOCKET_BAD on failure, which curl treats as an error
            return socket;
        }

        // Clears the recorded handle when libcurl closes that socket, so a later Abort() cannot
        // shutdown() a descriptor the OS has since reused for another connection.
        static int CloseSocketCallback(void* clientp, curl_socket_t item)
        {
            auto* self = static_cast<Impl*>(clientp);
            curl_socket_t expected = item;
            self->m_socket.compare_exchange_strong(expected, CURL_SOCKET_BAD);
            return ::close(item);
        }


        static void Append(std::string& string, char* buffer, size_t nitems)
        {
            string.insert(string.end(), buffer, buffer + nitems);
        }

        static void Append(std::vector<std::byte>& byteVector, char* buffer, size_t nitems)
        {
            auto bytes = reinterpret_cast<std::byte*>(buffer);
            byteVector.insert(byteVector.end(), bytes, bytes + nitems);   
        }

        template<typename DataT>
        arcana::task<void, std::exception_ptr> PerformAsync(DataT& data)
        {
            data.clear();

            curl_write_callback callback = [](char* buffer, size_t /*size*/, size_t nitems, void* userData) {
                auto& data = *static_cast<DataT*>(userData);
                Append(data, buffer, nitems);
                return nitems;
            };

            curl_check(curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, callback));
            curl_check(curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &data));

            arcana::task_completion_source<void, std::exception_ptr> taskCompletionSource{};

            // Wire Abort() to interrupt this request: if the worker is blocked waiting on an idle
            // socket, shutdown() wakes it so the progress callback can return the abort. The socket
            // is recorded by OpenSocketCallback during curl_easy_perform; emplace() resets any prior
            // send's listener (and fires synchronously if the request was already aborted, where the
            // socket is still CURL_SOCKET_BAD and the shutdown is skipped).
            m_socket.store(CURL_SOCKET_BAD);
            m_cancellationTicket.emplace(m_cancellationSource.add_listener([this]() {
                const curl_socket_t socket = m_socket.load();
                if (socket != CURL_SOCKET_BAD)
                {
                    ::shutdown(socket, SHUT_RDWR);
                }
            }));

            m_thread.emplace([this, taskCompletionSource]() mutable
            {
                m_curlErrorBuffer[0] = '\0';
                const CURLcode performResult = curl_easy_perform(m_curl);
                if (performResult != CURLE_OK)
                {
                    // Retain the default status code of 0 to indicate a client side error,
                    // matching the convention of UrlRequest_UWP.cpp's catch(winrt::hresult_error)
                    // and UrlRequest_Apple.mm's error branch -- but record what actually went
                    // wrong so consumers can surface it. Prefer libcurl's per-request
                    // CURLOPT_ERRORBUFFER detail (it includes host/port/path specifics, e.g.
                    // "Failed to connect to 127.0.0.1 port 47651 ...") over the generic
                    // curl_easy_strerror text.
                    const char* detail = m_curlErrorBuffer[0] != '\0' ? m_curlErrorBuffer.data() : curl_easy_strerror(performResult);
                    SetError("curl", curl_error_symbol(performResult), static_cast<int32_t>(performResult), detail);
                }
                else
                {
                    try
                    {
                        long codep{};
                        curl_check(curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &codep));
                        if (codep == 0 && m_file)
                        {
                            // File scheme always returns 0
                            m_statusCode = UrlStatusCode::Ok;
                        }
                        else
                        {
                            m_statusCode = static_cast<UrlStatusCode>(codep);
                        }
                    }
                    catch (const std::exception& e)
                    {
                        // Keep status 0 and record why. Without this catch the exception would
                        // escape this std::thread and call std::terminate. "GetInfoFailed" is not
                        // a real CURLcode, so it deliberately omits the "CURLE_" prefix to avoid
                        // implying libcurl produced this code.
                        SetError("curl", "GetInfoFailed", -1, e.what());
                    }
                }

                taskCompletionSource.complete();
            });

            return taskCompletionSource.as_task();
        }

        static size_t HeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata)
        {
            // libcurl passes the header bytes as `size` chunks of `nitems`; the valid length is
            // their product. (curl currently always uses size == 1 for headers, but don't rely on it.)
            const size_t length = size * nitems;
            if (length > 0)
            {
                char* bufferEnd = buffer + length;

                // Status line: "HTTP/<version> <code>[ <reason>]\r\n". HTTP/1.x carries a reason
                // phrase; HTTP/2+ omits it. curl delivers a fresh status line for every response
                // in the chain (e.g. each redirect hop), so reset and let the final one win.
                if (length >= 5 && std::strncmp(buffer, "HTTP/", 5) == 0)
                {
                    auto& impl = *static_cast<Impl*>(userdata);
                    impl.m_statusText.clear();

                    // Skip "HTTP/<version>" then the spaces and the numeric status code.
                    char* cursor = buffer;
                    for (; cursor < bufferEnd && *cursor != ' '; ++cursor) {}      // end of version token
                    for (; cursor < bufferEnd && *cursor == ' '; ++cursor) {}      // spaces before code
                    for (; cursor < bufferEnd && *cursor != ' '; ++cursor) {}      // status code digits
                    for (; cursor < bufferEnd && *cursor == ' '; ++cursor) {}      // spaces before reason

                    char* reasonEnd = bufferEnd;
                    for (; reasonEnd - 1 >= cursor; --reasonEnd)
                    {
                        auto ch = *(reasonEnd - 1);
                        if (ch != '\r' && ch != '\n' && ch != ' ')
                        {
                            break;
                        }
                    }

                    if (cursor < reasonEnd)
                    {
                        impl.m_statusText.assign(cursor, reasonEnd);
                    }

                    return nitems * size;
                }

                char* keyStart = buffer;
                char* keyEnd = keyStart;
                for (; keyEnd < bufferEnd; ++keyEnd)
                {
                    if (*keyEnd == ':')
                    {
                        break;
                    }
                }

                if (keyEnd != bufferEnd)
                {
                    char* valueStart = keyEnd + 1;
                    for (; valueStart < bufferEnd; ++valueStart)
                    {
                        if (*valueStart != ' ')
                        {
                            break;
                        }
                    }

                    char* valueEnd = bufferEnd;
                    for (; valueEnd - 1 >= valueStart; --valueEnd)
                    {
                        auto ch = *(valueEnd - 1);
                        if (ch != '\r' && ch != '\n' && ch != ' ')
                        {
                            break;
                        }
                    }

                    std::string key{keyStart, keyEnd};
                    std::string value{valueStart, valueEnd};
                    static_cast<Impl*>(userdata)->m_headers.insert({std::move(key), std::move(value)});
                }
            }

            return nitems * size;
        }

        std::vector<std::byte> m_responseBuffer{};
        CURL* m_curl{};
        CURLU* m_curlu{};
        bool m_file{};
        std::array<char, CURL_ERROR_SIZE> m_curlErrorBuffer{};
        // The active transfer socket (recorded by OpenSocketCallback), so Abort() can shutdown() it
        // to interrupt a blocking poll. Atomic: written on the worker thread, read on the aborting
        // thread. Declared before m_cancellationTicket so it outlives the listener that reads it.
        std::atomic<curl_socket_t> m_socket{CURL_SOCKET_BAD};
        std::optional<arcana::cancellation::ticket> m_cancellationTicket{};
        std::optional<std::thread> m_thread{};
    };
}

#include "UrlRequest_Shared.h"
