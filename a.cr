require "socket"
require "openssl"

lib LibSSL
  fun ssl_get_peer_certificate = SSL_get_peer_certificate(handle : SSL) : LibCrypto::X509
end

class OpenSSL::SSL::Socket
  def peer_certificate : OpenSSL::X509::Certificate?
    cert = LibSSL.ssl_get_peer_certificate(@ssl)
    OpenSSL::X509::Certificate.new cert if cert
  end
end

module Gemini
  struct Request
    property uri : URI
    property addr : Socket::IPAddress
    property cert : OpenSSL::X509::Certificate?

    def initialize(uri, @addr, @cert)
      @uri = URI.parse uri
    end

    def cert_details
      if c = cert
        c.subject.to_a
      end
    end
  end

  struct Response
    property status : Int32
    property header : String
    property body : String

    def initialize(@status = 20, @header = "text/gemini", @body = "")
    end

    def to_s(io : IO)
      io << "#{status} #{header}\r\n#{body}"
    end
  end

  class Server
    Log = ::Log.for("Gemini Server")
    property port : Int32
    property context : OpenSSL::SSL::Context::Server

    def initialize(@port = 1965)
      @context = create_tls_context
    end

    private def create_tls_context
      ctx = OpenSSL::SSL::Context::Server.new
      # openssl req -newkey rsa:2048 -nodes -keyout localhost.key -nodes -x509 -out localhost.crt -subj "/CN=localhost"
      prefix = "ed"
      ctx.private_key = "#{prefix}.key"
      ctx.certificate_chain = "#{prefix}.crt"
      ctx.verify_mode = OpenSSL::SSL::VerifyMode::PEER
      LibSSL.ssl_ctx_set_cert_verify_callback(ctx.to_unsafe, ->(x509_ctx, arg) { 1 }, nil)
      ctx
    end

    def start
      socket = TCPServer.new port
      Log.info { "started on port #{port}" }
      while client = socket.accept?
        spawn handle_client(client)
      end
    end

    def handle_client(client)
      soc = OpenSSL::SSL::Socket::Server.new(client, context)
      req = Request.new(
        uri: soc.gets.not_nil!,
        addr: soc.remote_address.not_nil!.as(Socket::IPAddress),
        cert: soc.peer_certificate
      )

      resp = respond(req)

      soc << resp
      soc.close
    end

    def respond(request)
      req = request
      Response.new body: <<-GMI
        # hello world

        ## yes hello

        => hi ok

        you requested: #{req.uri}
        from: #{req.addr}
        cert details:#{req.cert_details}"
      GMI
    end
  end
end

Gemini::Server.new.start
