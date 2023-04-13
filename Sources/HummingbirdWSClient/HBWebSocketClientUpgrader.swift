import ExtrasBase64
import Hummingbird
import HummingbirdWSCore
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOWebSocket
import Crypto
import struct Foundation.Data

public final class HBWebSocketClientUpgrader: NIOHTTPClientProtocolUpgrader {
    
    /// RFC 6455 specs this as the required entry in the Upgrade header.
    public let supportedProtocol: String = "websocket"
    /// None of the websocket headers are actually defined as 'required'.
    public let requiredUpgradeHeaders: [String] = []

    private let host:String
    private let requestKey: String
    private let maxFrameSize: Int
    private let automaticErrorHandling: Bool
    private let upgradePipelineHandler: (Channel, HTTPResponseHead) -> EventLoopFuture<Void>

    /// - Parameters:
    ///   - requestKey: sent to the server in the `Sec-WebSocket-Key` HTTP header. Default is random request key.
    ///   - maxFrameSize: largest incoming `WebSocketFrame` size in bytes. Default is 16,384 bytes.
    ///   - automaticErrorHandling: If true, adds `WebSocketProtocolErrorHandler` to the channel pipeline to catch and respond to WebSocket protocol errors. Default is true.
    ///   - upgradePipelineHandler: called once the upgrade was successful
    public init(
        host: String,
        requestKey: String,
        maxFrameSize: Int = 1 << 20,
        automaticErrorHandling: Bool = true,
        upgradePipelineHandler: @escaping (Channel, HTTPResponseHead) -> EventLoopFuture<Void>
    ) {
        precondition(requestKey != "", "The request key must contain a valid Sec-WebSocket-Key")
        precondition(maxFrameSize <= UInt32.max, "invalid overlarge max frame size")
        self.host = host
        self.requestKey = requestKey
        self.upgradePipelineHandler = upgradePipelineHandler
        self.maxFrameSize = maxFrameSize
        self.automaticErrorHandling = automaticErrorHandling
    }

    /// Add additional headers that are needed for a WebSocket upgrade request.
    public func addCustom(upgradeRequestHeaders: inout HTTPHeaders) {
        upgradeRequestHeaders.replaceOrAdd(name: "Sec-WebSocket-Key", value: self.requestKey)
        upgradeRequestHeaders.replaceOrAdd(name: "Sec-WebSocket-Version", value: "13")
        upgradeRequestHeaders.replaceOrAdd(name: "Connection", value: "Upgrade")
        upgradeRequestHeaders.replaceOrAdd(name: "Upgrade", value: "websocket")
        upgradeRequestHeaders.replaceOrAdd(name: "Host", value: self.host)
    }

    /// Allow or deny the upgrade based on the upgrade HTTP response
    /// headers containing the correct accept key.
    public func shouldAllowUpgrade(upgradeResponse: HTTPResponseHead) -> Bool {
        
        let acceptValueHeader = upgradeResponse.headers["Sec-WebSocket-Accept"]

        guard acceptValueHeader.count == 1 else {
            return false
        }

        // Validate the response key in 'Sec-WebSocket-Accept'.
        let magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
		let acceptKey = requestKey + magicGUID
		let acceptData = Data(acceptKey.utf8)
		let acceptHash = Insecure.SHA1.hash(data: acceptData)
		let computed = acceptHash.withUnsafeBytes { (unsafeRawBufferPointer) -> String in
			let hashData = Data(unsafeRawBufferPointer)
			return hashData.base64EncodedString()
		}

        return acceptValueHeader[0] == computed
    }

    /// Called when the upgrade response has been flushed and it is safe to mutate the channel
    /// pipeline. Adds channel handlers for websocket frame encoding, decoding and errors.
    public func upgrade(context: ChannelHandlerContext, upgradeResponse: HTTPResponseHead) -> EventLoopFuture<Void> {

        var upgradeFuture = context.pipeline.addHandler(WebSocketFrameEncoder()).flatMap {
            context.pipeline.addHandler(ByteToMessageHandler(WebSocketFrameDecoder(maxFrameSize: self.maxFrameSize)))
        }
        
        if self.automaticErrorHandling {
            upgradeFuture = upgradeFuture.flatMap {
                context.pipeline.addHandler(WebSocketProtocolErrorHandler())
            }
        }
        
        return upgradeFuture.flatMap {
            self.upgradePipelineHandler(context.channel, upgradeResponse)
        }
    }
}