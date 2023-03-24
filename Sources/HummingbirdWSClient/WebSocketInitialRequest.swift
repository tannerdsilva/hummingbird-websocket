//===----------------------------------------------------------------------===//
//
// This source file is part of the Hummingbird server framework project
//
// Copyright (c) 2021-2021 the Hummingbird authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See hummingbird/CONTRIBUTORS.txt for the list of Hummingbird authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Hummingbird
import NIOCore
import NIOHTTP1
import struct Foundation.Data
import Crypto

/// The HTTP handler to be used to initiate the request.
/// This initial request will be adapted by the WebSocket upgrader to contain the upgrade header parameters.
/// Channel read will only be called if the upgrade fails.
final class WebSocketInitialRequestHandler: ChannelInboundHandler, RemovableChannelHandler {
	public typealias InboundIn = HTTPClientResponsePart
	public typealias OutboundOut = HTTPClientRequestPart

	let websocketKey:String
	
	let host: String
	let urlPath: String
	let headers: HTTPHeaders
	let upgradePromise: EventLoopPromise<Void>

	init(websocketKey:String, url: HBWebSocketClient.SplitURL, headers: HTTPHeaders = [:], upgradePromise: EventLoopPromise<Void>) throws {
		self.websocketKey = websocketKey
		self.host = url.hostHeader
		self.urlPath = url.pathQuery
		self.headers = headers
		self.upgradePromise = upgradePromise
	}

	public func channelActive(context: ChannelHandlerContext) {
		// We are connected. It's time to send the message to the server to initialize the upgrade dance.
		var headers = self.headers
		headers.add(name: "content-length", value: "0")
		headers.replaceOrAdd(name: "host", value: self.host)

		let requestHead = HTTPRequestHead(
			version: HTTPVersion(major: 1, minor: 1),
			method: .GET,
			uri: urlPath,
			headers: headers
		)

		context.write(self.wrapOutboundOut(.head(requestHead)), promise: nil)
		context.write(self.wrapOutboundOut(.body(.byteBuffer(ByteBuffer()))), promise: nil)
		context.writeAndFlush(self.wrapOutboundOut(.end(nil)), promise: nil)
	}

	private func createExpectedWebSocketAcceptHeader(fromKey key: String) -> String {
		let magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
		let acceptKey = key + magicGUID
		let acceptData = Data(acceptKey.utf8)
		let acceptHash = Insecure.SHA1.hash(data: acceptData)
	
		return acceptHash.withUnsafeBytes { (unsafeRawBufferPointer) -> String in
			let hashData = Data(unsafeRawBufferPointer)
			return hashData.base64EncodedString()
		}
	}

	public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
		let clientResponse = self.unwrapInboundIn(data)

		switch clientResponse {
		case .head(let responseHead):
			guard responseHead.status == .switchingProtocols else {
				print("WebSocket upgrade failed: invalid status code")
				self.upgradePromise.fail(HBWebSocketClient.Error.websocketUpgradeFailed)
				return
			}

			guard let upgradeHeader = responseHead.headers.first(name: "upgrade"),
				  upgradeHeader.lowercased() == "websocket" else {
				print("WebSocket upgrade failed: missing or invalid 'upgrade' header")
				self.upgradePromise.fail(HBWebSocketClient.Error.websocketUpgradeFailed)
				return
			}

			guard let connectionHeader = responseHead.headers.first(name: "connection"),
				  connectionHeader.lowercased() == "upgrade" else {
				print("WebSocket upgrade failed: missing or invalid 'connection' header")
				self.upgradePromise.fail(HBWebSocketClient.Error.websocketUpgradeFailed)
				return
			}

			guard let acceptHeader = responseHead.headers.first(name: "sec-websocket-accept") else {
				print("WebSocket upgrade failed: missing 'sec-websocket-accept' header")
				self.upgradePromise.fail(HBWebSocketClient.Error.websocketUpgradeFailed)
				return
			}

			let expectedAcceptHeader = createExpectedWebSocketAcceptHeader(fromKey: websocketKey)
			guard acceptHeader == expectedAcceptHeader else {
				print("WebSocket upgrade failed: invalid 'sec-websocket-accept' header")
				self.upgradePromise.fail(HBWebSocketClient.Error.websocketUpgradeFailed)
				return
			}

		case .body:
			break
		case .end:
			context.close(promise: nil)
		}
	}

	public func errorCaught(context: ChannelHandlerContext, error: Error) {
		self.upgradePromise.fail(error)
		// As we are not really interested getting notified on success or failure
		// we just pass nil as promise to reduce allocations.
		context.close(promise: nil)
	}
}
