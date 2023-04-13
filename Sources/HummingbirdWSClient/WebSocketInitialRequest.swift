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
import HummingbirdWSCore

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
	let eventLoop:EventLoop
	let upgradePromise: EventLoopPromise<Void>
	let configuration: HBWebSocketClient.Configuration
	let wsPromise: EventLoopPromise<HBWebSocket>

	init(websocketKey:String, url:HBWebSocketClient.SplitURL, headers:HTTPHeaders = [:], upgradePromise:EventLoopPromise<Void>, configuration:HBWebSocketClient.Configuration, eventLoop:EventLoop, wsPromise:EventLoopPromise<HBWebSocket>) throws {
		self.websocketKey = websocketKey
		self.host = url.hostHeader
		self.urlPath = url.pathQuery
		self.headers = headers
		self.upgradePromise = upgradePromise
		self.configuration = configuration
		self.eventLoop = eventLoop
		self.wsPromise = wsPromise
	}

	public func channelActive(context: ChannelHandlerContext) {
		// We are connected. It's time to send the message to the server to initialize the upgrade dance.
		var headers = self.headers
		headers.replaceOrAdd(name: "Sec-WebSocket-Key", value: websocketKey)
		headers.replaceOrAdd(name: "Sec-WebSocket-Version", value: "13")
		headers.replaceOrAdd(name:"Content-Length", value:"0")
		headers.replaceOrAdd(name:"Host", value:self.host)
		headers.replaceOrAdd(name:"Upgrade", value:"websocket")
		headers.replaceOrAdd(name: "Connection", value: "Upgrade")

		headers.add(name: "Origin", value: "https://tannersilva.com")

		let requestHead = HTTPRequestHead(
			version:HTTPVersion(major:1, minor:1),
			method:.GET,
			uri:urlPath,
			headers:headers
		)
		print("sending WebSocket headers to \(urlPath))")
		context.write(self.wrapOutboundOut(.head(requestHead)), promise: nil)
		context.write(self.wrapOutboundOut(.body(.byteBuffer(ByteBuffer(bytes:[])))), promise: nil)
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
			if responseHead.status == .movedPermanently, let location = responseHead.headers.first(name: "location") {
				let newURL = HBURL(location)
				print("WebSocket upgrade failed: redirect to \(newURL)")
				/*if self.configuration.redirectCount > 0 {
					 HBWebSocketClient.connect(url: newURL, configuration: self.configuration.withDecrementedRedirectCount(), on: self.eventLoop).whenComplete({
						switch $0 {
						case .success(let ws):
							self.wsPromise.succeed(ws)
							self.upgradePromise.succeed(())
						case .failure(let error):
							self.wsPromise.fail(error)
							self.upgradePromise.fail(error)
						}
					})
				} else {
					print("WebSocket upgrade failed after redirect: too many redirects")
					self.wsPromise.fail(HBWebSocketClient.Error.tooManyRedirects)
					self.upgradePromise.fail(HBWebSocketClient.Error.tooManyRedirects)
				}*/
				return
			} else {
				// in this branch of logic, the promises are handled upstream in a successful case
				// in a failure case, the upgrade promise is handled, as it should be configured to cascade to the ws promise
				guard responseHead.status == .switchingProtocols else {
					print("WebSocket upgrade failed: invalid response status \(responseHead.status)")
					self.upgradePromise.fail(HBWebSocketClient.Error.invalidHTTPUpgradeResponse(responseHead))
					return
				}
				guard let upgradeHeader = responseHead.headers.first(name:"upgrade"),
					upgradeHeader.lowercased() == "websocket" else {
					print("WebSocket upgrade failed: missing or invalid 'upgrade' header")
					self.upgradePromise.fail(HBWebSocketClient.Error.invalidOrMissingHTTPUpgradeHeader)
					return
				}
				guard let connectionHeader = responseHead.headers.first(name:"connection"),
					connectionHeader.lowercased() == "upgrade" else {
					print("WebSocket upgrade failed: missing or invalid 'connection' header")
					self.upgradePromise.fail(HBWebSocketClient.Error.invalidOrMissingHTTPConnectionHeader)
					return
				}
				guard let acceptHeader = responseHead.headers.first(name:"sec-websocket-accept") else {
					print("WebSocket upgrade failed: missing 'sec-websocket-accept' header")
					self.upgradePromise.fail(HBWebSocketClient.Error.missingSecWebSocketAcceptHeader)
					return
				}
				let expectedAcceptHeader = createExpectedWebSocketAcceptHeader(fromKey:websocketKey)
				guard acceptHeader == expectedAcceptHeader else {
					print("WebSocket upgrade failed: invalid 'sec-websocket-accept' header")
					self.upgradePromise.fail(HBWebSocketClient.Error.invalidSecWebSocketAcceptHeader)
					return
				}
			}
		case .body(bodyStream: var bodyStream):
			let myBytes = bodyStream.readBytes(length:bodyStream.readableBytes)
			let asString = String(bytes:myBytes!, encoding:.utf8)
			print("WebSocket upgrade for \(self.host) failed: response was: \(asString!)")
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
