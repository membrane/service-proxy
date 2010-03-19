/* Copyright 2009 predic8 GmbH, www.predic8.com

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License. */

package com.predic8.membrane.core.http;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.predic8.membrane.core.Constants;
import com.predic8.membrane.core.util.ByteUtil;
import com.predic8.membrane.core.util.HttpUtil;

public class Body {

	private Log log = LogFactory.getLog(Body.class.getName());

	boolean read;

	private boolean chunked;

	private List<Chunk> chunks = new ArrayList<Chunk>();

	private InputStream inputStream;

	private int length;

	protected Body() {

	}

	public Body(String body) {
		chunks.add(new Chunk(body));
		read = true; // because we do not have something to read
		length = body.length();
	}

	public Body(InputStream in, int length, boolean chunked) throws IOException {
		this.inputStream = in;
		this.length = length;
		this.chunked = chunked;
	}

	public Body(InputStream in, boolean chunked) {
		log.debug("Body(Stream in, boolean chunked) " + chunked);
		this.chunked = chunked;
		this.inputStream = in;
	}

	public void read() throws IOException {
		if (read)
			return;

		chunks.clear();

		if (!chunked) {
			chunks.add(new Chunk(ByteUtil.readByteArray(inputStream, length)));
			read = true;
			return;
		}
		chunks.addAll(HttpUtil.readChunks(inputStream));
		read = true;

	}

	public byte[] getContent() throws IOException {
		read();
		byte[] content = new byte[getLength()];
		int destPos = 0;
		for (Chunk chunk : chunks) {
			destPos = chunk.copyChunk(content, destPos);
		}
		return content;
	}

	public InputStream getBodyAsStream() throws IOException {
		return new ByteArrayInputStream(getContent());
	}

	/**
	 * the caller of this method is responsible to adjust the header accordingly
	 * e.g. the fields Transfer-Encoding and Content-Length Therefore this
	 * method has access modifier default
	 * 
	 * @param bytes
	 */
	void setContent(byte[] bytes) {
		chunks.clear();
		chunks.add(new Chunk(bytes));
		chunked = false;
		read = true;
	}

	public void write(OutputStream out) throws IOException {
		if (!read) {
			writeNotRead(out);
			return;
		}

		writeAlreadyRead(out);
	}

	private void writeAlreadyRead(OutputStream out) throws IOException {
		if (getLength() == 0)
			return;

		if (!chunked) {
			out.write(getContent(), 0, getLength());
			out.flush();
			return;
		}

		for (Chunk chunk : chunks) {
			chunk.write(out);
		}
		out.write("0".getBytes());
		out.write(Constants.CRLF.getBytes());
		out.write(Constants.CRLF.getBytes());
	}

	private void writeNotRead(OutputStream out) throws IOException {
		if (chunked) {
			writeNotReadChunked(out);
		} else {
			writeNotReadUnchunked(out);
		}
		read = true;
	}

	private void writeNotReadUnchunked(OutputStream out) throws IOException {
		byte[] buffer = new byte[8192];

		int totalLength = 0;
		int length = 0;
		chunks.clear();
		while ((this.length > totalLength || this.length == -1) && (length = inputStream.read(buffer)) > 0) {
			totalLength += length;
			out.write(buffer, 0, length);
			out.flush();
			byte[] chunk = new byte[length];
			System.arraycopy(buffer, 0, chunk, 0, length);
			chunks.add(new Chunk(chunk));
		}
	}

	private void writeNotReadChunked(OutputStream out) throws IOException {
		log.debug("writeNotReadChunked");
		int chunkSize;
		while ((chunkSize = HttpUtil.readChunkSize(inputStream)) > 0) {
			writeChunkSize(out, chunkSize);
			byte[] chunk = ByteUtil.readByteArray(inputStream, chunkSize);
			out.write(chunk);
			chunks.add(new Chunk(chunk));
			out.write(Constants.CRLF_BYTES);
			inputStream.read(); // CR
			inputStream.read(); // LF
			out.flush();
		}
		inputStream.read(); // CR
		inputStream.read(); // LF-
		writeLastChunk(out);
		out.flush();
	}

	private void writeLastChunk(OutputStream out) throws IOException {
		out.write("0".getBytes());
		out.write(Constants.CRLF_BYTES);
		out.write(Constants.CRLF_BYTES);
	}

	private void writeChunkSize(OutputStream out, int chunkSize) throws IOException {
		out.write(Integer.toHexString(chunkSize).getBytes());
		out.write(Constants.CRLF_BYTES);
	}

	public int getLength() throws IOException {
		read();

		int length = 0;
		for (Chunk chunk : chunks) {
			length += chunk.getLength();
		}
		return length;
	}

	private int getRawLength() throws IOException {
		if (chunks.size() == 0)
			return 0;
		int length = getLength();
		for (Chunk chunk : chunks) {
			length += Long.toHexString(chunk.getLength()).getBytes().length;
			length += 2 * Constants.CRLF_BYTES.length;
		}
		length += "0".getBytes().length;
		length += 2 * Constants.CRLF_BYTES.length;
		return length;
	}

	public byte[] getRaw() throws IOException {
		read();
		
		if (chunked) {
			byte[] raw = new byte[getRawLength()];
			int destPos = 0;
			for (Chunk chunk : chunks) {

				destPos = chunk.copyChunkLength(raw, destPos, this);

				destPos = copyCRLF(raw, destPos);

				destPos = chunk.copyChunk(raw, destPos);

				destPos = copyCRLF(raw, destPos);

			}

			destPos = copyLastChunk(raw, destPos);

			destPos = copyCRLF(raw, destPos);
			return raw;
		}
		if (chunks.isEmpty()) {
			log.debug("size of chunks list: " + chunks.size() + "  " + hashCode());
			log.debug("chunks size is: " + chunks.size() + " at time: " + System.currentTimeMillis());
			return new byte[0];
		}

		return getContent();
	}

	private int copyLastChunk(byte[] raw, int destPos) {
		System.arraycopy("0".getBytes(), 0, raw, destPos, "0".getBytes().length);
		destPos += "0".getBytes().length;
		destPos = copyCRLF(raw, destPos);
		return destPos;
	}

	private int copyCRLF(byte[] raw, int destPos) {
		System.arraycopy(Constants.CRLF_BYTES, 0, raw, destPos, 2);
		return destPos += 2;
	}

	@Override
	public String toString() {
		if (chunks.isEmpty()) {
			return "";
		}
		try {
			return new String(getRaw());
		} catch (IOException e) {
			e.printStackTrace();
			return "Error in body: " + e;
		}
	}

}
