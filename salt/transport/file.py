# -*- coding: utf-8 -*-
"""
TCP transport classes

Wire protocol: "len(payload) msgpack({'head': SOMEHEADER, 'body': SOMEBODY})"

"""

## Import Python Libs
from __future__ import absolute_import, print_function, unicode_literals
import json
import base64
import errno
import logging
import os
import socket
import sys
import threading
import time
import traceback
import weakref
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from tornado.ioloop import IOLoop
from tornado.queues import Queue
import tempfile

# Import Salt Libs
import salt.crypt
import salt.exceptions

# Import Tornado Libs
import salt.ext.tornado
import salt.ext.tornado.concurrent
import salt.ext.tornado.gen
import salt.ext.tornado.iostream
import salt.ext.tornado.netutil
import salt.ext.tornado.tcpclient
import salt.ext.tornado.tcpserver
import salt.payload
import salt.transport.client
import salt.transport.frame
import salt.transport.ipc
import salt.transport.mixins.auth
import salt.transport.server
import salt.utils.asynchronous
import salt.utils.event
import salt.utils.files
import salt.utils.msgpack
import salt.utils.platform
import salt.utils.process
import salt.utils.verify
from salt.exceptions import SaltClientError, SaltReqTimeoutError
from salt.ext import six
from salt.ext.six.moves import queue  # pylint: disable=import-error
from salt.transport import iter_transport_opts

# pylint: disable=import-error,no-name-in-module
if six.PY2:
    import urlparse
else:
    import urllib.parse as urlparse
# pylint: enable=import-error,no-name-in-module

# Import third party libs
try:
    from M2Crypto import RSA

    HAS_M2 = True
except ImportError:
    HAS_M2 = False
    try:
        from Cryptodome.Cipher import PKCS1_OAEP
    except ImportError:
        from Crypto.Cipher import PKCS1_OAEP

log = logging.getLogger(__name__)


class AsyncTCPReqChannel(AbstractAsyncTCPReqChannel):
    def start_channel(self, io_loop):
        resolver = kwargs.get("resolver")

        parse = urlparse.urlparse(self.opts["master_uri"])
        master_host, master_port = parse.netloc.rsplit(":", 1)
        self.master_addr = (master_host, int(master_port))

        self.message_client = SaltMessageClientPool(
            self.opts,
            args=(self.opts, master_host, int(master_port),),
            kwargs={
                "io_loop": self.io_loop,
                "resolver": resolver,
                "source_ip": self.opts.get("source_ip"),
                "source_port": self.opts.get("source_ret_port"),
            },
        )

    def close(self):
        super(AsyncTCPReqChannel, self).close()
        self.message_client.close()

    def publish_dict(self, dicty, tries=3, timeout=60):
        return self.message_client.send(dicty, timeout=timeout)


## TODO: move serial down into message library
#class AsyncTCPReqChannel(AbstractAsyncTCPReqChannel):
#    def start_channel(self, io_loop):
#        pass
#
#    def publish_string(self, spayload):
#        """Transfer a string to the minions.
#
#        The transfer involves two steps.
#        1. Create a temporary file, with the payload.
#        2. Signal an event to master, that a new temporary file has been
#           created, and should be consumed.
#        """
#        payload_filename = None
#        with tempfile.NamedTemporaryFile(mode="w", dir=req_folder, delete=False) as tmpfile:
#            payload_filename = tmpfile.name
#            tmpfile.write(spayload)
#
#        event = {
#            "timestamp": str(time.time()),
#            "file": str(payload_filename)
#        }
#        with open(req_event_file, "a") as event_file:
#            event_file.write(json.dumps(event) + "\n")
#

def read_file(file_path, queue: Queue, io_loop: IOLoop, chunk_size: int = 64 * 1024):
    lock = threading.Lock()

    def putter(chunk, lock: threading.Lock):
        queue.put(chunk)        # Called from the loop's thread -> can block
        lock.release()          # Awake reader thread after the chunk has been put into the processing queue

    def put(chunk, lock):
        """Put the chunk into the queue, and wait until it is processed by the ioloop"""
        lock.acquire()  # Acquire in this thread
        io_loop.spawn_callback(putter, chunk, lock) # Release in the loop's thread
        lock.acquire()  # Wait until the loop's thread has accepted the chunk for processing
        lock.release()  # Cleanup before return

    # Open and watch the event file for changes
    reader_start = time.time()
    with open(file_path, "r") as event_file:
        while True:
            serialized_event = event_file.readline()
            # No data yet, try again later
            if len(serialized_event) == 0:
                time.sleep(1)
                continue
            print("read", serialized_event)
            event = json.loads(serialized_event)
            print("event", event)
            contents = None
            # Only accept events from after we started listening
            if float(event['timestamp']) < reader_start:
                print("got old event", event)
                continue
            # Read out the entire payload, and put it into the queue
            with open(event['file'], "r") as tmpfile:
                contents = tmpfile.read()
            print("contents", contents)
            put(contents, lock)


pub_folder = "/tmp/salt-pub/"
pub_event_file = pub_folder + "event_file"
req_folder = "/tmp/salt-req/"
req_event_file = req_folder + "event_file"


class AsyncTCPPubChannel(
    salt.transport.mixins.auth.AESPubClientMixin, salt.transport.client.AsyncPubChannel
):
    def __init__(self, opts, **kwargs):
        self.opts = opts

        self.serial = salt.payload.Serial(self.opts)

        self.crypt = kwargs.get("crypt", "aes")
        self.io_loop = kwargs.get("io_loop") or salt.ext.tornado.ioloop.IOLoop.current()
        self.event = salt.utils.event.get_event("minion", opts=self.opts, listen=False)
        self.callbacks = []

    def close(self):
        pass

    # pylint: disable=W1701
    def __del__(self):
        pass

    @salt.ext.tornado.gen.coroutine
    def read_file(self):
        pool = ThreadPoolExecutor(3)
        # Create a queue for sending chunks of data
        cq = Queue(maxsize=3)
        # Start the reader thread that reads in a separate thread
        pool.submit(read_file, pub_event_file, cq, self.io_loop)
        # Process chunks
        unpacker = salt.utils.msgpack.Unpacker()
        while True:
            line = yield cq.get()
            payload_string = line
            bpayload = payload_string.encode('ascii')
            payload = base64.b64decode(bpayload)
            print("payload", payload, type(payload))
            print("bpayload", bpayload, type(bpayload))
            print("payload_string", payload_string, type(payload_string))
            unpacker.feed(payload)
            for framed_msg in unpacker:
                print("framed", framed_msg)
                header = framed_msg[b"head"]
                body = framed_msg[b"body"]
                message_id = header.get("mid")
                print("msgpacked", header, body, message_id)
                if not isinstance(body, dict):
                    body = salt.utils.msgpack.loads(body)
                    print("double loaded body", body)
                    if six.PY3:
                        body = salt.transport.frame.decode_embedded_strs(body)
                        print("six bodies", body)
                ret = yield self._decode_payload(body)
                print("ret", ret)
                for callback in self.callbacks:
                    self.io_loop.spawn_callback(callback, ret)
        raise salt.ext.tornado.gen.Return(None)

    # pylint: enable=W1701
    @salt.ext.tornado.gen.coroutine
    def connect(self):
        print("INSIDE CONNECT")
        try:
            self.auth = salt.crypt.AsyncAuth(self.opts, io_loop=self.io_loop)
            self.tok = self.auth.gen_token(b"salt")
            if not self.auth.authenticated:
                yield self.auth.authenticate()
            if self.auth.authenticated:
                self.io_loop.spawn_callback(self.read_file)
                self.event.fire_event({"master": self.opts["master"]}, "__master_connected")
        except KeyboardInterrupt:  # pylint: disable=try-except-raise
            raise
        except Exception as exc:  # pylint: disable=broad-except
            if "-|RETRY|-" not in six.text_type(exc):
                raise SaltClientError(
                    "Unable to sign_in to master: {0}".format(exc)
                ) # TODO: better error message

    def on_recv(self, callback):
        print("INSIDE ON_RECV")
        self.callbacks.append(callback)


class FileReqServerChannel(salt.transport.abstract.AbstractReqServerChannel):
    def __init__(self, opts):
        self.io_loop = None

    def start_channel(self, io_loop):
        """Start communications channel.

        Starting the channel is creating the communications folder, and
        emptying out the event file.
        """
        # Create folder if it does not exist
        try:
            os.mkdir(req_folder)
        except FileExistsError:
            pass
        # Clear out file
        open(req_event_file, 'w').close()
        self.io_loop.spawn_callback(self.read_file)

    @salt.ext.tornado.gen.coroutine
    def read_file(self):
        print("!!!", "read_file")
        pool = ThreadPoolExecutor(3)
        # Create a queue for sending chunks of data
        cq = Queue(maxsize=3)
        # Start the reader thread that reads in a separate thread
        pool.submit(read_file, req_event_file, cq, self.io_loop)
        # Process chunks
        unpacker = salt.utils.msgpack.Unpacker()
        while True:
            line = yield cq.get()
            print("!!!", "line", line)
            payload_string = line
            bpayload = payload_string.encode('ascii')
            payload = base64.b64decode(bpayload)
            print("payload", payload, type(payload))
            print("bpayload", bpayload, type(bpayload))
            print("payload_string", payload_string, type(payload_string))
            unpacker.feed(payload)
            for framed_msg in unpacker:
                print("framed", framed_msg)
                if six.PY3:
                    framed_msg = salt.transport.frame.decode_embedded_strs(
                        framed_msg
                    )
                header = framed_msg["head"]
                self.io_loop.spawn_callback(
                    self.process_message, header, framed_msg["body"]
                )
        raise salt.ext.tornado.gen.Return(None)

    def write_back(self, message):
        print(message)

    def send_back(self, message):
        print(message)


class TCPPubServerChannel(AbstractPubServerChannel):
    """File-based PubServerChannel.

    This implementation serves solely as a minimal example for how to implement
    the PubSererChannel.

    It utilizes a single file as an event bus notifying minions whenever new
    data is available, and creates a temporary files for each transfer.

    Minions read the event bus file, and reacts to events by reading the
    temporary file containing the actual message.
    """
    def start_channel(self, io_loop):
        """Start communications channel.

        Starting the channel is creating the communications folder, and
        emptying out the event file.
        """
        # Create folder if it does not exist
        try:
            os.mkdir(pub_folder)
        except FileExistsError:
            pass
        # Clear out file
        open(pub_event_file, 'w').close()

    def publish_string(self, spayload):
        """Transfer a string to the minions.

        The transfer involves two steps.
        1. Create a temporary file, with the payload.
        2. Signal an event to minions, that a new temporary file has been
           created, and should be consumed.
        """
        payload_filename = None
        with tempfile.NamedTemporaryFile(mode="w", dir=pub_folder, delete=False) as tmpfile:
            payload_filename = tmpfile.name
            tmpfile.write(spayload)

        event = {
            "timestamp": str(time.time()),
            "file": str(payload_filename)
        }
        with open(pub_event_file, "a") as event_file:
            event_file.write(json.dumps(event) + "\n")
