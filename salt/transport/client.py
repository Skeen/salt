# -*- coding: utf-8 -*-
"""
Encapsulate the different transports available to Salt.

This includes client side transport, for the ReqServer and the Publisher
"""

# Import Python Libs
from __future__ import absolute_import, print_function, unicode_literals

import logging

# Import Salt Libs
from salt.utils.asynchronous import SyncWrapper

log = logging.getLogger(__name__)


class ReqChannel(object):
    """
    Factory class to create a Sync communication channels to the ReqServer
    """

    @staticmethod
    def factory(opts, **kwargs):
        # All Sync interfaces are just wrappers around the Async ones
        return SyncWrapper(
            AsyncReqChannel.factory, (opts,), kwargs, loop_kwarg="io_loop",
        )

    def close(self):
        """
        Close the channel
        """
        raise NotImplementedError()

    def send(self, load, tries=3, timeout=60, raw=False):
        """
        Send "load" to the master.
        """
        raise NotImplementedError()

    def crypted_transfer_decode_dictentry(
        self, load, dictkey=None, tries=3, timeout=60
    ):
        """
        Send "load" to the master in a way that the load is only readable by
        the minion and the master (not other minions etc.)
        """
        raise NotImplementedError()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class PushChannel(object):
    """
    Factory class to create Sync channel for push side of push/pull IPC
    """

    @staticmethod
    def factory(opts, **kwargs):
        return SyncWrapper(
            AsyncPushChannel.factory, (opts,), kwargs, loop_kwarg="io_loop",
        )

    def send(self, load, tries=3, timeout=60):
        """
        Send load across IPC push
        """
        raise NotImplementedError()


class PullChannel(object):
    """
    Factory class to create Sync channel for pull side of push/pull IPC
    """

    @staticmethod
    def factory(opts, **kwargs):
        return SyncWrapper(
            AsyncPullChannel.factory, (opts,), kwargs, loop_kwarg="io_loop",
        )


# TODO: better doc strings
class AsyncChannel(object):
    """
    Parent class for Async communication channels
    """

    # Resolver is used by Tornado TCPClient.
    # This static field is shared between
    # AsyncReqChannel and AsyncPubChannel.
    # This will check to make sure the Resolver
    # is configured before first use.
    _resolver_configured = False

    @classmethod
    def _config_resolver(cls, num_threads=10):
        import salt.ext.tornado.netutil

        salt.ext.tornado.netutil.Resolver.configure(
            "salt.ext.tornado.netutil.ThreadedResolver", num_threads=num_threads
        )
        cls._resolver_configured = True


# TODO: better doc strings
class AsyncReqChannel(AsyncChannel):
    """
    Factory class to create a Async communication channels to the ReqServer
    """

    @classmethod
    def factory(cls, opts, **kwargs):
        # Default to ZeroMQ for now
        ttype = "zeromq"

        # determine the ttype
        if "transport" in opts:
            ttype = opts["transport"]
        elif "transport" in opts.get("pillar", {}).get("master", {}):
            ttype = opts["pillar"]["master"]["transport"]

        transport = None
        # switch on available ttypes
        if ttype == "zeromq":
            import salt.transport.zeromq

            transport = salt.transport.zeromq.AsyncZeroMQReqChannel(opts, **kwargs)
        elif ttype == "tcp":
            if not cls._resolver_configured:
                # TODO: add opt to specify number of resolver threads
                AsyncChannel._config_resolver()
            import salt.transport.tcp

            transport = salt.transport.tcp.AsyncTCPReqChannel(opts, **kwargs)
        elif ttype == "local":
            raise Exception("There's no AsyncLocalChannel implementation yet")
            # import salt.transport.local
            # return salt.transport.local.AsyncLocalChannel(opts, **kwargs)
        else:
            raise Exception("Channels are only defined for tcp, zeromq, and local")
            # return NewKindOfChannel(opts, **kwargs)'

        import salt.transport.traced
        return salt.transport.traced.TracedReqChannel(transport)

    def send(self, load, tries=3, timeout=60, raw=False):
        """
        Send "load" to the master.
        """
        raise NotImplementedError()

    def crypted_transfer_decode_dictentry(
        self, load, dictkey=None, tries=3, timeout=60
    ):
        """
        Send "load" to the master in a way that the load is only readable by
        the minion and the master (not other minions etc.)
        """
        raise NotImplementedError()

    def close(self):
        """
        Close the channel
        """
        raise NotImplementedError()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class AsyncPubChannel(AsyncChannel):
    """
    Factory class to create subscription channels to the master's Publisher
    """

    @classmethod
    def factory(cls, opts, **kwargs):
        # Default to ZeroMQ for now
        ttype = "zeromq"

        # determine the ttype
        if "transport" in opts:
            ttype = opts["transport"]
        elif "transport" in opts.get("pillar", {}).get("master", {}):
            ttype = opts["pillar"]["master"]["transport"]

        transport = None
        # switch on available ttypes
        if ttype == "detect":
            opts["detect_mode"] = True
            log.info("Transport is set to detect; using %s", ttype)
        if ttype == "zeromq":
            import salt.transport.zeromq

            transport = salt.transport.zeromq.AsyncZeroMQPubChannel(opts, **kwargs)
        elif ttype == "tcp":
            if not cls._resolver_configured:
                # TODO: add opt to specify number of resolver threads
                AsyncChannel._config_resolver()
            import salt.transport.tcp

            transport = salt.transport.tcp.AsyncTCPPubChannel(opts, **kwargs)
        elif ttype == "local":  # TODO:
            raise Exception("There's no AsyncLocalPubChannel implementation yet")
            # import salt.transport.local
            # return salt.transport.local.AsyncLocalPubChannel(opts, **kwargs)
        else:
            raise Exception("Channels are only defined for tcp, zeromq, and local")
            # return NewKindOfChannel(opts, **kwargs)
        import salt.transport.traced
        return salt.transport.traced.TracedPubChannel(transport)

    def connect(self):
        """
        Return a future which completes when connected to the remote publisher
        """
        raise NotImplementedError()

    def close(self):
        """
        Close the channel
        """
        raise NotImplementedError()

    def on_recv(self, callback):
        """
        When jobs are received pass them (decoded) to callback
        """
        raise NotImplementedError()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class AsyncPushChannel(object):
    """
    Factory class to create IPC Push channels
    """

    @staticmethod
    def factory(opts, **kwargs):
        """
        If we have additional IPC transports other than UxD and TCP, add them here
        """
        # FIXME for now, just UXD
        # Obviously, this makes the factory approach pointless, but we'll extend later
        import salt.transport.ipc

        transport = salt.transport.ipc.IPCMessageClient(opts, **kwargs)

        import salt.transport.traced
        return salt.transport.traced.TracedPushChannel(transport)


class AsyncPullChannel(object):
    """
    Factory class to create IPC pull channels
    """

    @staticmethod
    def factory(opts, **kwargs):
        """
        If we have additional IPC transports other than UXD and TCP, add them here
        """
        import salt.transport.ipc

        transport = salt.transport.ipc.IPCMessageServer(opts, **kwargs)

        import salt.transport.traced
        return salt.transport.traced.TracedPullChannel(transport)


## Additional IPC messaging patterns should provide interfaces here, ala router/dealer, pub/sub, etc

# EOF
