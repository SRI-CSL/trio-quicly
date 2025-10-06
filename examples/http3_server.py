#  Copyright (c) 2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/
#

import argparse
import functools
import logging
import sys
import trio


async def main(
    host: str,
    port: int,
    # configuration: QuicConfiguration,
    # session_ticket_store: SessionTicketStore,
    retry: bool,
) -> None:
    await trio.sleep(5)  # TODO: implement entry point
    # await serve(
    #     host,
    #     port,
    #     # configuration=configuration,
    #     # create_protocol=HttpServerProtocol,
    #     # session_ticket_fetcher=session_ticket_store.pop,
    #     # session_ticket_handler=session_ticket_store.add,
    #     retry=retry,
    # )


if __name__ == "__main__":
    #defaults = QuicConfiguration(is_client=False)

    parser = argparse.ArgumentParser(description="QUIC server")
    parser.add_argument(
        "--host",
        type=str,
        default="::",
        help="listen on the specified address (defaults to ::)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4444,
        help="listen on the specified port (defaults to 4444)",
    )
    parser.add_argument(
        "--quic-log",
        type=str,
        help="log QUIC events to QLOG files in the specified directory",
    )
    parser.add_argument(
        "--retry",
        action="store_true",
        help="send a retry for new connections",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="increase logging verbosity"
    )
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    # create QUIC logger
    # if args.quic_log:
    #     quic_logger = QuicFileLogger(args.quic_log)
    # else:
    #     quic_logger = None

    # TODO: configuration

    try:
        trio.run(main, functools.partial(
            host=args.host,
            port=args.port,
            # configuration=configuration,
            # session_ticket_store=SessionTicketStore(),
            retry=args.retry))
    except* KeyboardInterrupt:
        pass