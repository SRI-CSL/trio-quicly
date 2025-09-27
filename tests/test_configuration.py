#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

from quicly.configuration import QuicConfiguration, TransportParameterType, update_config

def test_datagram_configuration():
    config = QuicConfiguration()
    assert config.transport_parameters.max_datagram_frame_size == 0
    transport_parameters = {TransportParameterType.MAX_DATAGRAM_FRAME_SIZE : 1200}  # add DATAGRAM support
    update_config(config, transport_parameters)
    assert config.transport_parameters.max_datagram_frame_size == 1200
