import tempfile
import unittest
from pathlib import Path
from zkteco_push_probe import ProtocolState, parse_records, redact_response


class ProtocolTests(unittest.TestCase):
    def test_security_handshake_and_events(self):
        with tempfile.TemporaryDirectory() as d:
            state = ProtocolState(Path(d) / 'state.json', 'TEST-SERIAL')
            unreg, typ = state.make_response('GET', '/iclock/cdata', {'options': ['all']}, 'TEST-SERIAL', b'')
            self.assertEqual((unreg, typ), ('OK', 'security_unregistered'))
            reg, typ = state.make_response('POST', '/iclock/registry', {}, 'TEST-SERIAL', b'device=acc')
            self.assertEqual(typ, 'security_registry')
            self.assertTrue(reg.startswith('RegistryCode='))
            config, typ = state.make_response('GET', '/iclock/push', {}, 'TEST-SERIAL', b'')
            self.assertEqual(typ, 'security_push_configuration')
            self.assertIn('Realtime=1', config)
            self.assertIn('TransTables=User Transaction', config)
            registered, _ = state.make_response('GET', '/iclock/cdata', {'options': ['all']}, 'TEST-SERIAL', b'')
            self.assertIn('registry=ok', registered)
            self.assertIn('RegistryCode=', registered)
            ack, _ = state.make_response('POST', '/iclock/cdata', {'table': ['rtlog']}, 'TEST-SERIAL', b'cardno=1a2b3')
            self.assertEqual(ack, 'OK')
            again = ProtocolState(Path(d) / 'state.json', 'TEST-SERIAL')
            reg2, _ = again.make_response('POST', '/iclock/registry', {}, 'TEST-SERIAL', b'')
            self.assertEqual(reg, reg2)

    def test_parse_card(self):
        records = parse_records(b'time=2026-01-01 12:00:00\tpin=0\tcardno=1a2b3\tevent=27\tverifytype=4\n', 'rtlog')
        self.assertEqual(records[0]['parsed']['cardno'], '1a2b3')

    def test_redaction(self):
        self.assertNotIn('top-secret', redact_response('RegistryCode=top-secret\nSessionID=top-secret'))


if __name__ == '__main__':
    unittest.main()
