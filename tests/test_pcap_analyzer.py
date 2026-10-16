import os
import tempfile
import pytest
from app.services.pcap_analyzer import PcapAnalyzer, PcapAnalysisError
from app.database import init_db, get_db

def test_parse_valid_pcap(sample_pcap_path, test_db_path):
    analyzer = PcapAnalyzer()
    result = analyzer.parse_file(sample_pcap_path, db_path=test_db_path)

    assert result['packet_count'] == 5
    assert result['analysis_duration'] >= 0.0
    assert result['file_size'] > 0
    assert len(result['statistics']['protocol_distribution']) >= 2

    # Verify database persistence
    with get_db(test_db_path) as conn:
        cap_row = conn.execute("SELECT * FROM captures WHERE id = ?", (result['capture_id'],)).fetchone()
        assert cap_row is not None
        assert cap_row['packet_count'] == 5

        pkt_count = conn.execute("SELECT COUNT(*) FROM packets WHERE capture_id = ?", (result['capture_id'],)).fetchone()[0]
        assert pkt_count == 5

def test_parse_empty_file(test_db_path):
    fd, path = tempfile.mkstemp(suffix='.pcap')
    os.close(fd)

    analyzer = PcapAnalyzer()
    with pytest.raises(PcapAnalysisError) as exc_info:
        analyzer.parse_file(path, db_path=test_db_path)

    assert "completely empty" in str(exc_info.value).lower()

    if os.path.exists(path):
        os.remove(path)

def test_parse_malformed_file(test_db_path):
    fd, path = tempfile.mkstemp(suffix='.pcap')
    os.close(fd)
    with open(path, 'wb') as f:
        f.write(b"NOT_A_VALID_PCAP_STREAM_CONTENT_CORRUPTED")

    analyzer = PcapAnalyzer()
    with pytest.raises(PcapAnalysisError):
        analyzer.parse_file(path, db_path=test_db_path)

    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass

def test_truncation_limit(sample_pcap_path, test_db_path):
    # Set max_packets to 2
    analyzer = PcapAnalyzer(max_packets=2)
    result = analyzer.parse_file(sample_pcap_path, db_path=test_db_path)

    assert result['packet_count'] == 2
    assert result['is_truncated'] is True
    assert any("limit reached" in w.lower() for w in result['parsing_warnings'])
