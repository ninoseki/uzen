s = """
from app.schemas.classifications import Classification
from app.schemas.dns_records import BaseDnsRecord, DnsRecord
from app.schemas.domain import Domain
from app.schemas.ip_address import IPAddress
from app.schemas.matches import Match, MatchResult
from app.schemas.rules import Rule
from app.schemas.screenshots import Screenshot
from app.schemas.scripts import File, Script
from app.schemas.snapshots import Snapshot
from app.schemas.utils import SearchResults, SnapshotResult
from app.schemas.yara import ScanPayload, ScanResult
"""

s.lines.each do |line|
  klass_names = line.split(" import ").last.strip
  klass_names.split(",").each do |klass|
    puts '"' + klass.strip + '",'
  end
end
