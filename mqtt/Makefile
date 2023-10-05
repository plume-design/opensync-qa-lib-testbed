all: network_metadata_pb2.py opensync_stats_pb2.py

network_metadata_pb2.py: network_metadata.proto
	protoc -I. --python_out=. $^

opensync_stats_pb2.py: opensync_stats.proto
	protoc -I. --python_out=. $^
