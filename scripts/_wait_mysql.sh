#!/usr/bin/env bash
# Wait for MySQL container to become healthy.
for i in $(seq 1 20); do
  status=$(docker inspect -f '{{.State.Health.Status}}' dbsec-mysql 2>/dev/null || echo "unknown")
  echo "attempt $i: $status"
  if [ "$status" = "healthy" ]; then
    exit 0
  fi
  sleep 3
done
echo "MySQL did not become healthy in time."
exit 1
