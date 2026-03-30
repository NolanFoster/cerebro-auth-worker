#!/bin/bash
# Deploy with wrangler, then smoke-test /email/send-verification.
# After deploy, set AUTH_WORKER_BASE_URL to your workers.dev URL if not testing locally.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

DEPLOY_ONLY=false
TEST_ONLY=false
EMAIL="test@example.com"

while [[ $# -gt 0 ]]; do
  case $1 in
    --deploy-only) DEPLOY_ONLY=true; shift ;;
    --test-only) TEST_ONLY=true; shift ;;
    --email) EMAIL="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 [--deploy-only] [--test-only] [--email addr]"
      echo "Set AUTH_WORKER_BASE_URL for remote smoke test (default: http://127.0.0.1:8787)"
      exit 0
      ;;
    *)
      error "Unknown option: $1"; exit 1
      ;;
  esac
done

if [[ ! -f "wrangler.toml" ]]; then
  error "Run from auth-worker directory."
  exit 1
fi

if [[ "$TEST_ONLY" == false ]]; then
  log "wrangler deploy"
  wrangler deploy
  success "Deploy finished."
fi

if [[ "$DEPLOY_ONLY" == false ]]; then
  export AUTH_WORKER_BASE_URL="${AUTH_WORKER_BASE_URL:-http://127.0.0.1:8787}"
  log "Smoke test send-verification → $AUTH_WORKER_BASE_URL ($EMAIL)"
  node test-email.js "$EMAIL" "TEST$(date +%s)" 15
  success "Smoke test finished."
fi

success "Done."
