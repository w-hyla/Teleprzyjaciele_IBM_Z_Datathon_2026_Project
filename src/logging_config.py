"""Central logging setup for pipeline operations and audit events.

This module defines a single dictConfig-compatible logging registry used by the
hackathon pipeline to keep operational and audit logs consistent.
"""

import logging.config

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            # Human-readable format for service/runtime diagnostics.
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S"
        },
        "audit_formatter": {
            # AuditService already structures message content; formatter only adds timestamp.
            "format": "%(asctime)s %(message)s",
            "datefmt": "%Y-%m-%dT%H:%M:%S"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "level": "INFO",
            "stream": "ext://sys.stdout"
        },
        "audit_file": {
            "class": "logging.FileHandler",
            "filename": "pipeline_audit.log",
            "formatter": "audit_formatter",
            "level": "INFO",
            "mode": "a",
            "encoding": "utf-8"
        }
    },
    "loggers": {
        # Operational logs for pipeline flow/health.
        "pipeline": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False  # Avoid duplicate entries via root logger.
        },
        # Deterministic audit stream for traceability and post-incident review.
        "pipeline.audit": {
            "handlers": ["console", "audit_file"],
            "level": "INFO",
            "propagate": False  # Keep audit output isolated from parent loggers.
        }
    }
}


def setup_logging():
    """Apply the module's logging configuration.

    Uses ``logging.config.dictConfig`` to register formatters, handlers, and
    named loggers from ``LOGGING_CONFIG``.
    """
    logging.config.dictConfig(LOGGING_CONFIG)