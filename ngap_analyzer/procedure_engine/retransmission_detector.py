"""
Generic Retransmission and Duplicate Capture Detection Framework.
"""

import logging
from collections import defaultdict
from typing import List
from ..models import Procedure

logger = logging.getLogger(__name__)


class RetransmissionDetector:
    """
    Detects and annotates duplicate packet captures versus legitimate protocol retransmissions in procedure timelines.
    """

    def detect_retransmissions(self, procedures: List[Procedure]):
        for p in procedures:
            # Group events by message type
            type_events = defaultdict(list)
            for event in p.events:
                type_events[event.message_type].append(event)

            for msg_type, ev_list in type_events.items():
                if len(ev_list) > 1:
                    # Sort chronologically by timestamp
                    sorted_evs = sorted(ev_list, key=lambda x: x.timestamp)
                    
                    for i in range(len(sorted_evs) - 1):
                        e1 = sorted_evs[i]
                        e2 = sorted_evs[i + 1]
                        dt = e2.timestamp - e1.timestamp

                        if dt < 0.05:  # Less than 50 milliseconds is duplicate capture
                            p.observations.append(
                                f"Duplicate capture of {msg_type} detected in frame {e2.frame_number} (delta: {dt:.3f}s)."
                            )
                        else:  # Legitimate retransmission
                            p.observations.append(
                                f"Protocol retransmission of {msg_type} detected in frame {e2.frame_number} (delta: {dt:.3f}s)."
                            )
