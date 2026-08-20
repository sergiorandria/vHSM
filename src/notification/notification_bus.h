// WHY NotificationBus is a virtual interface (not concrete class): Multiple
// subscribers may need to receive events (logging, monitoring, audit records,
// SIEM integration, webhooks). Making publish() virtual allows different
// implementations (in-process queue, RabbitMQ, Kafka, REST API call). The
// interface is decoupled from transport. SignatureDispatcher doesn't care how
// events are delivered; it just publishes to the bus.
//
// WHY publish() takes const NotificationEvent&: Events are immutable after
// creation. const prevents accidental modification. Reference avoids copying
// the struct (efficient).
//
// WHY virtual (not pure virtual) publish(): Allows default implementation
// (e.g., no-op for testing, or log to file). Derived classes can override with
// their own logic (in-memory queue, database, external API). Concrete
// subclasses implement the specific transport.

#ifndef VHSM_NOTIFICATION_NOTIFICATION_BUS_H
#define VHSM_NOTIFICATION_NOTIFICATION_BUS_H

#include "notification_event.h"

namespace vhsm::notification {

// WHY NotificationBus pattern (observer pattern): Decouples event producers
// (Signature Dispatcher, LedgerWorker) from consumers (audit log, monitoring,
// alerting). Producers don't know or care who listens; they just publish.
// Consumers can be added/removed without changing producers. This is the
// pub-sub pattern: central bus, multiple subscribers.

class NotificationBus {
public:
  virtual ~NotificationBus() = default;

  // WHY virtual publish: Allows multiple implementations. In-memory queue for
  // testing, database for production, webhook for cloud, etc. The interface is
  // stable; implementation can change without affecting callers.
  //
  // WHY publish takes const reference to NotificationEvent: Events are
  // immutable data. const enforces read-only semantics. Reference avoids struct
  // copy (efficient). The event is expected to contain:
  // - type: event type enum (SIGN_CREATED, DB_WRITE_FAILED, etc.)
  // - severity: event severity (INFO, WARNING, CRITICAL)
  // - timestamp: when the event occurred (epoch milliseconds)
  // - source: which component generated the event
  // - actor: who/what was responsible (user label, system component)
  // - summary: human-readable brief description
  // - detail_json: JSON with machine-parseable structured details
  // - hsm_instance: which HSM instance (for multi-instance correlation)
  virtual void publish(const NotificationEvent &event) = 0;
};
} // namespace vhsm::notification
#endif // VHSM_NOTIFICATION_NOTIFICATION_BUS_H