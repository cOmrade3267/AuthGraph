// testdata/authz_check.go
package testdata

import "context"

type Ticket struct {
	ID      int64
	OwnerID int64
}

func GetTicketByID(ctx context.Context, id int64) (*Ticket, error) {
	// stub — pretend this hits a database
	return &Ticket{ID: id}, nil
}

func DeleteTicket(ctx context.Context, t *Ticket) error {
	// stub — pretend this deletes the record
	return nil
}

// removeTicket fetches a ticket by ID and deletes it with no permission
// check — mirrors the CVE-2026-58438 (Gitea RemoveDependency) shape.
func removeTicket(ctx context.Context, ticketID int64) error {
	ticket, err := GetTicketByID(ctx, ticketID)
	if err != nil {
		return err
	}
	return DeleteTicket(ctx, ticket)
}
