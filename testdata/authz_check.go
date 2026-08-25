package testdata

import "context"

type Ticket struct {
	ID      int64
	OwnerID int64
}

func GetTicketByID(ctx context.Context, id int64) (*Ticket, error) {
	return &Ticket{ID: id}, nil
}

func DeleteTicket(ctx context.Context, t *Ticket) error {
	return nil
}

func removeTicket(ctx context.Context, ticketID int64) error {
	ticket, err := GetTicketByID(ctx, ticketID)
	if err != nil {
		return err
	}
	return DeleteTicket(ctx, ticket)
}
