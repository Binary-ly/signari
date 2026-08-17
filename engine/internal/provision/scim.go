package provision

import (
	"context"

	"signari.dev/engine/internal/scim"
)

// SCIM adapts the SCIM client to the provisioner interface.
//
// A thin translation between two User types rather than a change to either.
// The SCIM client is the older of the two and is used directly elsewhere; the
// provisioner interface exists so Google and Entra can share the machinery
// above it. Making SCIM's client speak the newer shape would ripple through
// code that has nothing to do with provisioning.
type SCIM struct{ Client *scim.Client }

func (s SCIM) CreateUser(ctx context.Context, u User) (string, error) {
	return s.Client.CreateUser(ctx,
		scim.NewUser(u.ExternalID, u.UserName, u.DisplayName, u.Email, u.Active))
}

func (s SCIM) SetActive(ctx context.Context, remoteID string, active bool) error {
	return s.Client.SetActive(ctx, remoteID, active)
}

func (s SCIM) DeleteUser(ctx context.Context, remoteID string) error {
	return s.Client.DeleteUser(ctx, remoteID)
}

func (s SCIM) FindByUserName(ctx context.Context, userName string) (*User, error) {
	u, err := s.Client.FindByUserName(ctx, userName)
	if err != nil || u == nil {
		return nil, err
	}
	return &User{
		RemoteID: u.ID, ExternalID: u.ExternalID, UserName: u.UserName,
		DisplayName: u.DisplayName, Active: u.Active,
		Email: firstEmail(u),
	}, nil
}

func (s SCIM) ListUsers(ctx context.Context, pageSize int) ([]User, error) {
	us, err := s.Client.ListUsers(ctx, pageSize)
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(us))
	for _, u := range us {
		out = append(out, User{
			RemoteID: u.ID, ExternalID: u.ExternalID, UserName: u.UserName,
			DisplayName: u.DisplayName, Active: u.Active, Email: firstEmail(&u),
		})
	}
	return out, nil
}

func firstEmail(u *scim.User) string {
	for _, e := range u.Emails {
		if e.Value != "" {
			return e.Value
		}
	}
	return ""
}
