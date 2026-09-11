package fixture

import (
	"context"
	"database/sql"
	"fmt"

	"google.golang.org/grpc"
	pb "example.test/generated"
)

type server struct {
	pb.UnimplementedDemoServer
	db *sql.DB
}

func (s *server) Unsafe(ctx context.Context, in *pb.CreateRequest) (*pb.Result, error) {
	name := in.GetName()
	query := fmt.Sprintf(`INSERT INTO people (name) VALUES ("%s")`, name)
	statement, err := s.db.Prepare(query)
	if err != nil {
		return nil, err
	}
	statement.Exec()
	return &pb.Result{}, nil
}

func (s *server) Safe(ctx context.Context, in *pb.CreateRequest) (*pb.Result, error) {
	_, err := s.db.Exec("INSERT INTO people (name) VALUES (?)", in.GetName())
	return &pb.Result{}, err
}

func transports(creds grpc.ServerOption) {
	grpc.WithInsecure()
	grpc.NewServer()
	grpc.NewServer(grpc.Creds(creds))
}
