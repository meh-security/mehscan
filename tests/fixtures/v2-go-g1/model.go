package fixture

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func Lookup(client *mongo.Client, filter bson.M) error {
	return client.Database("app").Collection("items").FindOne(context.TODO(), filter).Err()
}
