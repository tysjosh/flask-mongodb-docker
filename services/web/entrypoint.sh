#!/bin/sh

if [ "$DATABASE" = "mongodb" ]

then
    echo "Seeding Initial DB Documents"
    mongoimport --uri "$MONGO_URI" --file ./recipes.json
fi
exec "$@"