module.exports = {
    client: 'sqlite3',
    connection: {
        filename: __dirname+'/db/dev.sqlite3',
    },
    migrations: {
        directory: __dirname + '/db/migrations',
    },
    seeds: {
        directory: __dirname + './db/seeds',
    },
    useNullAsDefault: true // Specify true to use null as the default value
};