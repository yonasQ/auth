exports.up = function (knex) {
  return knex.schema.hasTable('access_tokens').then(function (exists) {
    if (!exists) {
      knex.schema.createTable('access_tokens', table => {
        table.increments('id').primary();
        table.string('uid').notNullable();
        table.string('access_token_hash').notNullable();
        table.string('owner_uid').notNullable();
      }).then((tableName) => {
        console.log(`Table ${tableName} created or already exists`);
        return knex.destroy();
      })
        .catch(error => {
          console.error(`Error creating table ${tableName}: ${error.message}`);
          return knex.destroy();
        });
    }
  })
};

exports.down = function (knex) {
  return knex.schema.dropTable('access_tokens');
};