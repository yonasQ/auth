exports.up = function (knex) {
  return knex.schema.hasTable('users').then(function (exists) {
    if (!exists) {
      knex.schema.createTable('users', function (table) {
        table.increments('uid').primary();
        table.string('email').notNullable();
        table.string('first_name').notNullable();
        table.string('last_name').notNullable();
        table.jsonb('preferences');
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
  return knex.schema.dropTable('users');
};