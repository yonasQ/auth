exports.up = function (knex) {
  return knex.schema.hasTable('sessions').then(function (exists) {
    if (!exists) {
      knex.schema.createTable('sessions', table => {
        table.string('sid').notNullable().primary();
        table.json('sess').notNullable();
        table.timestamp('expired').notNullable();
        table.string('user_uid');
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
  return knex.schema.dropTable('sessions');
};