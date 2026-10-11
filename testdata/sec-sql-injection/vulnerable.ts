// Vulnerable: SQL built by concatenation / template interpolation.
interface Db {
  query(sql: string, params?: unknown[]): Promise<unknown[]>;
}

export function findUser(db: Db, name: string): Promise<unknown[]> {
  return db.query("SELECT * FROM users WHERE name = '" + name + "'");
}

export function findById(db: Db, id: number): Promise<unknown[]> {
  return db.query(`SELECT * FROM users WHERE id = ${id}`);
}
