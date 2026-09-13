import {integer,sqliteTable,text,index} from "drizzle-orm/sqlite-core";
export const sandboxes=sqliteTable("sandboxes",{id:text("id").primaryKey(),revision:integer("revision").notNull().default(0),state:text("state").notNull(),expiresAt:integer("expires_at").notNull()},t=>[index("idx_sandboxes_expires").on(t.expiresAt)]);
