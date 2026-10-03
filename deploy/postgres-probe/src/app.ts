import { useContainer } from '@di-framework/core/container';
import { TypedRouter } from '@di-framework/http';
import { ExampleDatabase } from './bindings';

const database = useContainer().resolve(ExampleDatabase);
const router = TypedRouter();
router.post('/verify', async () => {
  await database.execute(`
    CREATE TEMP TABLE binding_probe (id integer PRIMARY KEY, message text) ON COMMIT DROP;
    INSERT INTO binding_probe VALUES (1, 'hello from wasm');
    DO $$ BEGIN
      IF (SELECT message FROM binding_probe WHERE id = 1) IS DISTINCT FROM 'hello from wasm' THEN
        RAISE EXCEPTION 'insert/read verification failed';
      END IF;
    END $$;
    UPDATE binding_probe SET message = 'updated through binding' WHERE id = 1;
    DO $$ BEGIN
      IF (SELECT message FROM binding_probe WHERE id = 1) IS DISTINCT FROM 'updated through binding' THEN
        RAISE EXCEPTION 'update/read verification failed';
      END IF;
    END $$;
    DELETE FROM binding_probe WHERE id = 1;
    DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM binding_probe) THEN RAISE EXCEPTION 'delete verification failed'; END IF;
    END $$;
  `);
  return Response.json({ app: 'postgres-probe', ok: true });
});
export default router;
