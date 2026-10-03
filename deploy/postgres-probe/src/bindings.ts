import { Postgres, WasmCloudBinding } from '@di-framework/bindings';
import { Container } from '@di-framework/core/decorators';

@WasmCloudBinding('example-database', {
  serviceName: 'orders',
})
@Container()
export class ExampleDatabase extends Postgres {
  async execute(sql: string): Promise<void> {
    const result = await this.queryBatch(sql);
    if (result && typeof result === 'object' && 'tag' in result && result.tag === 'err') {
      throw new Error('PostgreSQL rejected the batch');
    }
  }
}
