import { compilePolicies, type PolicyDocument } from '@di-framework/authz';

const documents = new Map<string, PolicyDocument>();

/**
 * Compiled `@di-framework/authz` document holding only `resources`, taken from the decorator
 * registry on first use. Call it from the module that imports the `@Policy` classes, so the
 * snapshot always contains them regardless of what else has been imported.
 */
export function policyDocument(...resources: string[]): PolicyDocument {
  const key = resources.join('\0');
  let document = documents.get(key);
  if (!document) {
    document = {
      policies: compilePolicies().policies.filter((policy) => resources.includes(policy.resource)),
    };
    documents.set(key, document);
  }
  return document;
}
