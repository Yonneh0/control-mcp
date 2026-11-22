import { z } from 'zod';

// A password environment variable name: one rule for both SSH and RDP so the
// derived secret lookup and the schema cannot disagree.
const PasswordEnvSchema = z
  .string()
  .regex(/^[A-Z0-9_]+$/, 'passwordEnv must be an UPPER_SNAKE_CASE environment variable name');

export const SshSchema = z
  .object({
    port: z.number().int().min(1).max(65535).default(22),
    user: z.string().min(1),
    privateKeyPath: z.string().min(1).optional(),
    password: z.string().min(1).optional(),
    passwordEnv: PasswordEnvSchema.optional(),
  })
  .strict()
  .superRefine((v, ctx) => {
    // min(1) already rejects empty strings; this covers the all-absent case.
    if (!v.privateKeyPath && !v.password && !v.passwordEnv) {
      ctx.addIssue({
        code: 'custom',
        message: 'ssh needs at least one of privateKeyPath, password, or passwordEnv',
        path: ['privateKeyPath'],
      });
    }
  });

export const RdpSchema = z
  .object({
    port: z.number().int().min(1).max(65535).default(3389),
    user: z.string().min(1),
    domain: z.string().min(1).optional(),
    credentialTarget: z.string().min(1).optional(),
    passwordEnv: PasswordEnvSchema.optional(),
    width: z.number().int().min(640).max(7680).default(1920),
    height: z.number().int().min(480).max(4320).default(1080),
  })
  .strict();

export const HostSchema = z
  .object({
    name: z
      .string()
      .regex(/^[A-Za-z0-9][A-Za-z0-9_-]*$/, 'name must start with a letter or digit and use only letters, digits, _ or - (it is also used to derive env-var names for secrets)'),
    address: z.string().trim().min(1),
    os: z.enum(['windows', 'linux']),
    ssh: SshSchema,
    rdp: RdpSchema.optional(),
    alternateAddresses: z.array(z.string()).default([]),
    capabilities: z
      .object({ rdp: z.boolean().default(false) })
      .strict()
      .prefault({}),
  })
  .strict();

export const SafetySchema = z
  .object({
    refuseSelfSevering: z.boolean().default(true),
    firewallProfile: z.enum(['Any', 'Domain', 'Private', 'Public']).default('Any'),
  })
  .strict()
  .prefault({});

export const ConfigSchema = z
  .object({
    hosts: z.array(HostSchema).min(1),
    defaultHost: z.string().optional(),
    safety: SafetySchema,
  })
  .strict()
  .superRefine((cfg, ctx) => {
    // A host is resolved by name OR any of its addresses. Two hosts sharing a
    // resolvable key make selection ambiguous, so reject at load time and name
    // both rather than silently picking array order.
    const owner = new Map<string, string>();
    const note = (key: string, host: string, path: number, kind: string) => {
      const prior = owner.get(key);
      if (prior && prior !== host) {
        ctx.addIssue({
          code: 'custom',
          message: `${kind} "${key}" is claimed by both "${prior}" and "${host}"; a host must be uniquely resolvable by name and address`,
          path: [path],
        });
      } else if (!prior) {
        owner.set(key, host);
      }
    };
    cfg.hosts.forEach((h, i) => {
      note(h.name, h.name, i, 'name');
      note(h.address, h.name, i, 'address');
      for (const alt of h.alternateAddresses) note(alt, h.name, i, 'alternate address');
    });
  });

export type SshConfig = z.infer<typeof SshSchema>;
export type RdpConfig = z.infer<typeof RdpSchema>;
export type HostConfig = z.infer<typeof HostSchema>;
export type SafetyConfig = z.infer<typeof SafetySchema>;
export type ControlConfig = z.infer<typeof ConfigSchema>;
