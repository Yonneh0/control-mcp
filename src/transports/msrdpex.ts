import koffi from 'koffi';

export const DLL_PATH_DEFAULT = 'C:\\Program Files\\Devolutions\\MsRdpEx\\MsRdpEx.dll';

export const IID_IUnknown = '00000000-0000-0000-C000-000000000046';
export const IID_IClassFactory = '00000001-0000-0000-C000-000000000046';
export const IID_IMsRdpExCoreApi = '13F6E86F-EE7D-44D1-AA94-1136B784441D';
export const IID_IMsRdpExInstance = '94CDA65A-EFDF-4453-B8B2-2493A12D31C7';
export const IID_IMsTscAx = '8c11efae-92c3-11d1-bc1e-00c04fa31489';
export const IID_IMsRdpClient = '92b4a539-7115-4b7c-a5a9-e5d9efc2780a';
export const IID_IMsTscNonScriptable = 'c1e6743a-41c1-4a74-832a-0dd06c1c7a0e';
export const IID_IMsRdpExtendedSettings = '302d8188-0052-4807-806a-362b628f9ac5';
export const CLSID_MsRdpClientNotSafeForScripting = '7cacbd7b-0d99-468f-ac33-22e495c0afe5';

const GuidStruct = koffi.struct('MsRdpEx_GUID', {
  Data1: 'uint32_t',
  Data2: 'uint16_t',
  Data3: 'uint16_t',
  Data4: koffi.array('uint8_t', 8),
});

export function guidBuffer(guid: string): Buffer {
  const hex = guid.replace(/[{}-]/g, '');
  const d = (i: number, n: number) => parseInt(hex.slice(i, i + n), 16);
  const buf = Buffer.alloc(koffi.sizeof(GuidStruct));
  koffi.encode(buf, GuidStruct, {
    Data1: d(0, 8),
    Data2: d(8, 4),
    Data3: d(12, 4),
    Data4: Array.from(Buffer.from(hex.slice(16), 'hex')),
  });
  return buf;
}

export function hr(n: number): string {
  return `0x${(n >>> 0).toString(16).toUpperCase().padStart(8, '0')}`;
}

export function failed(n: number): boolean {
  return (n & 0x80000000) !== 0;
}

export interface ComObject {
  ptr: bigint;
  vtbl: bigint;
  slot(index: number, ret: string, argTypes: string[]): (...args: unknown[]) => number;
  release(): void;
  queryInterface(iid: string): ComObject;
}

export function wrapCom(ptr: bigint): ComObject {
  const self = BigInt(ptr);
  const vtbl = koffi.decode(self, 'void**') as unknown as bigint;
  const obj: ComObject = {
    ptr: self,
    vtbl,
    slot(index: number, ret: string, argTypes: string[]): (...args: unknown[]) => number {
      const fnAddr = BigInt(koffi.decode(BigInt(vtbl) + BigInt(8 * index), 'void**'));
      const proto = koffi.proto(ret, ['void*', ...argTypes]);
      const fn = koffi.decode(fnAddr, proto) as unknown as (...a: unknown[]) => number;
      return (...args: unknown[]) => fn(self, ...args);
    },
    release() {
      obj.slot(2, 'uint32', [])();
    },
    queryInterface(iid: string): ComObject {
      const riid = guidBuffer(iid);
      const out = Buffer.alloc(8);
      const hrq = obj.slot(0, 'int32', ['void*', 'void**'])(riid, out);
      if (failed(hrq)) throw new Error(`QueryInterface ${iid} failed: ${hr(hrq)}`);
      return wrapCom(out.readBigUInt64LE(0));
    },
  };
  return obj;
}

export interface Ole32 {
  CoInitializeEx: (reserved: null, model: number) => number;
  CoUninitialize: () => void;
}

export function loadOle32(): Ole32 {
  const ole = koffi.load('ole32.dll');
  return {
    CoInitializeEx: ole.func('int32 CoInitializeEx(void*, uint32_t)'),
    CoUninitialize: ole.func('void CoUninitialize()'),
  };
}

export interface OleAut32 {
  SysAllocString: (s: string) => bigint;
  SysFreeString: (b: bigint) => void;
}

export function loadOleAut32(): OleAut32 {
  const aut = koffi.load('oleaut32.dll');
  return {
    SysAllocString: aut.func('void* SysAllocString(uint16_t*)'),
    SysFreeString: aut.func('void SysFreeString(void*)'),
  };
}

export function createInstanceViaFactory(factoryPtr: bigint, iid: string): ComObject {
  const factory = wrapCom(factoryPtr);
  const riid = guidBuffer(iid);
  const out = Buffer.alloc(8);
  const hrCreate = factory.slot(3, 'int32', ['void*', 'void*', 'void**'])(null, riid, out);
  if (failed(hrCreate)) throw new Error(`IClassFactory::CreateInstance failed: ${hr(hrCreate)}`);
  return wrapCom(out.readBigUInt64LE(0));
}

export interface MsRdpExLib {
  lib: ReturnType<typeof koffi.load>;
  InitPaths: (mask: number) => boolean;
  GetPath: (id: number) => string | null;
  CreateInstance: (riid: Buffer, ppvOut: Buffer) => number;
  DllGetClassObject: (rclsid: Buffer, riid: Buffer, ppvOut: Buffer) => number;
  Instance_SetOutputMirrorEnabled: (instance: unknown, enabled: boolean) => number;
  Instance_GetInputWindow: (instance: unknown, hwndOut: Buffer) => number;
}

// The MsRdpEx_OutputMirrorCapture_* surface is intentionally NOT bound here:
// headless in-process hosting can never reach a connected session on this box
// (the MsRdpEx Detours hooks only attach inside real mstsc/msrdc client
// processes, verified via MSRDPEX_LOG_FILE_PATH tracing), so capture bindings
// would be dead FFI that fails at first use. Screen capture goes through
// winsnapshot.ts (PrintWindow) or the axhost-on-target path instead.

export function loadMsRdpEx(dllPath: string = DLL_PATH_DEFAULT): MsRdpExLib {
  const lib = koffi.load(dllPath);
  return {
    lib,
    InitPaths: lib.func('MsRdpEx_InitPaths', 'bool', ['uint32_t']),
    GetPath: lib.func('MsRdpEx_GetPath', 'char*', ['uint32_t']),
    CreateInstance: lib.func('MsRdpEx_CreateInstance', 'int32', ['void*', 'void**']),
    DllGetClassObject: lib.func('DllGetClassObject', 'int32', ['void*', 'void*', 'void**']),
    Instance_SetOutputMirrorEnabled: lib.func('MsRdpEx_Instance_SetOutputMirrorEnabled', 'int32', ['void*', 'bool']),
    Instance_GetInputWindow: lib.func('MsRdpEx_Instance_GetInputWindow', 'int32', ['void*', 'void**']),
  };
}
