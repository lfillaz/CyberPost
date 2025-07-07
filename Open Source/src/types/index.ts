


export interface RequestHeader {
  key: string;
  value: string;
}

export interface RequestParam {
  key: string;
  value: string;
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS' | 'HEAD';
export type BodyType = 'raw' | 'json' | 'form-data' | 'x-www-form-urlencoded';

export interface RequestConfig {
  id: string;
  name: string;
  url: string;
  method: HttpMethod;
  headers: RequestHeader[];
  params: RequestParam[];
  body: string;
  bodyType: BodyType;
  createdAt?: number;
  updatedAt?: number;
  useCorsProxy?: boolean;
}

export interface RequestResponse {
  status: number;
  statusText: string;
  headers: [string, string][];
  data: any;
  time: number;
  error?: string;
  request?: {
    url: string;
    method: string;
    headers: RequestHeader[];
    body?: string;
  };
}


export interface Session {
  id: string;
  name: string;
  description?: string;
  requestIds: string[];
  createdAt: number;
  updatedAt: number;
}


export interface MockConfig {
  statusCode: number;
  contentType: string;
  responseBody: string;
  delay: number;
  reflectPost: boolean;
}


export interface Payload {
  name: string;
  value: string;
  description: string;
  tags?: string[];
}

export interface PayloadCategory {
  name: string;
  description: string;
  payloads: Payload[];
}


export type EncodingType = 'base64' | 'url' | 'html' | 'jwt';
export type EncodingDirection = 'encode' | 'decode';


export interface Tab {
  id: string;
  name: string;
}

export type ThemeType = 'cyber-green' | 'cyber-cyan' | 'cyber-red';

export interface AppSettings {
  theme: ThemeType;
  autoSave: boolean;
  defaultRequestMethod: HttpMethod;
  defaultBodyType: BodyType;
  darkMode: boolean;
}
