/**
 * Storage manager for handling requests and session history
 * Using IndexedDB for persistent storage
 */

import { v4 as uuidv4 } from 'uuid';
import type { RequestConfig } from '../utils/requestBuilder';

// Database configuration
const DB_NAME = 'cyberpost_db';
const DB_VERSION = 1;
const REQUESTS_STORE = 'requests';
const SESSIONS_STORE = 'sessions';

interface Session {
  id: string;
  name: string;
  description?: string;
  requestIds: string[];
  createdAt: number;
  updatedAt: number;
}

/**
 * Initialize the IndexedDB database
 */
export const initializeDB = (): Promise<IDBDatabase> => {
  return new Promise((resolve, reject) => {
    if (!window.indexedDB) {
      reject(new Error('Your browser doesn\'t support IndexedDB'));
      return;
    }

    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = (_event: Event) => {
      reject(new Error('Error opening database'));
    };

    request.onsuccess = (event: Event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      resolve(db);
    };

    request.onupgradeneeded = (event: IDBVersionChangeEvent) => {
      const db = (event.target as IDBOpenDBRequest).result;

      // Create requests store
      if (!db.objectStoreNames.contains(REQUESTS_STORE)) {
        const requestsStore = db.createObjectStore(REQUESTS_STORE, { keyPath: 'id' });
        requestsStore.createIndex('updatedAt', 'updatedAt', { unique: false });
      }

      // Create sessions store
      if (!db.objectStoreNames.contains(SESSIONS_STORE)) {
        const sessionsStore = db.createObjectStore(SESSIONS_STORE, { keyPath: 'id' });
        sessionsStore.createIndex('updatedAt', 'updatedAt', { unique: false });
      }
    };
  });
};

/**
 * Save or update a request
 */
export const saveRequest = async (request: RequestConfig): Promise<string> => {
  const db = await initializeDB();
  const timestamp = Date.now();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([REQUESTS_STORE], 'readwrite');
    const store = transaction.objectStore(REQUESTS_STORE);
    
    // Ensure the request has an ID
    if (!request.id) {
      request.id = uuidv4();
    }
    
    // Add timestamps
    // Use type assertion to satisfy TypeScript
    const requestWithTimestamp = {
      ...request,
      updatedAt: timestamp,
      createdAt: (request as any).createdAt || timestamp
    } as RequestConfig;
    
    const putRequest = store.put(requestWithTimestamp);
    
    putRequest.onsuccess = () => {
      resolve(request.id);
    };
    
    putRequest.onerror = () => {
      reject(new Error('Error saving request'));
    };
    
    transaction.oncomplete = () => {
      db.close();
    };
  });
};

/**
 * Get a request by ID
 */
export const getRequest = async (id: string): Promise<RequestConfig | null> => {
  const db = await initializeDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([REQUESTS_STORE], 'readonly');
    const store = transaction.objectStore(REQUESTS_STORE);
    const getRequest = store.get(id);
    
    getRequest.onsuccess = () => {
      resolve(getRequest.result || null);
    };
    
    getRequest.onerror = () => {
      reject(new Error('Error getting request'));
    };
    
    transaction.oncomplete = () => {
      db.close();
    };
  });
};

/**
 * Get all requests
 */
export const getAllRequests = async (): Promise<RequestConfig[]> => {
  const db = await initializeDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([REQUESTS_STORE], 'readonly');
    const store = transaction.objectStore(REQUESTS_STORE);
    const index = store.index('updatedAt');
    const getAllRequest = index.getAll();
    
    getAllRequest.onsuccess = () => {
      // Sort by updatedAt in descending order (newest first)
      const results = getAllRequest.result.sort((a, b) => b.updatedAt - a.updatedAt);
      resolve(results);
    };
    
    getAllRequest.onerror = () => {
      reject(new Error('Error getting requests'));
    };
    
    transaction.oncomplete = () => {
      db.close();
    };
  });
};

/**
 * Delete a request
 */
export const deleteRequest = async (id: string): Promise<boolean> => {
  const db = await initializeDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([REQUESTS_STORE], 'readwrite');
    const store = transaction.objectStore(REQUESTS_STORE);
    const deleteRequest = store.delete(id);
    
    deleteRequest.onsuccess = () => {
      resolve(true);
    };
    
    deleteRequest.onerror = () => {
      reject(new Error('Error deleting request'));
    };
    
    transaction.oncomplete = () => {
      db.close();
    };
  });
};

/**
 * Create a session with a set of requests
 */
export const createSession = async (name: string, description: string, requestIds: string[]): Promise<string> => {
  const db = await initializeDB();
  const timestamp = Date.now();
  const sessionId = uuidv4();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([SESSIONS_STORE], 'readwrite');
    const store = transaction.objectStore(SESSIONS_STORE);
    
    const session: Session = {
      id: sessionId,
      name,
      description,
      requestIds,
      createdAt: timestamp,
      updatedAt: timestamp
    };
    
    const addRequest = store.add(session);
    
    addRequest.onsuccess = () => {
      resolve(sessionId);
    };
    
    addRequest.onerror = () => {
      reject(new Error('Error creating session'));
    };
    
    transaction.oncomplete = () => {
      db.close();
    };
  });
};

/**
 * Get a session by ID
 */
export const getSession = async (id: string): Promise<Session | null> => {
  const db = await initializeDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([SESSIONS_STORE], 'readonly');
    const store = transaction.objectStore(SESSIONS_STORE);
    const getRequest = store.get(id);
    
    getRequest.onsuccess = () => {
      resolve(getRequest.result || null);
    };
    
    getRequest.onerror = () => {
      reject(new Error('Error getting session'));
    };
    
    transaction.oncomplete = () => {
      db.close();
    };
  });
};

/**
 * Get all sessions
 */
export const getAllSessions = async (): Promise<Session[]> => {
  const db = await initializeDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([SESSIONS_STORE], 'readonly');
    const store = transaction.objectStore(SESSIONS_STORE);
    const index = store.index('updatedAt');
    const getAllRequest = index.getAll();
    
    getAllRequest.onsuccess = () => {
      // Sort by updatedAt in descending order (newest first)
      const results = getAllRequest.result.sort((a, b) => b.updatedAt - a.updatedAt);
      resolve(results);
    };
    
    getAllRequest.onerror = () => {
      reject(new Error('Error getting sessions'));
    };
    
    transaction.oncomplete = () => {
      db.close();
    };
  });
};

/**
 * Delete a session
 */
export const deleteSession = async (id: string): Promise<boolean> => {
  const db = await initializeDB();
  
  return new Promise((resolve, reject) => {
    const transaction = db.transaction([SESSIONS_STORE], 'readwrite');
    const store = transaction.objectStore(SESSIONS_STORE);
    const deleteRequest = store.delete(id);
    
    deleteRequest.onsuccess = () => {
      resolve(true);
    };
    
    deleteRequest.onerror = () => {
      reject(new Error('Error deleting session'));
    };
    
    transaction.oncomplete = () => {
      db.close();
    };
  });
};

/**
 * Export a session with its requests as JSON
 */
export const exportSession = async (sessionId: string): Promise<string> => {
  const session = await getSession(sessionId);
  
  if (!session) {
    throw new Error('Session not found');
  }
  
  // Get all the requests in the session
  const requests = await Promise.all(
    session.requestIds.map(id => getRequest(id))
  );
  
  // Filter out any null values in case a request was deleted
  const validRequests = requests.filter(req => req !== null) as RequestConfig[];
  
  const exportData = {
    session,
    requests: validRequests
  };
  
  return JSON.stringify(exportData, null, 2);
};

/**
 * Import a session from JSON
 */
export const importSession = async (jsonData: string): Promise<string> => {
  try {
    const data = JSON.parse(jsonData);
    
    if (!data.session || !data.requests || !Array.isArray(data.requests)) {
      throw new Error('Invalid session data format');
    }
    
    // Create new IDs to avoid collisions
    // Session ID will be used in future implementation
    // We'll generate it when needed
    const newRequestIds: string[] = [];
    
    // Save all requests with new IDs
    for (const request of data.requests) {
      const newId = uuidv4();
      newRequestIds.push(newId);
      
      await saveRequest({
        ...request,
        id: newId
      });
    }
    
    // Create the session with new IDs
    const sessionName = `${data.session.name} (Imported)`;
    const sessionDescription = data.session.description || '';
    
    return await createSession(sessionName, sessionDescription, newRequestIds);
  } catch (error) {
    throw new Error(`Failed to import session: ${(error as Error).message}`);
  }
};
