import { NextResponse } from 'next/server';

const FASTAPI_URL = process.env.FASTAPI_URL || 'http://127.0.0.1:8000';

async function forwardRequest(request: Request, method: string) {
  const { searchParams } = new URL(request.url);
  const path = searchParams.get('path');

  if (!path) {
    return NextResponse.json({ error: 'No path specified' }, { status: 400 });
  }

  try {
    const headers: HeadersInit = {};
    const contentType = request.headers.get('content-type');
    if (contentType) headers['Content-Type'] = contentType;

    const fetchOptions: RequestInit = { method };
    if (method !== 'GET' && method !== 'DELETE') {
      fetchOptions.body = await request.text();
      fetchOptions.headers = { 'Content-Type': 'application/json' };
    }

    const response = await fetch(`${FASTAPI_URL}/${path}`, fetchOptions);
    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error(`Error proxying ${method} to backend path ${path}:`, error);
    return NextResponse.json(
      { error: 'Failed to communicate with backend' },
      { status: 500 }
    );
  }
}

export async function GET(request: Request) {
  return forwardRequest(request, 'GET');
}

export async function POST(request: Request) {
  return forwardRequest(request, 'POST');
}

export async function DELETE(request: Request) {
  return forwardRequest(request, 'DELETE');
}
