import { NextResponse } from 'next/server';

const FASTAPI_URL = process.env.FASTAPI_URL || 'http://127.0.0.1:8000';

export async function POST(request: Request) {
  try {
    const body = await request.json();
    
    // Proxy the request to our Python FastAPI backend
    const response = await fetch(`${FASTAPI_URL}/tasks`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    const data = await response.json();
    return NextResponse.json(data, { status: response.status });
  } catch (error) {
    console.error('Error proxying task to FastAPI:', error);
    return NextResponse.json(
      { error: 'Failed to communicate with agent backend' },
      { status: 500 }
    );
  }
}
