import { initializeApp } from 'firebase/app';
import { getFirestore, collection, getDocs, addDoc, query, where, Firestore, getDoc, doc, setDoc, deleteDoc } from 'firebase/firestore';
import * as ical from 'ical';

interface CalendarEvent {
	uid: string;
	summary: string;
	description?: string;
	location?: string;
	start: Date;
	end: Date;
	userId?: string;
}

interface UserConfig {
	userId: string;
	icalUrl: string;
	googleCalendarId: string;
	googleRefreshToken: string;
	enabled: boolean;
}

export default {
	async scheduled(event, env, ctx): Promise<void> {
		console.log(`Sync triggered at ${event.cron}`);

		// Create a main promise that encompasses all the work
		const mainProcess = async () => {
			try {
				// Initialize Firebase
				const firebaseConfig = {
					apiKey: env.FIREBASE_APIKEY,
					authDomain: env.FIREBASE_AUTHDOMAIN,
					projectId: env.FIREBASE_PROJECTID,
					storageBucket: env.FIREBASE_STORAGEBUCKET,
					messagingSenderId: env.FIREBASE_MESSAGINGSENDERID,
					appId: env.FIREBASE_APPID,
				};

				const app = initializeApp(firebaseConfig);
				const db = getFirestore(app);

				// Get all users from Firestore
				const users = await getUserConfigs(db);
				console.log(`Found ${users.length} users with calendar sync configurations`);

				// Process each user's calendars
				for (const userConfig of users) {
					if (!userConfig.enabled) {
						console.log(`Skipping disabled user ${userConfig.userId}`);
						continue;
					}

					console.log(`Processing calendar sync for user ${userConfig.userId}`);
					await processUserCalendar(db, userConfig, env);
				}
			} catch (error) {
				console.error('Error syncing calendars:', error);
			}
		};

		await mainProcess();
	},

	async fetch(request, env, ctx): Promise<Response> {
		try {
			const url = new URL(request.url);

			// Initialize Firebase
			const firebaseConfig = {
				apiKey: env.FIREBASE_APIKEY,
				authDomain: env.FIREBASE_AUTHDOMAIN,
				projectId: env.FIREBASE_PROJECTID,
				storageBucket: env.FIREBASE_STORAGEBUCKET,
				messagingSenderId: env.FIREBASE_MESSAGINGSENDERID,
				appId: env.FIREBASE_APPID,
			};

			const app = initializeApp(firebaseConfig);
			const db = getFirestore(app);

			// Handle CORS preflight requests
			if (request.method === 'OPTIONS') {
				return new Response(null, {
					headers: {
						'Access-Control-Allow-Origin': '*',
						'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
						'Access-Control-Allow-Headers': 'Content-Type, Authorization',
					},
				});
			}

			// Serve HTML page for the root route
			if (url.pathname === '/' || url.pathname === '') {
				return new Response(getIndexHtml(), {
					headers: {
						'Content-Type': 'text/html',
					},
				});
			}

			// Handle Google OAuth callback
			if (url.pathname === '/auth/google/callback') {
				return handleGoogleCallback(request, env, db);
			}

			// Handle login with Google
			if (url.pathname === '/auth/google') {
				return handleGoogleAuth(request, env);
			}

			// Handle user API endpoints
			if (url.pathname.startsWith('/api/user')) {
				// Verify authentication token
				const token = request.headers.get('Authorization')?.split('Bearer ')[1];
				if (!token) {
					return new Response(JSON.stringify({ error: 'Authorization token required' }), {
						status: 401,
						headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
					});
				}

				// Verify the Google token and get user info
				const userData = await verifyGoogleToken(token, env);
				if (!userData) {
					return new Response(JSON.stringify({ error: 'Invalid token' }), {
						status: 401,
						headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
					});
				}

				// Register user
				if (url.pathname === '/api/user/register' && request.method === 'POST') {
					return handleUserRegistration(request, db, userData);
				}

				// Delete user
				if (url.pathname === '/api/user/delete' && request.method === 'DELETE') {
					return handleUserDeletion(db, userData.id);
				}

				// Get user status
				if (url.pathname === '/api/user/status' && request.method === 'GET') {
					return handleUserStatus(db, userData.id);
				}
			}

			// Return 404 for any other routes
			return new Response(JSON.stringify({ error: 'Not found' }), {
				status: 404,
				headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
			});
		} catch (error) {
			console.error('Error processing request:', error);
			return new Response(JSON.stringify({ error: 'Internal server error' }), {
				status: 500,
				headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
			});
		}
	},
} satisfies ExportedHandler<Env>;

/**
 * Handles the initial Google authentication redirect
 */
function handleGoogleAuth(request: Request, env: Env): Response {
	const redirectUrl = new URL(request.url);
	redirectUrl.pathname = '/auth/google/callback';

	const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
	authUrl.searchParams.append('client_id', env.GOOGLE_CLIENT_ID);
	authUrl.searchParams.append('redirect_uri', redirectUrl.toString());
	authUrl.searchParams.append('response_type', 'code');
	authUrl.searchParams.append(
		'scope',
		'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/calendar'
	);
	authUrl.searchParams.append('access_type', 'offline');
	authUrl.searchParams.append('prompt', 'consent');

	return Response.redirect(authUrl.toString(), 302);
}

/**
 * Handles the Google OAuth callback
 */
async function handleGoogleCallback(request: Request, env: Env, db: Firestore): Promise<Response> {
	const url = new URL(request.url);
	const code = url.searchParams.get('code');

	if (!code) {
		return new Response(JSON.stringify({ error: 'Authorization code missing' }), {
			status: 400,
			headers: { 'Content-Type': 'application/json' },
		});
	}

	try {
		// Exchange code for tokens
		const redirectUrl = new URL(request.url);
		redirectUrl.pathname = '/auth/google/callback';
		redirectUrl.search = '';

		const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				code,
				client_id: env.GOOGLE_CLIENT_ID,
				client_secret: env.GOOGLE_CLIENT_SECRET,
				redirect_uri: redirectUrl.toString(),
				grant_type: 'authorization_code',
			}).toString(),
		});

		if (!tokenResponse.ok) {
			const error = await tokenResponse.text();
			throw new Error(`Token exchange failed: ${error}`);
		}

		// Define the type for Google OAuth token response
		interface GoogleOAuthTokenResponse {
			access_token: string;
			id_token: string;
			expires_in: number;
			refresh_token?: string;
			token_type: string;
			scope: string;
		}

		const tokenData = (await tokenResponse.json()) as GoogleOAuthTokenResponse;

		// Get user info
		const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
			headers: { Authorization: `Bearer ${tokenData.access_token}` },
		});

		if (!userInfoResponse.ok) {
			throw new Error('Failed to fetch user info');
		}

		// Define the type for Google user info response
		interface GoogleUserInfo {
			sub: string;
			name: string;
			email: string;
			picture: string;
			email_verified: boolean;
		}

		const userInfo = (await userInfoResponse.json()) as GoogleUserInfo;

		// Create or update user document
		const userDocRef = doc(db, 'users', userInfo.sub);
		const userDoc = await getDoc(userDocRef);

		if (!userDoc.exists()) {
			// New user, just store the refresh token
			await setDoc(userDocRef, {
				email: userInfo.email,
				name: userInfo.name,
				picture: userInfo.picture,
				googleRefreshToken: tokenData.refresh_token,
				enabled: false, // Not fully registered yet
				createdAt: new Date(),
			});
		} else {
			// Existing user, update refresh token if provided
			const userData = userDoc.data();
			await setDoc(userDocRef, {
				...userData,
				email: userInfo.email,
				name: userInfo.name,
				picture: userInfo.picture,
				googleRefreshToken: tokenData.refresh_token || userData.googleRefreshToken,
				updatedAt: new Date(),
			});
		}

		// Redirect to frontend with access token and ID token
		const frontendUrl = new URL(request.url);
		frontendUrl.searchParams.append('access_token', tokenData.access_token);
		frontendUrl.searchParams.append('id_token', tokenData.id_token);
		return Response.redirect(frontendUrl.toString(), 302);
	} catch (error) {
		console.error('Google OAuth error:', error);
		return new Response(JSON.stringify({ error: 'Authentication failed' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json' },
		});
	}
}

/**
 * Verifies a Google ID token and returns user data
 */
async function verifyGoogleToken(token: string, env: Env): Promise<{ id: string; email: string } | null> {
	try {
		const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${token}`);

		if (!response.ok) {
			return null;
		}

		// Define interface for Google ID token verification response
		interface GoogleTokenInfo {
			iss: string; // The JWT issuer
			azp: string; // The application that was issued the token
			aud: string; // The client ID of the app that requested the token
			sub: string; // A unique identifier for the user
			email: string; // The user's email address
			email_verified: boolean; // Whether the email is verified
			at_hash?: string; // Access token hash
			name?: string; // The user's full name
			picture?: string; // The user's profile picture URL
			given_name?: string; // The user's first name
			family_name?: string; // The user's last name
			locale?: string; // The user's locale
			iat: number; // Issued at time (seconds since Unix epoch)
			exp: number; // Expiration time (seconds since Unix epoch)
		}

		const data = (await response.json()) as GoogleTokenInfo;

		// Verify that the token was issued for our client
		if (data.aud !== env.GOOGLE_CLIENT_ID) {
			return null;
		}

		return {
			id: data.sub,
			email: data.email,
		};
	} catch (error) {
		console.error('Token verification error:', error);
		return null;
	}
}

/**
 * Handles user registration
 */
interface UserRegistrationData {
	icalUrl: string;
	googleCalendarId: string;
	[key: string]: any; // For any additional fields
}

async function handleUserRegistration(request: Request, db: Firestore, userData: { id: string; email: string }): Promise<Response> {
	try {
		const data = (await request.json()) as UserRegistrationData;

		// Validate request body
		if (!data.icalUrl || !data.googleCalendarId) {
			return new Response(JSON.stringify({ error: 'Missing required fields' }), {
				status: 400,
				headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
			});
		}

		// Update user document
		const userDocRef = doc(db, 'users', userData.id);
		const userDoc = await getDoc(userDocRef);

		if (!userDoc.exists()) {
			return new Response(JSON.stringify({ error: 'User not found' }), {
				status: 404,
				headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
			});
		}

		const existingData = userDoc.data();

		await setDoc(userDocRef, {
			...existingData,
			icalUrl: data.icalUrl,
			googleCalendarId: data.googleCalendarId,
			enabled: true,
			updatedAt: new Date(),
		});

		return new Response(JSON.stringify({ success: true, message: 'User registered successfully' }), {
			status: 200,
			headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
		});
	} catch (error) {
		console.error('User registration error:', error);
		return new Response(JSON.stringify({ error: 'Failed to register user' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
		});
	}
}

/**
 * Handles user deletion
 */
async function handleUserDeletion(db: Firestore, userId: string): Promise<Response> {
	try {
		// Delete user document
		const userDocRef = doc(db, 'users', userId);
		await deleteDoc(userDocRef);

		// Delete associated synced events
		const eventsCollection = collection(db, 'syncedEvents');
		const q = query(eventsCollection, where('userId', '==', userId));
		const querySnapshot = await getDocs(q);

		const deletionPromises = querySnapshot.docs.map((docSnapshot) => deleteDoc(docSnapshot.ref));
		await Promise.all(deletionPromises);

		return new Response(JSON.stringify({ success: true, message: 'User and associated data deleted' }), {
			status: 200,
			headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
		});
	} catch (error) {
		console.error('User deletion error:', error);
		return new Response(JSON.stringify({ error: 'Failed to delete user' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
		});
	}
}

/**
 * Handles user status check
 */
async function handleUserStatus(db: Firestore, userId: string): Promise<Response> {
	try {
		const userDocRef = doc(db, 'users', userId);
		const userDoc = await getDoc(userDocRef);

		if (!userDoc.exists()) {
			return new Response(JSON.stringify({ registered: false }), {
				status: 200,
				headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
			});
		}

		const userData = userDoc.data();

		return new Response(
			JSON.stringify({
				registered: true,
				enabled: userData.enabled === true,
				icalUrl: userData.icalUrl,
				googleCalendarId: userData.googleCalendarId,
				email: userData.email,
			}),
			{
				status: 200,
				headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
			}
		);
	} catch (error) {
		console.error('User status error:', error);
		return new Response(JSON.stringify({ error: 'Failed to get user status' }), {
			status: 500,
			headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
		});
	}
}

/**
 * Retrieves all user configurations from Firestore
 */
async function getUserConfigs(db: Firestore): Promise<UserConfig[]> {
	const usersCollection = collection(db, 'users');
	const snapshot = await getDocs(usersCollection);

	return snapshot.docs.map((doc) => {
		const data = doc.data();
		return {
			userId: doc.id,
			icalUrl: data.icalUrl,
			googleCalendarId: data.googleCalendarId,
			googleRefreshToken: data.googleRefreshToken,
			enabled: data.enabled !== false, // default to true if not specified
		};
	});
}

/**
 * Process calendar sync for a single user
 */
async function processUserCalendar(db: Firestore, userConfig: UserConfig, env: Env): Promise<void> {
	try {
		// Fetch and parse iCal events
		const icalEvents = await fetchIcalEvents(userConfig.icalUrl);
		console.log(`Fetched ${Object.keys(icalEvents).length} events from iCal for user ${userConfig.userId}`);

		// Get existing events from Firestore for this user
		const existingEvents = await getExistingEvents(db, userConfig.userId);
		console.log(`Found ${existingEvents.length} existing events in Firestore for user ${userConfig.userId}`);

		// Find new events
		const newEvents = findNewEvents(icalEvents, existingEvents);
		console.log(`Found ${newEvents.length} new events to sync for user ${userConfig.userId}`);

		if (newEvents.length > 0) {
			// Process events serially to avoid race conditions
			for (const event of newEvents) {
				// Add user ID to the event
				event.userId = userConfig.userId;

				// Add event to Google Calendar
				await addEventToGoogleCalendar(event, userConfig, env);

				// Store event in Firestore
				await storeEventInFirestore(db, event);
			}
			console.log(`Successfully synced ${newEvents.length} events to Google Calendar for user ${userConfig.userId}`);
		} else {
			console.log(`No new events to sync for user ${userConfig.userId}`);
		}
	} catch (error) {
		console.error(`Error processing calendar for user ${userConfig.userId}:`, error);
	}
}

/**
 * Fetches and parses events from an iCal URL
 */
async function fetchIcalEvents(url: string): Promise<Record<string, ical.CalendarComponent>> {
	const response = await fetch(url);
	const data = await response.text();
	return ical.parseICS(data);
}

/**
 * Retrieves existing events from Firestore for a specific user
 */
async function getExistingEvents(db: Firestore, userId: string): Promise<CalendarEvent[]> {
	const eventsCollection = collection(db, 'syncedEvents');
	const q = query(eventsCollection, where('userId', '==', userId));
	const snapshot = await getDocs(q);

	return snapshot.docs.map((doc) => {
		const data = doc.data();
		return {
			uid: data.uid,
			summary: data.summary,
			description: data.description,
			location: data.location,
			start: data.start.toDate(),
			end: data.end.toDate(),
			userId: data.userId,
		};
	});
}

/**
 * Identifies new events that need to be synced
 */
function findNewEvents(icalEvents: Record<string, ical.CalendarComponent>, existingEvents: CalendarEvent[]): CalendarEvent[] {
	const existingUids = new Set(existingEvents.map((event) => event.uid));
	const newEvents: CalendarEvent[] = [];

	for (const [uid, event] of Object.entries(icalEvents)) {
		// Skip non-VEVENT items
		if (event.type !== 'VEVENT') continue;

		// Skip events without required properties
		if (!event.summary || !event.start || !event.end) continue;

		// Skip already synced events
		if (existingUids.has(uid)) continue;

		newEvents.push({
			uid,
			summary: event.summary,
			description: event.description,
			location: event.location,
			start: event.start,
			end: event.end,
		});
	}

	return newEvents;
}

/**
 * Gets an access token using the user's refresh token
 */
async function getAccessToken(userConfig: UserConfig, env: Env): Promise<string> {
	const tokenUrl = 'https://oauth2.googleapis.com/token';
	const params = new URLSearchParams({
		client_id: env.GOOGLE_CLIENT_ID,
		client_secret: env.GOOGLE_CLIENT_SECRET,
		refresh_token: userConfig.googleRefreshToken,
		grant_type: 'refresh_token',
	});

	const response = await fetch(tokenUrl, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
		},
		body: params.toString(),
	});

	if (!response.ok) {
		const errorData = await response.json();
		throw new Error(`Failed to get access token: ${JSON.stringify(errorData)}`);
	}

	interface TokenResponse {
		access_token: string;
		expires_in: number;
		token_type: string;
	}

	const data = (await response.json()) as TokenResponse;
	return data.access_token;
}

/**
 * Adds an event to Google Calendar using the Calendar API
 */
async function addEventToGoogleCalendar(event: CalendarEvent, userConfig: UserConfig, env: Env): Promise<void> {
	const calendarId = userConfig.googleCalendarId;

	// Get access token using user's refresh token
	const accessToken = await getAccessToken(userConfig, env);

	// Format the event for Google Calendar API
	const googleEvent = {
		summary: event.summary,
		description: event.description || '',
		location: event.location || '',
		start: {
			dateTime: event.start.toISOString(),
			timeZone: 'UTC',
		},
		end: {
			dateTime: event.end.toISOString(),
			timeZone: 'UTC',
		},
	};

	// Add event to Google Calendar using OAuth 2.0 authentication
	const response = await fetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events`, {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${accessToken}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(googleEvent),
	});

	if (!response.ok) {
		const errorData = await response.json();
		throw new Error(`Failed to add event to Google Calendar: ${JSON.stringify(errorData)}`);
	}

	console.log(`Added event "${event.summary}" to Google Calendar`);
}

/**
 * Stores a synced event in Firestore
 */
async function storeEventInFirestore(db: Firestore, event: CalendarEvent): Promise<void> {
	const eventsCollection = collection(db, 'syncedEvents');

	// Check if event already exists for this user
	const q = query(eventsCollection, where('uid', '==', event.uid), where('userId', '==', event.userId));
	const querySnapshot = await getDocs(q);

	if (querySnapshot.empty) {
		// Add new event to Firestore
		await addDoc(eventsCollection, {
			uid: event.uid,
			summary: event.summary,
			description: event.description || '',
			location: event.location || '',
			start: event.start,
			end: event.end,
			userId: event.userId,
			syncedAt: new Date(),
		});

		console.log(`Stored event "${event.summary}" in Firestore for user ${event.userId}`);
	} else {
		console.log(`Event "${event.summary}" already exists in Firestore for user ${event.userId}`);
	}
}

/**
 * Returns the HTML content for the index page
 */
function getIndexHtml(): string {
	return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iCal to Google Calendar Sync</title>
    <style>
        :root {
            --primary-color: #4285F4;
            --secondary-color: #34A853;
            --accent-color: #EA4335;
            --light-gray: #f8f9fa;
            --dark-gray: #202124;
        }
        
        body {
            font-family: 'Roboto', Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            color: #333;
            background-color: var(--light-gray);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        header {
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 1rem 0;
            margin-bottom: 2rem;
        }
        
        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--primary-color);
        }
        
        .hero {
            background-color: white;
            border-radius: 8px;
            padding: 3rem;
            margin-bottom: 2rem;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        h1 {
            color: var(--dark-gray);
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }
        
        .subtitle {
            color: #5f6368;
            font-size: 1.25rem;
            margin-bottom: 2rem;
        }
        
        .btn {
            display: inline-block;
            background-color: var(--primary-color);
            color: white;
            padding: 12px 24px;
            font-size: 16px;
            border-radius: 4px;
            text-decoration: none;
            font-weight: 500;
            transition: background-color 0.3s;
            border: none;
            cursor: pointer;
        }
        
        .btn:hover {
            background-color: #3367D6;
        }
        
        .btn-google {
            background-color: white;
            color: #757575;
            border: 1px solid #dadce0;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 10px 24px;
        }
        
        .btn-google:hover {
            background-color: #f8f9fa;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
        }
        
        .btn-google img {
            margin-right: 10px;
            width: 18px;
            height: 18px;
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }
        
        .feature-card {
            background-color: white;
            border-radius: 8px;
            padding: 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .feature-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }
        
        .feature-icon {
            font-size: 2rem;
            color: var(--primary-color);
            margin-bottom: 1rem;
        }
        
        .feature-title {
            font-size: 1.25rem;
            font-weight: 500;
            margin-bottom: 1rem;
            color: var(--dark-gray);
        }
        
        footer {
            background-color: var(--dark-gray);
            color: white;
            padding: 2rem 0;
            margin-top: 3rem;
        }
        
        .dashboard {
            display: none;
            background-color: white;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        
        .dashboard-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }
        
        .form-group {
            margin-bottom: 1.5rem;
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        
        input[type="text"], input[type="url"] {
            width: 100%;
            padding: 10px;
            border-radius: 4px;
            border: 1px solid #dadce0;
            font-size: 16px;
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            margin-bottom: 1rem;
        }
        
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 10px;
        }
        
        .status-dot.active {
            background-color: var(--secondary-color);
        }
        
        .status-dot.inactive {
            background-color: var(--accent-color);
        }
        
        .loading {
            display: none;
            text-align: center;
            padding: 2rem;
        }
        
        .spinner {
            border: 4px solid rgba(0, 0, 0, 0.1);
            border-radius: 50%;
            border-top: 4px solid var(--primary-color);
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 1rem;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .error-message {
            color: var(--accent-color);
            background-color: rgba(234, 67, 53, 0.1);
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1rem;
            display: none;
        }
        
        .success-message {
            color: var(--secondary-color);
            background-color: rgba(52, 168, 83, 0.1);
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1rem;
            display: none;
        }
    </style>
</head>
<body>
    <header>
        <div class="container header-content">
            <div class="logo">iCal Sync</div>
            <div id="user-info" style="display: none;">
                <span id="user-email"></span>
                <button id="logout-btn" class="btn" style="background-color: #EA4335;">Logout</button>
            </div>
        </div>
    </header>

    <div class="container">
        <div id="login-section" class="hero">
            <h1>Sync Your iCal to Google Calendar</h1>
            <p class="subtitle">Automatically sync events from any iCal feed to your Google Calendar</p>
            <button id="login-btn" class="btn btn-google">
                <img src="https://upload.wikimedia.org/wikipedia/commons/5/53/Google_%22G%22_Logo.svg" alt="Google Logo">
                Sign in with Google
            </button>
        </div>

        <div id="dashboard" class="dashboard">
            <div class="dashboard-header">
                <h2>Your Sync Dashboard</h2>
                <div class="status-indicator">
                    <div id="status-dot" class="status-dot inactive"></div>
                    <span id="status-text">Inactive</span>
                </div>
            </div>

            <div id="error-message" class="error-message"></div>
            <div id="success-message" class="success-message"></div>

            <form id="sync-form">
                <div class="form-group">
                    <label for="ical-url">iCal URL</label>
                    <input type="url" id="ical-url" name="icalUrl" placeholder="https://example.com/calendar.ics" required>
                </div>
                <div class="form-group">
                    <label for="google-calendar-id">Google Calendar ID</label>
                    <input type="text" id="google-calendar-id" name="googleCalendarId" placeholder="primary or calendar ID" required>
                    <small style="display: block; margin-top: 5px; color: #5f6368;">
                        Use 'primary' for your main calendar, or find the calendar ID in your Google Calendar settings
                    </small>
                </div>
                <div class="form-group">
                    <button type="submit" id="save-btn" class="btn">Save Configuration</button>
                    <button type="button" id="delete-btn" class="btn" style="background-color: #EA4335;">Delete Configuration</button>
                </div>
            </form>
        </div>

        <div id="loading" class="loading">
            <div class="spinner"></div>
            <p>Loading your information...</p>
        </div>

        <div class="features">
            <div class="feature-card">
                <div class="feature-icon">🔄</div>
                <h3 class="feature-title">Automatic Syncing</h3>
                <p>Events automatically sync from your iCal feed to Google Calendar daily</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">🔒</div>
                <h3 class="feature-title">Secure Authentication</h3>
                <p>Uses Google's secure OAuth 2.0 for authentication and calendar access</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon">⚙️</div>
                <h3 class="feature-title">Easy Setup</h3>
                <p>Just paste your iCal URL, choose a calendar, and you're ready to go</p>
            </div>
        </div>
    </div>

    <footer>
        <div class="container">
            <p>&copy; 2023 iCal Sync Service. All rights reserved.</p>
        </div>
    </footer>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const loginBtn = document.getElementById('login-btn');
            const logoutBtn = document.getElementById('logout-btn');
            const loginSection = document.getElementById('login-section');
            const dashboard = document.getElementById('dashboard');
            const userInfo = document.getElementById('user-info');
            const userEmail = document.getElementById('user-email');
            const loading = document.getElementById('loading');
            const statusDot = document.getElementById('status-dot');
            const statusText = document.getElementById('status-text');
            const syncForm = document.getElementById('sync-form');
            const deleteBtn = document.getElementById('delete-btn');
            const errorMessage = document.getElementById('error-message');
            const successMessage = document.getElementById('success-message');
            
            // Check if user is logged in
            const checkAuth = () => {
                const token = localStorage.getItem('id_token');
                if (token) {
                    return true;
                }
                return false;
            };
            
            // Show loading state
            const showLoading = () => {
                loading.style.display = 'block';
                loginSection.style.display = 'none';
                dashboard.style.display = 'none';
            };
            
            // Hide loading state
            const hideLoading = () => {
                loading.style.display = 'none';
            };
            
            // Show error message
            const showError = (message) => {
                errorMessage.textContent = message;
                errorMessage.style.display = 'block';
                setTimeout(() => {
                    errorMessage.style.display = 'none';
                }, 5000);
            };
            
            // Show success message
            const showSuccess = (message) => {
                successMessage.textContent = message;
                successMessage.style.display = 'block';
                setTimeout(() => {
                    successMessage.style.display = 'none';
                }, 5000);
            };
            
            // Get user status from API
            const getUserStatus = async () => {
                const token = localStorage.getItem('id_token');
                if (!token) return;
                
                try {
                    const response = await fetch('/api/user/status', {
                        headers: {
                            'Authorization': 'Bearer ' + token
                        }
                    });
                    
                    if (!response.ok) {
                        if (response.status === 401) {
                            // Token is invalid or expired
                            localStorage.removeItem('id_token');
                            localStorage.removeItem('access_token');
                            showLoginUI();
                            return;
                        }
                        throw new Error('Failed to get user status');
                    }
                    
                    const data = await response.json();
                    
                    if (data.registered) {
                        // User is registered, show dashboard with data
                        document.getElementById('ical-url').value = data.icalUrl || '';
                        document.getElementById('google-calendar-id').value = data.googleCalendarId || '';
                        userEmail.textContent = data.email;
                        
                        if (data.enabled) {
                            statusDot.classList.remove('inactive');
                            statusDot.classList.add('active');
                            statusText.textContent = 'Active';
                        } else {
                            statusDot.classList.remove('active');
                            statusDot.classList.add('inactive');
                            statusText.textContent = 'Inactive';
                        }
                        
                        showDashboardUI();
                    } else {
                        // User authenticated but not fully registered
                        userEmail.textContent = 'New User';
                        showDashboardUI();
                    }
                } catch (error) {
                    console.error('Error fetching user status:', error);
                    showError('Failed to load your information. Please try again.');
                    showLoginUI();
                }
            };
            
            // Show login UI
            const showLoginUI = () => {
                loginSection.style.display = 'block';
                dashboard.style.display = 'none';
                userInfo.style.display = 'none';
                hideLoading();
            };
            
            // Show dashboard UI
            const showDashboardUI = () => {
                loginSection.style.display = 'none';
                dashboard.style.display = 'block';
                userInfo.style.display = 'flex';
                hideLoading();
            };
            
            // Initialize the UI based on auth state
            const initializeUI = () => {
                showLoading();
                if (checkAuth()) {
                    getUserStatus();
                } else {
                    showLoginUI();
                }
            };
            
            // Handle login button click
            loginBtn.addEventListener('click', () => {
                window.location.href = '/auth/google';
            });
            
            // Handle logout button click
            logoutBtn.addEventListener('click', () => {
                localStorage.removeItem('id_token');
                localStorage.removeItem('access_token');
                showLoginUI();
            });
            
            // Handle form submission
            syncForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                showLoading();
                
                const token = localStorage.getItem('id_token');
                if (!token) {
                    showLoginUI();
                    return;
                }
                
                const formData = new FormData(syncForm);
                const data = {
                    icalUrl: formData.get('icalUrl'),
                    googleCalendarId: formData.get('googleCalendarId')
                };
                
                try {
                    const response = await fetch('/api/user/register', {
                        method: 'POST',
                        headers: {
                            'Authorization': 'Bearer ' + token,
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(data)
                    });
                    
                    if (!response.ok) {
                        throw new Error('Failed to save configuration');
                    }
                    
                    showSuccess('Configuration saved successfully!');
                    getUserStatus(); // Refresh the UI with updated data
                } catch (error) {
                    console.error('Error saving configuration:', error);
                    hideLoading();
                    showError('Failed to save configuration. Please try again.');
                }
            });
            
            // Handle delete button click
            deleteBtn.addEventListener('click', async () => {
                if (!confirm('Are you sure you want to delete your configuration? This will stop all future syncing.')) {
                    return;
                }
                
                showLoading();
                
                const token = localStorage.getItem('id_token');
                if (!token) {
                    showLoginUI();
                    return;
                }
                
                try {
                    const response = await fetch('/api/user/delete', {
                        method: 'DELETE',
                        headers: {
                            'Authorization': 'Bearer ' + token
                        }
                    });
                    
                    if (!response.ok) {
                        throw new Error('Failed to delete configuration');
                    }
                    
                    showSuccess('Configuration deleted successfully!');
                    // Reset form
                    syncForm.reset();
                    statusDot.classList.remove('active');
                    statusDot.classList.add('inactive');
                    statusText.textContent = 'Inactive';
                    hideLoading();
                } catch (error) {
                    console.error('Error deleting configuration:', error);
                    hideLoading();
                    showError('Failed to delete configuration. Please try again.');
                }
            });
            
            // Check for authentication callback
            const urlParams = new URLSearchParams(window.location.search);
            const accessToken = urlParams.get('access_token');
            const idToken = urlParams.get('id_token');
            
            if (accessToken && idToken) {
                // Store tokens
                localStorage.setItem('access_token', accessToken);
                localStorage.setItem('id_token', idToken);
                
                // Remove query parameters from URL
                const url = new URL(window.location.href);
                url.search = '';
                window.history.replaceState({}, document.title, url.toString());
                
                // Initialize UI
                initializeUI();
            } else {
                // Normal initialization
                initializeUI();
            }
        });
    </script>
</body>
</html>
	`;
}
