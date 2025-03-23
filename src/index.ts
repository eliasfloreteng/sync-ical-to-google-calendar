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
		const frontendUrl = new URL('https://your-frontend-app.com/auth/callback');
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
