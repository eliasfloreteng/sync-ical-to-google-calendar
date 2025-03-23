import { initializeApp } from 'firebase/app';
import { getFirestore, collection, getDocs, addDoc, query, where, Firestore } from 'firebase/firestore';
import * as ical from 'ical';

interface CalendarEvent {
	uid: string;
	summary: string;
	description?: string;
	location?: string;
	start: Date;
	end: Date;
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

				// Public iCal URL - this could be stored in environment variables or Firestore
				const icalUrl = env.ICAL_URL;

				// Fetch and parse iCal events
				const icalEvents = await fetchIcalEvents(icalUrl);
				console.log(`Fetched ${Object.keys(icalEvents).length} events from iCal`);

				// Get existing events from Firestore
				const existingEvents = await getExistingEvents(db);
				console.log(`Found ${existingEvents.length} existing events in Firestore`);

				// Find new events
				const newEvents = findNewEvents(icalEvents, existingEvents);
				console.log(`Found ${newEvents.length} new events to sync`);

				if (newEvents.length > 0) {
					// Add new events to Google Calendar
					// Process events serially to avoid race conditions
					for (const event of newEvents) {
						await addEventToGoogleCalendar(event, env);
						await storeEventInFirestore(db, event);
					}
					console.log(`Successfully synced ${newEvents.length} events to Google Calendar`);
				} else {
					console.log('No new events to sync');
				}
			} catch (error) {
				console.error('Error syncing calendars:', error);
			}
		};

		// Use waitUntil to ensure the promise is properly handled
		ctx.waitUntil(mainProcess());
	},
} satisfies ExportedHandler<Env>;

/**
 * Fetches and parses events from an iCal URL
 */
async function fetchIcalEvents(url: string): Promise<Record<string, ical.CalendarComponent>> {
	const response = await fetch(url);
	const data = await response.text();
	return ical.parseICS(data);
}

/**
 * Retrieves existing events from Firestore
 */
async function getExistingEvents(db: Firestore): Promise<CalendarEvent[]> {
	const eventsCollection = collection(db, 'syncedEvents');
	const snapshot = await getDocs(eventsCollection);

	return snapshot.docs.map((doc) => {
		const data = doc.data();
		return {
			uid: data.uid,
			summary: data.summary,
			description: data.description,
			location: data.location,
			start: data.start.toDate(),
			end: data.end.toDate(),
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
 * Gets an access token using the refresh token
 */
async function getAccessToken(env: Env): Promise<string> {
	const tokenUrl = 'https://oauth2.googleapis.com/token';
	const params = new URLSearchParams({
		client_id: env.GOOGLE_CLIENT_ID,
		client_secret: env.GOOGLE_CLIENT_SECRET,
		refresh_token: env.GOOGLE_REFRESH_TOKEN,
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
async function addEventToGoogleCalendar(event: CalendarEvent, env: Env): Promise<void> {
	const calendarId = env.GOOGLE_CALENDAR_ID;

	// Get access token using refresh token
	const accessToken = await getAccessToken(env);

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

	// Check if event already exists
	const q = query(eventsCollection, where('uid', '==', event.uid));
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
			syncedAt: new Date(),
		});

		console.log(`Stored event "${event.summary}" in Firestore`);
	} else {
		console.log(`Event "${event.summary}" already exists in Firestore`);
	}
}
