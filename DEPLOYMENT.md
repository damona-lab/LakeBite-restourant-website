# LakeBite frontend and backend deployment

The frontend is configured in `frontend/api-config.js` to call the Render API at `https://lakebite-restourant-website.onrender.com`. All API calls include credentials, and uploaded `/uploads/...` images are resolved against the backend host.

## Recommended hosting

The backend already serves the files in `frontend/`. The simplest and most reliable setup is to host this repository as the existing Render web service and use its URL for the website. That keeps login cookies and API requests on one origin, including in browsers that restrict third-party cookies.

## Hosting the frontend on a separate domain

1. Deploy the `frontend/` folder as a static site at the root of its domain.
2. In the Render backend service, add `CORS_ORIGINS` with the exact frontend origin, including scheme and optional port, with no path or trailing slash. For example: `https://lakebite.example.com`.
3. For multiple frontend domains, enter comma-separated origins, for example: `https://lakebite.example.com,https://lakebite-preview.example.com`.
4. Redeploy the backend after saving the environment variable, and deploy the frontend files from this repository.
5. Confirm the backend is healthy at `https://lakebite-restourant-website.onrender.com/api/health`.

Do not use `*` for `CORS_ORIGINS`: credentialed login requires explicit origins. Cross-site login cookies can also be blocked by some browsers. For the most consistent admin and customer login, use the backend-served frontend or put the frontend and API behind the same custom domain.

The Render Blueprint declares `CORS_ORIGINS` as a dashboard-supplied value (`sync: false`); the actual frontend domain must be entered in the Render service settings after the hosting domain is known.
