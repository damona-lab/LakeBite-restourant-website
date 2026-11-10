(() => {
  const API_BASE_URL = 'https://lakebite-restourant-website.onrender.com';
  const nativeFetch = window.fetch.bind(window);

  function rewriteAssetUrls(value) {
    if (typeof value === 'string') return value.startsWith('/uploads/') ? `${API_BASE_URL}${value}` : value;
    if (Array.isArray(value)) return value.map(rewriteAssetUrls);
    if (value && typeof value === 'object') {
      for (const key of Object.keys(value)) value[key] = rewriteAssetUrls(value[key]);
    }
    return value;
  }

  window.fetch = async (input, init = {}) => {
    const rawUrl = input instanceof Request ? input.url : String(input);
    const isApiRequest = rawUrl.startsWith('/api/') || rawUrl.startsWith('/uploads/');
    const url = isApiRequest ? `${API_BASE_URL}${rawUrl}` : rawUrl;
    const options = isApiRequest ? { ...init, credentials: 'include' } : init;
    const response = await nativeFetch(url, options);
    if (isApiRequest && response.headers.get('content-type')?.includes('application/json')) {
      const originalJson = response.json.bind(response);
      response.json = async () => rewriteAssetUrls(await originalJson());
    }
    return response;
  };
})();
