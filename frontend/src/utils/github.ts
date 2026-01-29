import { useAppSettingsStore } from '@/stores'

export const getAcceleratedUrl = (url: string) => {
    if (!url) return url
    const appSettings = useAppSettingsStore()
    const githubProxy = appSettings.app.githubProxy

    if (!githubProxy) return url

    // Check if it's a GitHub URL
    const isGithub =
        url.includes('github.com') ||
        url.includes('raw.githubusercontent.com') ||
        url.includes('githubassets.com')

    if (!isGithub) return url

    const proxy = githubProxy.endsWith('/') ? githubProxy : githubProxy + '/'

    // For raw.githubusercontent.com, some proxies might need special handling, 
    // but usually prepending works.
    return proxy + url
}
