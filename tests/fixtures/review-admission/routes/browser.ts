import { environment as appEnvironment } from '../environments/environment'
import { NavigationService as AppNavigationService } from '../services/navigation.service'

export function fixedNavigation () {
  window.location.replace(appEnvironment.hostServer + '/profile')
}

export function dynamicNavigation (destination: string) {
  window.location.replace(destination)
}

export function dynamicSuffix (segment: string) {
  window.location.replace(appEnvironment.hostServer + segment)
}

export function shadowedNavigation (appEnvironment: { hostServer: string }) {
  window.location.replace(appEnvironment.hostServer + '/profile')
}

export function locallyShadowedNavigation (runtimeConfig: { hostServer: string }) {
  const appEnvironment = runtimeConfig
  window.location.replace(appEnvironment.hostServer + '/profile')
}

export class NavigationController {
  private readonly navigationService = inject(AppNavigationService)

  fixedServiceNavigation (identifier: string) {
    const redirectUrl = `${this.navigationService.hostServer}/files/report_${identifier}.pdf`
    window.open(redirectUrl, '_blank')
  }

  dynamicServiceNavigation (base: string, identifier: string) {
    const redirectUrl = `${base}/files/report_${identifier}.pdf`
    window.open(redirectUrl, '_blank')
  }
}
