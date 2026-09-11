import express from 'express'
import { runCommand } from './handler'
import { reviewBoundary as guardedBoundary } from './wrapper'

const app = express()
app.post('/run', isAuthorized(), guardedBoundary(runCommand))

declare function isAuthorized (): any
