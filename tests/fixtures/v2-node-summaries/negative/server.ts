import express from 'express'
import { safeHandlers } from './handler'
import { loggingOnly } from './wrapper'

const app = express()
app.post('/safe', loggingOnly(safeHandlers))
