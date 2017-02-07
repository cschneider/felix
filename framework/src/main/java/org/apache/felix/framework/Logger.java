/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.felix.framework;

import java.util.logging.Level;

import org.osgi.framework.Bundle;
import org.osgi.framework.BundleException;
import org.osgi.framework.ServiceReference;

/**
 * <p>
 * This class mimics the standard OSGi <tt>LogService</tt> interface. An
 * instance of this class is used by the framework for all logging. By default
 * this class logs messages to standard out. The log level can be set to
 * control the amount of logging performed, where a higher number results in
 * more logging. A log level of zero turns off logging completely.
 * </p>
 * <p>
 * The log levels match those specified in the OSGi Log Service (i.e., 1 = error,
 * 2 = warning, 3 = information, and 4 = debug). The default value is 1.
 * </p>
**/
@SuppressWarnings("rawtypes")
public class Logger extends org.apache.felix.resolver.Logger
{
    private java.util.logging.Logger juLogger;

    public Logger() {
        this(LoggerType.stdout);
    }

    public Logger(LoggerType loggerType)
    {
        super(LOG_ERROR);
        juLogger = loggerType == LoggerType.jul ? java.util.logging.Logger.getLogger("org.apache.felix") : null;
    }

    public final void log(ServiceReference sr, int level, String msg)
    {
        _log(null, sr, level, msg, null);
    }

    public final void log(ServiceReference sr, int level, String msg, Throwable throwable)
    {
        _log(null, sr, level, msg, throwable);
    }

    public final void log(Bundle bundle, int level, String msg)
    {
        _log(bundle, null, level, msg, null);
    }

    public final void log(Bundle bundle, int level, String msg, Throwable throwable)
    {
        _log(bundle, null, level, msg, throwable);
    }

    protected void _log(
            Bundle bundle, ServiceReference sr, int level,
            String msg, Throwable throwable)
    {
        if (getLogLevel() >= level)
        {
            // Default logging action.
            doLog(bundle, sr, level, msg, throwable);
        }
    }

    protected void doLog(
        Bundle bundle, ServiceReference sr, int level,
        String msg, Throwable throwable)
    {
        StringBuilder s = new StringBuilder();
        if (sr != null)
        {
            s.append("SvcRef ").append(sr).append(" ").append(msg);
        }
        else if (bundle != null)
        {
            s.append("Bundle ").append(bundle.toString()).append(" ").append(msg);
        }
        else
        {
            s.append(msg);
        }
        if (throwable != null)
        {
            s.append(" (").append(throwable).append(")");
        }
        doLog(level, s.toString(), throwable);
    }

    protected void doLog(int level, String msg, Throwable throwable)
    {
        if (juLogger != null)
        {
            juLogger.log(getLevel(level), msg, throwable);
        }
        else
        {
            doLogOut(level, msg, throwable);
        }
    }

    private Level getLevel(int level)
    {
        switch (level) {
            case LOG_ERROR:
                return Level.SEVERE;
            case LOG_WARNING:
                return Level.WARNING;
            case LOG_INFO:
                return Level.INFO;
            case LOG_DEBUG:
                return Level.FINE;
            default:
                return Level.FINEST;
        }
    }

    protected void doLogOut(int level, String s, Throwable throwable)
    {
        switch (level)
        {
            case LOG_DEBUG:
                System.out.println("DEBUG: " + s);
                break;
            case LOG_ERROR:
                System.out.println("ERROR: " + s);
                if (throwable != null)
                {
                    if ((throwable instanceof BundleException) &&
                        (((BundleException) throwable).getNestedException() != null))
                    {
                        throwable = ((BundleException) throwable).getNestedException();
                    }
                    throwable.printStackTrace();
                }
                break;
            case LOG_INFO:
                System.out.println("INFO: " + s);
                break;
            case LOG_WARNING:
                System.out.println("WARNING: " + s);
                break;
            default:
                System.out.println("UNKNOWN[" + level + "]: " + s);
        }
    }
}
