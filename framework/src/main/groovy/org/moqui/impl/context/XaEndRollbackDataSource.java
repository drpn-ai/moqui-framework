/*
 * This software is in the public domain under CC0 1.0 Universal plus a
 * Grant of Patent License.
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software (see the LICENSE.md file). If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
package org.moqui.impl.context;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.ConnectionEventListener;
import javax.sql.StatementEventListener;
import javax.sql.XAConnection;
import javax.sql.XADataSource;
import javax.transaction.xa.XAException;
import javax.transaction.xa.XAResource;
import javax.transaction.xa.Xid;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;

/**
 * Wraps an XADataSource so a branch whose xa_end reports XA_RB* still gets xa_rollback.
 *
 * In the XA state table a branch whose xa_end returns XA_RB* is "rollback only" and must still be rolled back.
 * Bitronix instead treats the resource as unilaterally rolled back and skips xa_rollback. MySQL then keeps that
 * session in the XA ROLLBACK ONLY state, the pool hands the connection out again, and every later XA START on it
 * fails with XAER_RMFAIL "... in the ROLLBACK ONLY state". One InnoDB deadlock (XA_RBDEADLOCK on xa_end) did this
 * in prod. isValid() and a test query (SELECT 1) both still pass on such a connection, so pool testing can't catch it.
 */
public class XaEndRollbackDataSource implements XADataSource {
    private static final Logger logger = LoggerFactory.getLogger(XaEndRollbackDataSource.class);

    private final XADataSource delegate;

    public XaEndRollbackDataSource(XADataSource delegate) { this.delegate = delegate; }

    @Override public XAConnection getXAConnection() throws SQLException { return new Conn(delegate.getXAConnection()); }
    @Override public XAConnection getXAConnection(String user, String password) throws SQLException {
        return new Conn(delegate.getXAConnection(user, password));
    }
    @Override public PrintWriter getLogWriter() throws SQLException { return delegate.getLogWriter(); }
    @Override public void setLogWriter(PrintWriter out) throws SQLException { delegate.setLogWriter(out); }
    @Override public void setLoginTimeout(int seconds) throws SQLException { delegate.setLoginTimeout(seconds); }
    @Override public int getLoginTimeout() throws SQLException { return delegate.getLoginTimeout(); }
    @Override public java.util.logging.Logger getParentLogger() throws SQLFeatureNotSupportedException { return delegate.getParentLogger(); }
    @Override public String toString() { return delegate.toString(); }

    static class Conn implements XAConnection {
        private final XAConnection delegate;
        private Res resource;
        Conn(XAConnection delegate) { this.delegate = delegate; }

        @Override public synchronized XAResource getXAResource() throws SQLException {
            XAResource current = delegate.getXAResource();
            if (resource == null || resource.delegate != current) resource = new Res(current);
            return resource;
        }
        @Override public Connection getConnection() throws SQLException { return delegate.getConnection(); }
        @Override public void close() throws SQLException { delegate.close(); }
        @Override public void addConnectionEventListener(ConnectionEventListener l) { delegate.addConnectionEventListener(l); }
        @Override public void removeConnectionEventListener(ConnectionEventListener l) { delegate.removeConnectionEventListener(l); }
        @Override public void addStatementEventListener(StatementEventListener l) { delegate.addStatementEventListener(l); }
        @Override public void removeStatementEventListener(StatementEventListener l) { delegate.removeStatementEventListener(l); }
        @Override public String toString() { return delegate.toString(); }
    }

    static class Res implements XAResource {
        final XAResource delegate;
        Res(XAResource delegate) { this.delegate = delegate; }

        @Override public void end(Xid xid, int flags) throws XAException {
            try {
                delegate.end(xid, flags);
            } catch (XAException e) {
                if (e.errorCode >= XAException.XA_RBBASE && e.errorCode <= XAException.XA_RBEND) {
                    try {
                        delegate.rollback(xid);
                        logger.warn("XA branch " + xid + " was rolled back by the resource (xa_end error " + e.errorCode + "), sent xa_rollback to release the connection");
                    } catch (XAException re) {
                        logger.warn("XA branch " + xid + " was rolled back by the resource (xa_end error " + e.errorCode + "), xa_rollback failed with error " + re.errorCode, re);
                    }
                }
                throw e;
            }
        }
        @Override public void start(Xid xid, int flags) throws XAException { delegate.start(xid, flags); }
        @Override public int prepare(Xid xid) throws XAException { return delegate.prepare(xid); }
        @Override public void commit(Xid xid, boolean onePhase) throws XAException { delegate.commit(xid, onePhase); }
        @Override public void rollback(Xid xid) throws XAException { delegate.rollback(xid); }
        @Override public void forget(Xid xid) throws XAException { delegate.forget(xid); }
        @Override public Xid[] recover(int flag) throws XAException { return delegate.recover(flag); }
        @Override public boolean isSameRM(XAResource other) throws XAException {
            return delegate.isSameRM(other instanceof Res ? ((Res) other).delegate : other);
        }
        @Override public int getTransactionTimeout() throws XAException { return delegate.getTransactionTimeout(); }
        @Override public boolean setTransactionTimeout(int seconds) throws XAException { return delegate.setTransactionTimeout(seconds); }
        @Override public String toString() { return delegate.toString(); }
    }
}
