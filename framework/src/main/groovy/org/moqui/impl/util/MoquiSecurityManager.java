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
package org.moqui.impl.util;

import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;

/**
 * Shiro's DefaultSecurityManager, except that login keeps the subject's session.
 *
 * Moqui puts the servlet HttpSession on a web subject (UserFacadeImpl.makeEmptySubject, wrapped in HttpServletSession)
 * and Shiro stores the signed-in principal there. Since Shiro 2.2.0, DefaultSecurityManager.login stops that session
 * first (HttpSession.invalidate()) and moves its attributes into a native in-memory Shiro session that no cookie points
 * to: the principal never reaches the servlet session, so the next request is signed out, and Moqui keeps working on an
 * invalidated HttpSession. Moqui rotates the servlet session itself before a password sign-in
 * (WebFacadeImpl.makeNewSession, called by UserFacadeImpl.loginUser), so this keeps the Shiro 2.0 login behaviour.
 */
public class MoquiSecurityManager extends DefaultSecurityManager {
    @Override
    protected void beforeSuccessfulLogin(Subject subject) { }
}
