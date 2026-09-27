package afakesu.facts;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Answers "what are this uid's package facts" over binder, and nothing else.
 *
 * The shell this project used to query only ever gave us uid 2000, so every
 * fact arrived as scraped text out of "dumpsys package packages" -- 34k
 * lines whose sub-sections repeated package headers and overwrote each
 * other's fields.  Reading the fields through PackageManager removes the
 * scraping, the parsing and the races in one step.
 *
 * Everything here goes through reflection on purpose.  The build machine has
 * no android.jar, and more importantly the signatures differ across Android
 * releases; resolving by name at runtime cannot fail to link against a
 * framework that is present.
 *
 * This process runs as our own app uid and issues read-only binder calls.  It
 * requests no permission, starts no looper, touches no ActivityThread and
 * writes nothing, so it cannot take the device down with it.
 */
public final class Facts {

    private static final int FLAG_SYSTEM = 0x00000001;      // ApplicationInfo.FLAG_SYSTEM
    private static final int FLAG_UPDATED_SYSTEM_APP = 0x00000080;
    private static final int PRIVATE_FLAG_PRIVILEGED = 0x00000001;

    private static Object pm;          // IPackageManager proxy
    private static Method mPkgsForUid; // getPackagesForUid(int) -> String[]
    private static Method mAppInfo;    // getApplicationInfo(String,int,int) -> ApplicationInfo
    private static Method mInstalled;  // getInstalledPackages(int,int) -> PackageInfo[]

    private static Field fName, fUid, fTargetSdk, fFlags, fPrivFlags, fSourceDir;
    private static Field fPkgInfoName, fPkgInfoApp;

    public static void main(String[] args) {
        StringBuilder out = new StringBuilder();
        try {
            if (!bind()) {
                System.out.println("ERR cannot reach package service");
                System.out.flush();
                return;
            }
            if (args.length >= 2 && "--user".equals(args[0])) {
                int user = parseInt(args[1], 0);
                dumpUser(out, user);
            } else if (args.length >= 1 && "--uid".equals(args[0])) {
                dumpUid(out, parseInt(args[1], -1));
            } else if (args.length >= 1) {
                dumpUid(out, parseInt(args[0], -1));
            } else {
                System.out.println("ERR usage: Facts <uid> | --uid <uid> | --user <userId>");
                System.out.flush();
                return;
            }
        } catch (Throwable t) {
            // A dex that throws out of main takes its host process with it.
            // Report and leave.
            System.out.println("ERR " + t.getClass().getSimpleName() + ": " + t.getMessage());
        }
        System.out.print(out);
        System.out.flush();
    }

    private static int parseInt(String s, int dflt) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Throwable t) {
            return dflt;
        }
    }

    /** Resolve IPackageManager through ServiceManager, entirely by reflection. */
    private static boolean bind() throws Exception {
        Class<?> sm = Class.forName("android.os.ServiceManager");
        Method getService = sm.getDeclaredMethod("getService", String.class);
        Object binder = getService.invoke(null, "package");
        if (binder == null) {
            return false;
        }
        Class<?> stub = Class.forName("android.content.pm.IPackageManager$Stub");
        Method asInterface = stub.getDeclaredMethod("asInterface",
                Class.forName("android.os.IBinder"));
        pm = asInterface.invoke(null, binder);
        if (pm == null) {
            return false;
        }
        mPkgsForUid = find("getPackagesForUid", int.class);
        // Newer releases widen the flags argument to long as part of the
        // v2 binder ABI.  Accept either shape rather than pin one SDK.
        mAppInfo = findAny("getApplicationInfo",
                new Class<?>[][]{{String.class, int.class, int.class},
                                 {String.class, long.class, int.class}});
        mInstalled = findAny("getInstalledPackages",
                new Class<?>[][]{{int.class, int.class},
                                 {long.class, int.class}});
        Class<?> ai = Class.forName("android.content.pm.ApplicationInfo");
        fName = field(ai, "packageName");
        fUid = field(ai, "uid");
        fTargetSdk = field(ai, "targetSdkVersion");
        fFlags = field(ai, "flags");
        fPrivFlags = field(ai, "privateFlags");
        fSourceDir = field(ai, "publicSourceDir");
        Class<?> pi = Class.forName("android.content.pm.PackageInfo");
        fPkgInfoName = field(pi, "packageName");
        fPkgInfoApp = field(pi, "applicationInfo");
        return mPkgsForUid != null;
    }

    /**
     * The binder object is a dynamic Proxy, so the methods live on the
     * IPackageManager interface rather than on the proxy class.  Walking
     * only the class hierarchy is why getPackagesForUid resolved and
     * getApplicationInfo did not.
     */
    private static Method find(String name, Class<?>... sig) {
        for (Class<?> c = pm.getClass(); c != null; c = c.getSuperclass()) {
            Method m = lookup(c, name, sig);
            if (m != null) {
                return m;
            }
            for (Class<?> itf : c.getInterfaces()) {
                m = searchInterface(itf, name, sig);
                if (m != null) {
                    return m;
                }
            }
        }
        return null;
    }

    private static Method findAny(String name, Class<?>[][] shapes) {
        for (Class<?>[] s : shapes) {
            Method m = find(name, s);
            if (m != null) {
                return m;
            }
        }
        return null;
    }

    private static boolean isLongFlags(Method m) {
        Class<?>[] p = m.getParameterTypes();
        return p.length > 0 && p[0] == long.class;
    }

    private static Object flagArg(Method m) {
        return isLongFlags(m) ? (Object) Long.valueOf(0L) : (Object) Integer.valueOf(0);
    }

    private static Method searchInterface(Class<?> itf, String name, Class<?>... sig) {
        Method m = lookup(itf, name, sig);
        if (m != null) {
            return m;
        }
        for (Class<?> sup : itf.getInterfaces()) {
            m = searchInterface(sup, name, sig);
            if (m != null) {
                return m;
            }
        }
        return null;
    }

    private static Method lookup(Class<?> c, String name, Class<?>... sig) {
        try {
            Method m = c.getDeclaredMethod(name, sig);
            m.setAccessible(true);
            return m;
        } catch (NoSuchMethodException e) {
            return null;
        } catch (Throwable t) {
            return null;
        }
    }

    private static Field field(Class<?> c, String name) {
        try {
            Field f = c.getDeclaredField(name);
            f.setAccessible(true);
            return f;
        } catch (Throwable t) {
            return null;
        }
    }

    private static int i(Field f, Object o, int dflt) {
        if (f == null) {
            return dflt;
        }
        try {
            return f.getInt(o);
        } catch (Throwable t) {
            return dflt;
        }
    }

    private static String s(Field f, Object o) {
        if (f == null) {
            return "-";
        }
        try {
            Object v = f.get(o);
            return v == null ? "-" : v.toString();
        } catch (Throwable t) {
            return "-";
        }
    }

    private static void dumpUid(StringBuilder out, int uid) {
        if (uid < 0) {
            return;
        }
        String[] names;
        try {
            names = (String[]) mPkgsForUid.invoke(pm, uid);
        } catch (Throwable t) {
            return;
        }
        if (names == null) {
            return;
        }
        int user = uid / 100000;
        for (String n : names) {
            emit(out, uid, user, n);
        }
    }

    private static void dumpUser(StringBuilder out, int user) {
        if (mInstalled == null) {
            return;
        }
        Object raw;
        try {
            raw = mInstalled.invoke(pm, flagArg(mInstalled), user);
        } catch (Throwable t) {
            return;
        }
        Object[] arr = unwrapList(raw);
        if (arr == null) {
            return;
        }
        for (Object pi : arr) {
            if (pi == null) {
                continue;
            }
            Object app = get(fPkgInfoApp, pi);
            String name = s(fPkgInfoName, pi);
            if (app == null && name == null) {
                continue;
            }
            emitApp(out, app, name);
        }
    }

    /** getInstalledPackages hands back a ParceledListSlice, not an array. */
    private static Object[] unwrapList(Object raw) {
        if (raw == null) {
            return null;
        }
        if (raw instanceof Object[]) {
            return (Object[]) raw;
        }
        try {
            Method getList = raw.getClass().getMethod("getList");
            Object lst = getList.invoke(raw);
            if (lst instanceof java.util.List) {
                return ((java.util.List<?>) lst).toArray();
            }
        } catch (Throwable t) {
            /* fall through */
        }
        return null;
    }

    private static void emit(StringBuilder out, int uid, int user, String name) {
        if (mAppInfo == null) {
            return;
        }
        Object app;
        try {
            app = mAppInfo.invoke(pm, name, flagArg(mAppInfo), user);
        } catch (Throwable t) {
            /* Cross-user reads can be refused; the uid is still worth
             * reporting, just without the detail. */
            out.append("FACT\t").append(uid).append('\t').append(user).append('\t')
               .append(name).append("\t0\t0\t0\t-\n");
            return;
        }
        emitApp(out, app, name);
    }

    private static void emitApp(StringBuilder out, Object app, String name) {
        if (app == null) {
            out.append("FACT\t-1\t-1\t").append(name == null ? "-" : name)
               .append("\t0\t0\t0\t-\n");
            return;
        }
        int uid = i(fUid, app, -1);
        int user = uid >= 0 ? uid / 100000 : -1;
        int flags = i(fFlags, app, 0);
        int priv = i(fPrivFlags, app, 0);
        int tsdk = i(fTargetSdk, app, 0);
        String path = s(fSourceDir, app);
        int isSys = ((flags & FLAG_SYSTEM) != 0
                || (flags & FLAG_UPDATED_SYSTEM_APP) != 0) ? 1 : 0;
        int isPriv = (path.indexOf("/priv-app/") >= 0
                || (priv & PRIVATE_FLAG_PRIVILEGED) != 0) ? 1 : 0;
        String nm = name != null ? name : s(fName, app);
        out.append("FACT\t").append(uid).append('\t').append(user).append('\t')
           .append(nm).append('\t').append(tsdk).append('\t')
           .append(isSys).append('\t').append(isPriv).append('\t')
           .append(path).append('\n');
    }

    private static Object get(Field f, Object o) {
        if (f == null) {
            return null;
        }
        try {
            return f.get(o);
        } catch (Throwable t) {
            return null;
        }
    }
}
