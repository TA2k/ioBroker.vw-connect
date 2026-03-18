.class public final Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
.super Lnet/zetetic/database/sqlcipher/SQLiteClosable;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/sqlite/db/SupportSQLiteDatabase;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;,
        Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CustomFunction;
    }
.end annotation


# static fields
.field static final synthetic $assertionsDisabled:Z = false

.field public static final CONFLICT_ABORT:I = 0x2

.field public static final CONFLICT_FAIL:I = 0x3

.field public static final CONFLICT_IGNORE:I = 0x4

.field public static final CONFLICT_NONE:I = 0x0

.field public static final CONFLICT_REPLACE:I = 0x5

.field public static final CONFLICT_ROLLBACK:I = 0x1

.field private static final CONFLICT_VALUES:[Ljava/lang/String;

.field public static final CREATE_IF_NECESSARY:I = 0x10000000

.field public static final ENABLE_WRITE_AHEAD_LOGGING:I = 0x20000000

.field private static final EVENT_DB_CORRUPT:I = 0x124fc

.field public static final MAX_SQL_CACHE_SIZE:I = 0x64

.field public static final NO_LOCALIZED_COLLATORS:I = 0x10

.field public static final OPEN_READONLY:I = 0x1

.field public static final OPEN_READWRITE:I = 0x0

.field private static final OPEN_READ_MASK:I = 0x1

.field public static final SQLITE_MAX_LIKE_PATTERN_LENGTH:I = 0xc350

.field private static final TAG:Ljava/lang/String; = "SQLiteDatabase"

.field private static sActiveDatabases:Ljava/util/WeakHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/WeakHashMap<",
            "Lnet/zetetic/database/sqlcipher/SQLiteDatabase;",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final mCloseGuardLocked:Lnet/zetetic/database/sqlcipher/CloseGuard;

.field private final mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

.field private mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

.field private final mCursorFactory:Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;

.field private final mErrorHandler:Lnet/zetetic/database/DatabaseErrorHandler;

.field private mHasAttachedDbsLocked:Z

.field private final mLock:Ljava/lang/Object;

.field private final mThreadSession:Ljava/lang/ThreadLocal;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ThreadLocal<",
            "Lnet/zetetic/database/sqlcipher/SQLiteSession;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Ljava/util/WeakHashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/WeakHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->sActiveDatabases:Ljava/util/WeakHashMap;

    .line 7
    .line 8
    const-string v5, " OR IGNORE "

    .line 9
    .line 10
    const-string v6, " OR REPLACE "

    .line 11
    .line 12
    const-string v1, ""

    .line 13
    .line 14
    const-string v2, " OR ROLLBACK "

    .line 15
    .line 16
    const-string v3, " OR ABORT "

    .line 17
    .line 18
    const-string v4, " OR FAIL "

    .line 19
    .line 20
    filled-new-array/range {v1 .. v6}, [Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    sput-object v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->CONFLICT_VALUES:[Ljava/lang/String;

    .line 25
    .line 26
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;[BILnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Lnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase$1;

    .line 5
    .line 6
    invoke-direct {v0, p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase$1;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mThreadSession:Ljava/lang/ThreadLocal;

    .line 10
    .line 11
    new-instance v0, Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 17
    .line 18
    invoke-static {}, Lnet/zetetic/database/sqlcipher/CloseGuard;->get()Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mCloseGuardLocked:Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 23
    .line 24
    iput-object p4, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mCursorFactory:Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;

    .line 25
    .line 26
    if-eqz p5, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    new-instance p5, Lnet/zetetic/database/DefaultDatabaseErrorHandler;

    .line 30
    .line 31
    invoke-direct {p5}, Lnet/zetetic/database/DefaultDatabaseErrorHandler;-><init>()V

    .line 32
    .line 33
    .line 34
    :goto_0
    iput-object p5, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mErrorHandler:Lnet/zetetic/database/DatabaseErrorHandler;

    .line 35
    .line 36
    new-instance p4, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 37
    .line 38
    invoke-direct {p4, p1, p3, p2, p6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;-><init>(Ljava/lang/String;I[BLnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)V

    .line 39
    .line 40
    .line 41
    iput-object p4, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 42
    .line 43
    return-void
.end method

.method private beginTransaction(Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;Z)V
    .locals 3

    .line 2
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 3
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getThreadSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    move-result-object v0

    if-eqz p2, :cond_0

    const/4 p2, 0x2

    goto :goto_0

    :cond_0
    const/4 p2, 0x1

    :goto_0
    const/4 v1, 0x0

    .line 4
    invoke-virtual {p0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getThreadDefaultConnectionFlags(Z)I

    move-result v1

    const/4 v2, 0x0

    .line 5
    invoke-virtual {v0, p2, p1, v1, v2}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->beginTransaction(ILnet/zetetic/database/sqlcipher/SQLiteTransactionListener;ILandroid/os/CancellationSignal;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    return-void

    :catchall_0
    move-exception p1

    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 7
    throw p1
.end method

.method private collectDbStats(Ljava/util/ArrayList;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/ArrayList<",
            "Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;",
            ">;)V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 5
    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->collectDbStats(Ljava/util/ArrayList;)V

    .line 9
    .line 10
    .line 11
    goto :goto_0

    .line 12
    :catchall_0
    move-exception p0

    .line 13
    goto :goto_1

    .line 14
    :cond_0
    :goto_0
    monitor-exit v0

    .line 15
    return-void

    .line 16
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    throw p0
.end method

.method public static create(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 2

    .line 1
    const-string v0, ":memory:"

    .line 2
    .line 3
    const/high16 v1, 0x10000000

    .line 4
    .line 5
    invoke-static {v0, p0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;I)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static deleteDatabase(Ljava/io/File;)Z
    .locals 4

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/io/File;->delete()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-instance v1, Ljava/io/File;

    .line 8
    .line 9
    new-instance v2, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string v3, "-journal"

    .line 22
    .line 23
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-direct {v1, v2}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1}, Ljava/io/File;->delete()Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    or-int/2addr v0, v1

    .line 38
    new-instance v1, Ljava/io/File;

    .line 39
    .line 40
    new-instance v2, Ljava/lang/StringBuilder;

    .line 41
    .line 42
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string v3, "-shm"

    .line 53
    .line 54
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    invoke-direct {v1, v2}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/io/File;->delete()Z

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    or-int/2addr v0, v1

    .line 69
    new-instance v1, Ljava/io/File;

    .line 70
    .line 71
    new-instance v2, Ljava/lang/StringBuilder;

    .line 72
    .line 73
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v3, "-wal"

    .line 84
    .line 85
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    invoke-direct {v1, v2}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v1}, Ljava/io/File;->delete()Z

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    or-int/2addr v0, v1

    .line 100
    invoke-virtual {p0}, Ljava/io/File;->getParentFile()Ljava/io/File;

    .line 101
    .line 102
    .line 103
    move-result-object v1

    .line 104
    if-eqz v1, :cond_0

    .line 105
    .line 106
    new-instance v2, Ljava/lang/StringBuilder;

    .line 107
    .line 108
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 109
    .line 110
    .line 111
    invoke-virtual {p0}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    const-string p0, "-mj"

    .line 119
    .line 120
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    new-instance v2, Lnet/zetetic/database/sqlcipher/SQLiteDatabase$4;

    .line 128
    .line 129
    invoke-direct {v2, p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase$4;-><init>(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v1, v2}, Ljava/io/File;->listFiles(Ljava/io/FileFilter;)[Ljava/io/File;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    if-eqz p0, :cond_0

    .line 137
    .line 138
    array-length v1, p0

    .line 139
    const/4 v2, 0x0

    .line 140
    :goto_0
    if-ge v2, v1, :cond_0

    .line 141
    .line 142
    aget-object v3, p0, v2

    .line 143
    .line 144
    invoke-virtual {v3}, Ljava/io/File;->delete()Z

    .line 145
    .line 146
    .line 147
    move-result v3

    .line 148
    or-int/2addr v0, v3

    .line 149
    add-int/lit8 v2, v2, 0x1

    .line 150
    .line 151
    goto :goto_0

    .line 152
    :cond_0
    return v0

    .line 153
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 154
    .line 155
    const-string v0, "file must not be null"

    .line 156
    .line 157
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    throw p0
.end method

.method private dispose(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mCloseGuardLocked:Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 5
    .line 6
    if-eqz v1, :cond_1

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    invoke-virtual {v1}, Lnet/zetetic/database/sqlcipher/CloseGuard;->warnIfOpen()V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    goto :goto_1

    .line 16
    :cond_0
    :goto_0
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mCloseGuardLocked:Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 17
    .line 18
    invoke-virtual {v1}, Lnet/zetetic/database/sqlcipher/CloseGuard;->close()V

    .line 19
    .line 20
    .line 21
    :cond_1
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    iput-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 25
    .line 26
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    if-nez p1, :cond_2

    .line 28
    .line 29
    sget-object p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->sActiveDatabases:Ljava/util/WeakHashMap;

    .line 30
    .line 31
    monitor-enter p1

    .line 32
    :try_start_1
    sget-object v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->sActiveDatabases:Ljava/util/WeakHashMap;

    .line 33
    .line 34
    invoke-virtual {v0, p0}, Ljava/util/WeakHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    invoke-virtual {v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->close()V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :catchall_1
    move-exception p0

    .line 45
    :try_start_2
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 46
    throw p0

    .line 47
    :cond_2
    return-void

    .line 48
    :goto_1
    :try_start_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 49
    throw p0
.end method

.method private dump(Landroid/util/Printer;Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    const-string v1, ""

    .line 9
    .line 10
    invoke-interface {p1, v1}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 14
    .line 15
    invoke-virtual {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->dump(Landroid/util/Printer;Z)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    :goto_0
    monitor-exit v0

    .line 22
    return-void

    .line 23
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    throw p0
.end method

.method public static dumpAll(Landroid/util/Printer;Z)V
    .locals 2

    .line 1
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getActiveDatabases()Ljava/util/ArrayList;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 20
    .line 21
    invoke-direct {v1, p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->dump(Landroid/util/Printer;Z)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    return-void
.end method

.method private executeSql(Ljava/lang/String;[Ljava/lang/Object;)I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-static {p1}, Lnet/zetetic/database/DatabaseUtils;->getSqlStatementType(Ljava/lang/String;)I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    const/4 v1, 0x3

    .line 9
    if-ne v0, v1, :cond_1

    .line 10
    .line 11
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 12
    .line 13
    monitor-enter v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 14
    :try_start_1
    iget-boolean v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mHasAttachedDbsLocked:Z

    .line 15
    .line 16
    if-nez v1, :cond_0

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    iput-boolean v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mHasAttachedDbsLocked:Z

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception p1

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    const/4 v1, 0x0

    .line 25
    :goto_0
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    :try_start_2
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->disableWriteAheadLogging()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 29
    .line 30
    .line 31
    goto :goto_2

    .line 32
    :catchall_1
    move-exception p1

    .line 33
    goto :goto_3

    .line 34
    :goto_1
    :try_start_3
    monitor-exit v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 35
    :try_start_4
    throw p1

    .line 36
    :cond_1
    :goto_2
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 37
    .line 38
    invoke-direct {v0, p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 39
    .line 40
    .line 41
    :try_start_5
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;->executeUpdateDelete()I

    .line 42
    .line 43
    .line 44
    move-result p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 45
    :try_start_6
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 49
    .line 50
    .line 51
    return p1

    .line 52
    :catchall_2
    move-exception p1

    .line 53
    :try_start_7
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 54
    .line 55
    .line 56
    throw p1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 57
    :goto_3
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 58
    .line 59
    .line 60
    throw p1
.end method

.method public static findEditTable(Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    .line 1
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_4

    .line 6
    .line 7
    const/16 v0, 0x20

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Ljava/lang/String;->indexOf(I)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/16 v1, 0x2c

    .line 14
    .line 15
    invoke-virtual {p0, v1}, Ljava/lang/String;->indexOf(I)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    const/4 v2, 0x0

    .line 20
    if-lez v0, :cond_1

    .line 21
    .line 22
    if-lt v0, v1, :cond_0

    .line 23
    .line 24
    if-gez v1, :cond_1

    .line 25
    .line 26
    :cond_0
    invoke-virtual {p0, v2, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :cond_1
    if-lez v1, :cond_3

    .line 32
    .line 33
    if-lt v1, v0, :cond_2

    .line 34
    .line 35
    if-gez v0, :cond_3

    .line 36
    .line 37
    :cond_2
    invoke-virtual {p0, v2, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    :cond_3
    return-object p0

    .line 42
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string v0, "Invalid tables"

    .line 45
    .line 46
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0
.end method

.method private static getActiveDatabases()Ljava/util/ArrayList;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList<",
            "Lnet/zetetic/database/sqlcipher/SQLiteDatabase;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->sActiveDatabases:Ljava/util/WeakHashMap;

    .line 7
    .line 8
    monitor-enter v1

    .line 9
    :try_start_0
    sget-object v2, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->sActiveDatabases:Ljava/util/WeakHashMap;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/util/WeakHashMap;->keySet()Ljava/util/Set;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 16
    .line 17
    .line 18
    monitor-exit v1

    .line 19
    return-object v0

    .line 20
    :catchall_0
    move-exception v0

    .line 21
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    throw v0
.end method

.method private static getBytes(Ljava/lang/String;)[B
    .locals 1

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, "UTF-8"

    .line 11
    .line 12
    invoke-static {v0}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {p0, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 22
    new-array p0, p0, [B

    .line 23
    .line 24
    return-object p0
.end method

.method public static getDbStats()Ljava/util/ArrayList;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/ArrayList<",
            "Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getActiveDatabases()Ljava/util/ArrayList;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eqz v2, :cond_0

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 25
    .line 26
    invoke-direct {v2, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->collectDbStats(Ljava/util/ArrayList;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    return-object v0
.end method

.method public static hasCodec()Z
    .locals 1

    .line 1
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->hasCodec()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    return v0
.end method

.method private static isMainThread()Z
    .locals 2

    .line 1
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    const/4 v0, 0x1

    .line 14
    return v0

    .line 15
    :cond_0
    const/4 v0, 0x0

    .line 16
    return v0
.end method

.method private isReadOnlyLocked()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 2
    .line 3
    iget p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    and-int/2addr p0, v0

    .line 7
    if-ne p0, v0, :cond_0

    .line 8
    .line 9
    return v0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return p0
.end method

.method private open()V
    .locals 3

    .line 1
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openInner()V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteDatabaseCorruptException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 2
    .line 3
    .line 4
    return-void

    .line 5
    :catch_0
    move-exception v0

    .line 6
    goto :goto_0

    .line 7
    :catch_1
    move-exception v0

    .line 8
    :try_start_1
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->onCorruption(Landroid/database/sqlite/SQLiteException;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openInner()V
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :goto_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v2, "Failed to open database \'"

    .line 18
    .line 19
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getLabel()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v2, "\'."

    .line 30
    .line 31
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    const-string v2, "SQLiteDatabase"

    .line 39
    .line 40
    invoke-static {v2, v1, v0}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 44
    .line 45
    .line 46
    throw v0
.end method

.method public static openDatabase(Ljava/lang/String;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 0

    .line 5
    invoke-static {p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getBytes(Ljava/lang/String;)[B

    move-result-object p1

    invoke-static/range {p0 .. p5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openDatabase(Ljava/lang/String;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 6

    .line 2
    invoke-static {p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getBytes(Ljava/lang/String;)[B

    move-result-object v1

    const/4 v4, 0x0

    move-object v0, p0

    move-object v2, p2

    move v3, p3

    move-object v5, p4

    invoke-static/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openDatabase(Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;I)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-static {p0, p1, p2, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openDatabase(Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 7

    const/4 v0, 0x0

    .line 4
    new-array v2, v0, [B

    const/4 v6, 0x0

    move-object v1, p0

    move-object v3, p1

    move v4, p2

    move-object v5, p3

    invoke-static/range {v1 .. v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 7

    .line 6
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-object v1, p0

    move-object v2, p1

    move-object v4, p2

    move v3, p3

    move-object v5, p4

    move-object v6, p5

    invoke-direct/range {v0 .. v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;-><init>(Ljava/lang/String;[BILnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Lnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)V

    .line 7
    invoke-direct {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->open()V

    return-object v0
.end method

.method public static openDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 6

    const/4 v4, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move v3, p3

    move-object v5, p4

    .line 3
    invoke-static/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method private openInner()V
    .locals 3

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 5
    .line 6
    invoke-static {v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->open(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    iput-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 11
    .line 12
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mCloseGuardLocked:Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 13
    .line 14
    const-string v2, "close"

    .line 15
    .line 16
    invoke-virtual {v1, v2}, Lnet/zetetic/database/sqlcipher/CloseGuard;->open(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 20
    sget-object v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->sActiveDatabases:Ljava/util/WeakHashMap;

    .line 21
    .line 22
    monitor-enter v1

    .line 23
    :try_start_1
    sget-object v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->sActiveDatabases:Ljava/util/WeakHashMap;

    .line 24
    .line 25
    const/4 v2, 0x0

    .line 26
    invoke-virtual {v0, p0, v2}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    monitor-exit v1

    .line 30
    return-void

    .line 31
    :catchall_0
    move-exception p0

    .line 32
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 33
    throw p0

    .line 34
    :catchall_1
    move-exception p0

    .line 35
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 36
    throw p0
.end method

.method public static openOrCreateDatabase(Ljava/io/File;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Lnet/zetetic/database/DatabaseErrorHandler;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 6

    .line 4
    invoke-virtual {p0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v0

    const/high16 v3, 0x10000000

    const/4 v5, 0x0

    move-object v1, p1

    move-object v2, p2

    move-object v4, p3

    invoke-static/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openOrCreateDatabase(Ljava/io/File;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Lnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 6

    .line 8
    invoke-virtual {p0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v0

    const/high16 v3, 0x10000000

    move-object v1, p1

    move-object v2, p2

    move-object v4, p3

    move-object v5, p4

    invoke-static/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openOrCreateDatabase(Ljava/io/File;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/io/File;->getPath()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openOrCreateDatabase(Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openOrCreateDatabase(Ljava/io/File;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Lnet/zetetic/database/DatabaseErrorHandler;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 6

    .line 5
    invoke-virtual {p0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v0

    const/high16 v3, 0x10000000

    const/4 v5, 0x0

    move-object v1, p1

    move-object v2, p2

    move-object v4, p3

    invoke-static/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openOrCreateDatabase(Ljava/io/File;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Lnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 6

    .line 9
    invoke-virtual {p0}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    move-result-object v0

    const/high16 v3, 0x10000000

    move-object v1, p1

    move-object v2, p2

    move-object v4, p3

    move-object v5, p4

    invoke-static/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openOrCreateDatabase(Ljava/lang/String;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Lnet/zetetic/database/DatabaseErrorHandler;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 6

    const/high16 v3, 0x10000000

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v4, p3

    .line 6
    invoke-static/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openOrCreateDatabase(Ljava/lang/String;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Lnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 6

    const/high16 v3, 0x10000000

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v4, p3

    move-object v5, p4

    .line 10
    invoke-static/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openOrCreateDatabase(Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 2

    const/high16 v0, 0x10000000

    const/4 v1, 0x0

    .line 2
    invoke-static {p0, p1, v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openOrCreateDatabase(Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Lnet/zetetic/database/DatabaseErrorHandler;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 1

    const/high16 v0, 0x10000000

    .line 3
    invoke-static {p0, p1, v0, p2}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openOrCreateDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Lnet/zetetic/database/DatabaseErrorHandler;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 6

    const/high16 v3, 0x10000000

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v4, p3

    .line 7
    invoke-static/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static openOrCreateDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Lnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 6

    const/high16 v3, 0x10000000

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v4, p3

    move-object v5, p4

    .line 11
    invoke-static/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public static releaseMemory()I
    .locals 1

    .line 1
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->releaseMemory()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    return v0
.end method

.method private throwIfNotOpenLocked()V
    .locals 3

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    new-instance v1, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v2, "The database \'"

    .line 11
    .line 12
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 16
    .line 17
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->label:Ljava/lang/String;

    .line 18
    .line 19
    const-string v2, "\' is not open."

    .line 20
    .line 21
    invoke-static {v1, p0, v2}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw v0
.end method

.method private yieldIfContendedHelper(ZJ)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getThreadSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-virtual {v0, p2, p3, p1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->yieldTransaction(JZLandroid/os/CancellationSignal;)Z

    .line 10
    .line 11
    .line 12
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 14
    .line 15
    .line 16
    return p1

    .line 17
    :catchall_0
    move-exception p1

    .line 18
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 19
    .line 20
    .line 21
    throw p1
.end method


# virtual methods
.method public addCustomFunction(Ljava/lang/String;ILnet/zetetic/database/sqlcipher/SQLiteDatabase$CustomFunction;)V
    .locals 1

    .line 1
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteCustomFunction;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2, p3}, Lnet/zetetic/database/sqlcipher/SQLiteCustomFunction;-><init>(Ljava/lang/String;ILnet/zetetic/database/sqlcipher/SQLiteDatabase$CustomFunction;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 7
    .line 8
    monitor-enter p1

    .line 9
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->throwIfNotOpenLocked()V

    .line 10
    .line 11
    .line 12
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 13
    .line 14
    iget-object p2, p2, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->customFunctions:Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-virtual {p2, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    .line 18
    .line 19
    :try_start_1
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 20
    .line 21
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 22
    .line 23
    invoke-virtual {p2, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->reconfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 24
    .line 25
    .line 26
    :try_start_2
    monitor-exit p1

    .line 27
    return-void

    .line 28
    :catchall_0
    move-exception p0

    .line 29
    goto :goto_0

    .line 30
    :catch_0
    move-exception p2

    .line 31
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 32
    .line 33
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->customFunctions:Ljava/util/ArrayList;

    .line 34
    .line 35
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    throw p2

    .line 39
    :goto_0
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 40
    throw p0
.end method

.method public beginTransaction()V
    .locals 2

    const/4 v0, 0x0

    const/4 v1, 0x1

    .line 1
    invoke-direct {p0, v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->beginTransaction(Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;Z)V

    return-void
.end method

.method public beginTransactionNonExclusive()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x0

    .line 3
    invoke-direct {p0, v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->beginTransaction(Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public beginTransactionReadOnly()V
    .locals 0

    .line 1
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteDatabase;->beginTransaction()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public beginTransactionWithListener(Landroid/database/sqlite/SQLiteTransactionListener;)V
    .locals 1

    .line 1
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase$2;

    invoke-direct {v0, p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase$2;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Landroid/database/sqlite/SQLiteTransactionListener;)V

    const/4 p1, 0x1

    invoke-direct {p0, v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->beginTransaction(Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;Z)V

    return-void
.end method

.method public beginTransactionWithListener(Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;)V
    .locals 1

    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, p1, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->beginTransaction(Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;Z)V

    return-void
.end method

.method public beginTransactionWithListenerNonExclusive(Landroid/database/sqlite/SQLiteTransactionListener;)V
    .locals 1

    .line 1
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase$3;

    invoke-direct {v0, p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase$3;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Landroid/database/sqlite/SQLiteTransactionListener;)V

    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->beginTransactionWithListenerNonExclusive(Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;)V

    return-void
.end method

.method public beginTransactionWithListenerNonExclusive(Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;)V
    .locals 1

    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->beginTransaction(Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;Z)V

    return-void
.end method

.method public beginTransactionWithListenerReadOnly(Landroid/database/sqlite/SQLiteTransactionListener;)V
    .locals 1

    .line 1
    const-string v0, "transactionListener"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0, p1}, Landroidx/sqlite/db/SupportSQLiteDatabase;->beginTransactionWithListener(Landroid/database/sqlite/SQLiteTransactionListener;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public changePassword(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-static {p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getBytes(Ljava/lang/String;)[B

    move-result-object p1

    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->changePassword([B)V

    return-void
.end method

.method public changePassword([B)V
    .locals 3

    .line 2
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    monitor-enter v0

    .line 3
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->throwIfNotOpenLocked()V

    .line 4
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isReadOnlyLocked()Z

    move-result v1

    if-nez v1, :cond_1

    .line 5
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    invoke-virtual {v1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->isInMemoryDb()Z

    move-result v1

    if-nez v1, :cond_0

    .line 6
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    iget-object v2, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->password:[B

    .line 7
    iput-object p1, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->password:[B
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 8
    :try_start_1
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    invoke-virtual {p1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->reconfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 9
    :try_start_2
    monitor-exit v0

    return-void

    :catchall_0
    move-exception p0

    goto :goto_0

    :catch_0
    move-exception p1

    .line 10
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    iput-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->password:[B

    .line 11
    throw p1

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Can\'t change password for in-memory databases."

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 13
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Can\'t change password for readonly databases."

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 14
    :goto_0
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    throw p0
.end method

.method public bridge synthetic compileStatement(Ljava/lang/String;)Landroidx/sqlite/db/SupportSQLiteStatement;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    move-result-object p0

    return-object p0
.end method

.method public compileStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteStatement;
    .locals 2

    .line 2
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 3
    :try_start_0
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 4
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    return-object v0

    :catchall_0
    move-exception p1

    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 5
    throw p1
.end method

.method public createSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->throwIfNotOpenLocked()V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 8
    .line 9
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 11
    .line 12
    invoke-direct {v0, p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;)V

    .line 13
    .line 14
    .line 15
    return-object v0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 18
    throw p0
.end method

.method public delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)I
    .locals 4

    const/4 v0, 0x0

    if-nez p3, :cond_0

    move v1, v0

    goto :goto_0

    .line 1
    :cond_0
    array-length v1, p3

    .line 2
    :goto_0
    new-array v2, v1, [Ljava/lang/String;

    :goto_1
    if-ge v0, v1, :cond_1

    .line 3
    aget-object v3, p3, v0

    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v3

    aput-object v3, v2, v0

    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    .line 4
    :cond_1
    invoke-virtual {p0, p1, p2, v2}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 4

    .line 5
    const-string v0, " WHERE "

    const-string v1, "DELETE FROM "

    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 6
    :try_start_0
    new-instance v2, Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 7
    invoke-static {p2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p1

    if-nez p1, :cond_0

    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    const-string p1, ""

    :goto_0
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v2, p0, p1, p3}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 8
    :try_start_1
    invoke-virtual {v2}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;->executeUpdateDelete()I

    move-result p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 9
    :try_start_2
    invoke-virtual {v2}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 10
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    return p1

    :catchall_1
    move-exception p1

    .line 11
    :try_start_3
    invoke-virtual {v2}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 12
    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 13
    :goto_1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 14
    throw p1
.end method

.method public disableWriteAheadLogging()V
    .locals 5

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->throwIfNotOpenLocked()V

    .line 5
    .line 6
    .line 7
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 8
    .line 9
    iget v2, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 10
    .line 11
    const/high16 v3, 0x20000000

    .line 12
    .line 13
    and-int v4, v2, v3

    .line 14
    .line 15
    if-nez v4, :cond_0

    .line 16
    .line 17
    monitor-exit v0

    .line 18
    return-void

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const v4, -0x20000001

    .line 22
    .line 23
    .line 24
    and-int/2addr v2, v4

    .line 25
    iput v2, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    .line 27
    :try_start_1
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 28
    .line 29
    invoke-virtual {v2, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->reconfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 30
    .line 31
    .line 32
    :try_start_2
    monitor-exit v0

    .line 33
    return-void

    .line 34
    :catch_0
    move-exception v1

    .line 35
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 36
    .line 37
    iget v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 38
    .line 39
    or-int/2addr v2, v3

    .line 40
    iput v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 41
    .line 42
    throw v1

    .line 43
    :goto_0
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 44
    throw p0
.end method

.method public enableLocalizedCollators()V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 2
    .line 3
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->enableLocalizedCollators()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public enableWriteAheadLogging()Z
    .locals 6

    .line 1
    const-string v0, "this database: "

    .line 2
    .line 3
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->throwIfNotOpenLocked()V

    .line 7
    .line 8
    .line 9
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 10
    .line 11
    iget v2, v2, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 12
    .line 13
    const/high16 v3, 0x20000000

    .line 14
    .line 15
    and-int/2addr v2, v3

    .line 16
    const/4 v4, 0x1

    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    monitor-exit v1

    .line 20
    return v4

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isReadOnlyLocked()Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    const/4 v5, 0x0

    .line 28
    if-eqz v2, :cond_1

    .line 29
    .line 30
    monitor-exit v1

    .line 31
    return v5

    .line 32
    :cond_1
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 33
    .line 34
    invoke-virtual {v2}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->isInMemoryDb()Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-eqz v2, :cond_2

    .line 39
    .line 40
    const-string p0, "SQLiteDatabase"

    .line 41
    .line 42
    const-string v0, "can\'t enable WAL for memory databases."

    .line 43
    .line 44
    invoke-static {p0, v0}, Lnet/zetetic/database/Logger;->i(Ljava/lang/String;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    monitor-exit v1

    .line 48
    return v5

    .line 49
    :cond_2
    iget-boolean v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mHasAttachedDbsLocked:Z

    .line 50
    .line 51
    if-eqz v2, :cond_4

    .line 52
    .line 53
    const-string v2, "SQLiteDatabase"

    .line 54
    .line 55
    const/4 v3, 0x3

    .line 56
    invoke-static {v2, v3}, Lnet/zetetic/database/Logger;->isLoggable(Ljava/lang/String;I)Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-eqz v2, :cond_3

    .line 61
    .line 62
    const-string v2, "SQLiteDatabase"

    .line 63
    .line 64
    new-instance v3, Ljava/lang/StringBuilder;

    .line 65
    .line 66
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 70
    .line 71
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->label:Ljava/lang/String;

    .line 72
    .line 73
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string p0, " has attached databases. can\'t  enable WAL."

    .line 77
    .line 78
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-static {v2, p0}, Lnet/zetetic/database/Logger;->d(Ljava/lang/String;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    :cond_3
    monitor-exit v1

    .line 89
    return v5

    .line 90
    :cond_4
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 91
    .line 92
    iget v2, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 93
    .line 94
    or-int/2addr v2, v3

    .line 95
    iput v2, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 96
    .line 97
    :try_start_1
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 98
    .line 99
    invoke-virtual {v2, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->reconfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 100
    .line 101
    .line 102
    :try_start_2
    monitor-exit v1

    .line 103
    return v4

    .line 104
    :catch_0
    move-exception v0

    .line 105
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 106
    .line 107
    iget v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 108
    .line 109
    const v3, -0x20000001

    .line 110
    .line 111
    .line 112
    and-int/2addr v2, v3

    .line 113
    iput v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 114
    .line 115
    throw v0

    .line 116
    :goto_0
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 117
    throw p0
.end method

.method public endTransaction()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getThreadSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-virtual {v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->endTransaction(Landroid/os/CancellationSignal;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :catchall_0
    move-exception v0

    .line 17
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 18
    .line 19
    .line 20
    throw v0
.end method

.method public execPerConnectionSQL(Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0
    .param p2    # [Ljava/lang/Object;
        .annotation build Landroid/annotation/SuppressLint;
            value = {
                "ArrayReturn"
            }
        .end annotation
    .end param

    .line 1
    const-string p0, "sql"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 9
    .line 10
    .line 11
    throw p0
.end method

.method public execSQL(Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-direct {p0, p1, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->executeSql(Ljava/lang/String;[Ljava/lang/Object;)I

    return-void
.end method

.method public execSQL(Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    if-eqz p2, :cond_0

    .line 2
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->executeSql(Ljava/lang/String;[Ljava/lang/Object;)I

    return-void

    .line 3
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Empty bindArgs"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public finalize()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    :try_start_0
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->dispose(Z)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    .line 5
    invoke-super {p0}, Ljava/lang/Object;->finalize()V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :catchall_0
    move-exception v0

    .line 10
    invoke-super {p0}, Ljava/lang/Object;->finalize()V

    .line 11
    .line 12
    .line 13
    throw v0
.end method

.method public getAttachedDbs()Ljava/util/List;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Landroid/util/Pair<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 7
    .line 8
    monitor-enter v1

    .line 9
    :try_start_0
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    monitor-exit v1

    .line 15
    return-object v3

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto :goto_3

    .line 18
    :cond_0
    iget-boolean v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mHasAttachedDbsLocked:Z

    .line 19
    .line 20
    if-nez v2, :cond_1

    .line 21
    .line 22
    new-instance v2, Landroid/util/Pair;

    .line 23
    .line 24
    const-string v3, "main"

    .line 25
    .line 26
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 27
    .line 28
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->path:Ljava/lang/String;

    .line 29
    .line 30
    invoke-direct {v2, v3, p0}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    monitor-exit v1

    .line 37
    return-object v0

    .line 38
    :cond_1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 39
    .line 40
    .line 41
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    :try_start_1
    const-string v1, "pragma database_list;"

    .line 43
    .line 44
    invoke-virtual {p0, v1, v3}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    :goto_0
    invoke-interface {v3}, Landroid/database/Cursor;->moveToNext()Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    if-eqz v1, :cond_2

    .line 53
    .line 54
    new-instance v1, Landroid/util/Pair;

    .line 55
    .line 56
    const/4 v2, 0x1

    .line 57
    invoke-interface {v3, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    const/4 v4, 0x2

    .line 62
    invoke-interface {v3, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    invoke-direct {v1, v2, v4}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :catchall_1
    move-exception v0

    .line 74
    goto :goto_1

    .line 75
    :cond_2
    :try_start_2
    invoke-interface {v3}, Landroid/database/Cursor;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 76
    .line 77
    .line 78
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 79
    .line 80
    .line 81
    return-object v0

    .line 82
    :catchall_2
    move-exception v0

    .line 83
    goto :goto_2

    .line 84
    :goto_1
    if-eqz v3, :cond_3

    .line 85
    .line 86
    :try_start_3
    invoke-interface {v3}, Landroid/database/Cursor;->close()V

    .line 87
    .line 88
    .line 89
    :cond_3
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 90
    :goto_2
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 91
    .line 92
    .line 93
    throw v0

    .line 94
    :goto_3
    :try_start_4
    monitor-exit v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 95
    throw p0
.end method

.method public getLabel()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 5
    .line 6
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->label:Ljava/lang/String;

    .line 7
    .line 8
    monitor-exit v0

    .line 9
    return-object p0

    .line 10
    :catchall_0
    move-exception p0

    .line 11
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    throw p0
.end method

.method public getMaximumSize()J
    .locals 4

    .line 1
    const-string v0, "PRAGMA max_page_count;"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {p0, v0, v1}, Lnet/zetetic/database/DatabaseUtils;->longForQuery(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/String;)J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getPageSize()J

    .line 9
    .line 10
    .line 11
    move-result-wide v2

    .line 12
    mul-long/2addr v2, v0

    .line 13
    return-wide v2
.end method

.method public getPageSize()J
    .locals 2

    .line 1
    const-string v0, "PRAGMA page_size;"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {p0, v0, v1}, Lnet/zetetic/database/DatabaseUtils;->longForQuery(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/String;)J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    return-wide v0
.end method

.method public final getPath()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 5
    .line 6
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->path:Ljava/lang/String;

    .line 7
    .line 8
    monitor-exit v0

    .line 9
    return-object p0

    .line 10
    :catchall_0
    move-exception p0

    .line 11
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    throw p0
.end method

.method public getSyncedTables()Ljava/util/Map;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    new-instance p0, Ljava/util/HashMap;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-direct {p0, v0}, Ljava/util/HashMap;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-object p0
.end method

.method public getThreadDefaultConnectionFlags(Z)I
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    goto :goto_0

    .line 5
    :cond_0
    const/4 p0, 0x2

    .line 6
    :goto_0
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isMainThread()Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    or-int/lit8 p0, p0, 0x4

    .line 13
    .line 14
    :cond_1
    return p0
.end method

.method public getThreadSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mThreadSession:Ljava/lang/ThreadLocal;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 8
    .line 9
    return-object p0
.end method

.method public getVersion()I
    .locals 2

    .line 1
    const-string v0, "PRAGMA user_version;"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-static {p0, v0, v1}, Lnet/zetetic/database/DatabaseUtils;->longForQuery(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/String;)J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Ljava/lang/Long;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

.method public inTransaction()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getThreadSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->hasTransaction()Z

    .line 9
    .line 10
    .line 11
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 13
    .line 14
    .line 15
    return v0

    .line 16
    :catchall_0
    move-exception v0

    .line 17
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 18
    .line 19
    .line 20
    throw v0
.end method

.method public insert(Ljava/lang/String;ILandroid/content/ContentValues;)J
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-virtual {p0, p1, v0, p3, p2}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    move-result-wide p0

    return-wide p0
.end method

.method public insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J
    .locals 1

    const/4 v0, 0x0

    .line 2
    :try_start_0
    invoke-virtual {p0, p1, p2, p3, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    move-result-wide p0
    :try_end_0
    .catch Landroid/database/SQLException; {:try_start_0 .. :try_end_0} :catch_0

    return-wide p0

    :catch_0
    move-exception p0

    .line 3
    const-string p1, "SQLiteDatabase"

    const-string p2, "Error inserting"

    invoke-static {p1, p2, p0}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    const-wide/16 p0, -0x1

    return-wide p0
.end method

.method public insertOrThrow(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, p2, p3, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    .line 3
    .line 4
    .line 5
    move-result-wide p0

    .line 6
    return-wide p0
.end method

.method public insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J
    .locals 6

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 7
    .line 8
    .line 9
    const-string v1, "INSERT"

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    sget-object v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->CONFLICT_VALUES:[Ljava/lang/String;

    .line 15
    .line 16
    aget-object p4, v1, p4

    .line 17
    .line 18
    invoke-virtual {v0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string p4, " INTO "

    .line 22
    .line 23
    invoke-virtual {v0, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const/16 p1, 0x28

    .line 30
    .line 31
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const/4 p1, 0x0

    .line 35
    if-eqz p3, :cond_0

    .line 36
    .line 37
    invoke-virtual {p3}, Landroid/content/ContentValues;->size()I

    .line 38
    .line 39
    .line 40
    move-result p4

    .line 41
    if-lez p4, :cond_0

    .line 42
    .line 43
    invoke-virtual {p3}, Landroid/content/ContentValues;->size()I

    .line 44
    .line 45
    .line 46
    move-result p4

    .line 47
    goto :goto_0

    .line 48
    :catchall_0
    move-exception p1

    .line 49
    goto/16 :goto_5

    .line 50
    .line 51
    :cond_0
    move p4, p1

    .line 52
    :goto_0
    const/16 v1, 0x29

    .line 53
    .line 54
    if-lez p4, :cond_4

    .line 55
    .line 56
    new-array p2, p4, [Ljava/lang/Object;

    .line 57
    .line 58
    invoke-virtual {p3}, Landroid/content/ContentValues;->keySet()Ljava/util/Set;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    move v3, p1

    .line 67
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 68
    .line 69
    .line 70
    move-result v4

    .line 71
    if-eqz v4, :cond_2

    .line 72
    .line 73
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    check-cast v4, Ljava/lang/String;

    .line 78
    .line 79
    if-lez v3, :cond_1

    .line 80
    .line 81
    const-string v5, ","

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_1
    const-string v5, ""

    .line 85
    .line 86
    :goto_2
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    add-int/lit8 v5, v3, 0x1

    .line 93
    .line 94
    invoke-virtual {p3, v4}, Landroid/content/ContentValues;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    aput-object v4, p2, v3

    .line 99
    .line 100
    move v3, v5

    .line 101
    goto :goto_1

    .line 102
    :cond_2
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string p3, " VALUES ("

    .line 106
    .line 107
    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    :goto_3
    if-ge p1, p4, :cond_5

    .line 111
    .line 112
    if-lez p1, :cond_3

    .line 113
    .line 114
    const-string p3, ",?"

    .line 115
    .line 116
    goto :goto_4

    .line 117
    :cond_3
    const-string p3, "?"

    .line 118
    .line 119
    :goto_4
    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    add-int/lit8 p1, p1, 0x1

    .line 123
    .line 124
    goto :goto_3

    .line 125
    :cond_4
    new-instance p1, Ljava/lang/StringBuilder;

    .line 126
    .line 127
    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    .line 128
    .line 129
    .line 130
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    const-string p2, ") VALUES (NULL"

    .line 134
    .line 135
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    const/4 p2, 0x0

    .line 146
    :cond_5
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    new-instance p1, Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 150
    .line 151
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object p3

    .line 155
    invoke-direct {p1, p0, p3, p2}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 156
    .line 157
    .line 158
    :try_start_1
    invoke-virtual {p1}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;->executeInsert()J

    .line 159
    .line 160
    .line 161
    move-result-wide p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 162
    :try_start_2
    invoke-virtual {p1}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 163
    .line 164
    .line 165
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 166
    .line 167
    .line 168
    return-wide p2

    .line 169
    :catchall_1
    move-exception p2

    .line 170
    :try_start_3
    invoke-virtual {p1}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 171
    .line 172
    .line 173
    throw p2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 174
    :goto_5
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 175
    .line 176
    .line 177
    throw p1
.end method

.method public isDatabaseIntegrityOk()Z
    .locals 7

    .line 1
    const-string v0, "databaselist for: "

    .line 2
    .line 3
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getAttachedDbs()Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 14
    .line 15
    new-instance v2, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getPath()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v0, " couldn\'t be retrieved. probably because the database is closed"

    .line 28
    .line 29
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw v1
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    :catchall_0
    move-exception v0

    .line 41
    goto/16 :goto_3

    .line 42
    .line 43
    :catch_0
    :try_start_1
    new-instance v1, Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 46
    .line 47
    .line 48
    new-instance v0, Landroid/util/Pair;

    .line 49
    .line 50
    const-string v2, "main"

    .line 51
    .line 52
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getPath()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    invoke-direct {v0, v2, v3}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    :goto_0
    const/4 v0, 0x0

    .line 63
    move v2, v0

    .line 64
    :goto_1
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 65
    .line 66
    .line 67
    move-result v3

    .line 68
    if-ge v2, v3, :cond_3

    .line 69
    .line 70
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    check-cast v3, Landroid/util/Pair;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 75
    .line 76
    const/4 v4, 0x0

    .line 77
    :try_start_2
    new-instance v5, Ljava/lang/StringBuilder;

    .line 78
    .line 79
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 80
    .line 81
    .line 82
    const-string v6, "PRAGMA "

    .line 83
    .line 84
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    iget-object v6, v3, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v6, Ljava/lang/String;

    .line 90
    .line 91
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string v6, ".integrity_check(1);"

    .line 95
    .line 96
    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v5

    .line 103
    invoke-virtual {p0, v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    invoke-virtual {v4}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;->simpleQueryForString()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    const-string v6, "ok"

    .line 112
    .line 113
    invoke-virtual {v5, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 114
    .line 115
    .line 116
    move-result v6

    .line 117
    if-nez v6, :cond_1

    .line 118
    .line 119
    const-string v1, "SQLiteDatabase"

    .line 120
    .line 121
    new-instance v2, Ljava/lang/StringBuilder;

    .line 122
    .line 123
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 124
    .line 125
    .line 126
    const-string v6, "PRAGMA integrity_check on "

    .line 127
    .line 128
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 129
    .line 130
    .line 131
    iget-object v3, v3, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast v3, Ljava/lang/String;

    .line 134
    .line 135
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    const-string v3, " returned: "

    .line 139
    .line 140
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 144
    .line 145
    .line 146
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    invoke-static {v1, v2}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 151
    .line 152
    .line 153
    :try_start_3
    invoke-virtual {v4}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 154
    .line 155
    .line 156
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 157
    .line 158
    .line 159
    return v0

    .line 160
    :catchall_1
    move-exception v0

    .line 161
    goto :goto_2

    .line 162
    :cond_1
    :try_start_4
    invoke-virtual {v4}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 163
    .line 164
    .line 165
    add-int/lit8 v2, v2, 0x1

    .line 166
    .line 167
    goto :goto_1

    .line 168
    :goto_2
    if-eqz v4, :cond_2

    .line 169
    .line 170
    invoke-virtual {v4}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 171
    .line 172
    .line 173
    :cond_2
    throw v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 174
    :cond_3
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 175
    .line 176
    .line 177
    const/4 p0, 0x1

    .line 178
    return p0

    .line 179
    :goto_3
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 180
    .line 181
    .line 182
    throw v0
.end method

.method public isDbLockedByCurrentThread()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getThreadSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->hasConnection()Z

    .line 9
    .line 10
    .line 11
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 13
    .line 14
    .line 15
    return v0

    .line 16
    :catchall_0
    move-exception v0

    .line 17
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 18
    .line 19
    .line 20
    throw v0
.end method

.method public isDbLockedByOtherThreads()Z
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public bridge synthetic isExecPerConnectionSQLSupported()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public isInMemoryDatabase()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 5
    .line 6
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->isInMemoryDb()Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    monitor-exit v0

    .line 11
    return p0

    .line 12
    :catchall_0
    move-exception p0

    .line 13
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    throw p0
.end method

.method public isOpen()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 5
    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    const/4 p0, 0x1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    :goto_0
    monitor-exit v0

    .line 12
    return p0

    .line 13
    :catchall_0
    move-exception p0

    .line 14
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    throw p0
.end method

.method public isReadOnly()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isReadOnlyLocked()Z

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    monitor-exit v0

    .line 9
    return p0

    .line 10
    :catchall_0
    move-exception p0

    .line 11
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    throw p0
.end method

.method public isWriteAheadLoggingEnabled()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->throwIfNotOpenLocked()V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 8
    .line 9
    iget p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 10
    .line 11
    const/high16 v1, 0x20000000

    .line 12
    .line 13
    and-int/2addr p0, v1

    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    const/4 p0, 0x1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    :goto_0
    monitor-exit v0

    .line 20
    return p0

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    throw p0
.end method

.method public markTableSyncable(Ljava/lang/String;Ljava/lang/String;)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    return-void
.end method

.method public markTableSyncable(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 2
    return-void
.end method

.method public needUpgrade(I)Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getVersion()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-le p1, p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public onAllReferencesReleased()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->dispose(Z)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public onCorruption(Landroid/database/sqlite/SQLiteException;)V
    .locals 2

    .line 1
    const v0, 0x124fc

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getLabel()Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object v1

    .line 8
    invoke-static {v0, v1}, Landroid/util/EventLog;->writeEvent(ILjava/lang/String;)I

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mErrorHandler:Lnet/zetetic/database/DatabaseErrorHandler;

    .line 12
    .line 13
    invoke-interface {v0, p0, p1}, Lnet/zetetic/database/DatabaseErrorHandler;->onCorruption(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Landroid/database/sqlite/SQLiteException;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public query(Landroidx/sqlite/db/SupportSQLiteQuery;)Landroid/database/Cursor;
    .locals 1

    const/4 v0, 0x0

    .line 3
    invoke-virtual {p0, p1, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->query(Landroidx/sqlite/db/SupportSQLiteQuery;Landroid/os/CancellationSignal;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public query(Landroidx/sqlite/db/SupportSQLiteQuery;Landroid/os/CancellationSignal;)Landroid/database/Cursor;
    .locals 4

    .line 4
    const-string v0, ""

    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 5
    :try_start_0
    invoke-interface {p1}, Landroidx/sqlite/db/SupportSQLiteQuery;->c()Ljava/lang/String;

    move-result-object v1

    .line 6
    new-instance v2, Lnet/zetetic/database/sqlcipher/SQLiteDirectCursorDriver;

    invoke-direct {v2, p0, v1, v0, p2}, Lnet/zetetic/database/sqlcipher/SQLiteDirectCursorDriver;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)V

    .line 7
    new-instance v3, Lnet/zetetic/database/sqlcipher/SQLiteQuery;

    invoke-direct {v3, p0, v1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteQuery;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;Landroid/os/CancellationSignal;)V

    .line 8
    invoke-interface {p1, v3}, Landroidx/sqlite/db/SupportSQLiteQuery;->f(Lva/a;)V

    .line 9
    new-instance p1, Lnet/zetetic/database/sqlcipher/SQLiteCursor;

    invoke-direct {p1, v2, v0, v3}, Lnet/zetetic/database/sqlcipher/SQLiteCursor;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteQuery;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    return-object p1

    :catchall_0
    move-exception p1

    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 11
    throw p1
.end method

.method public query(Ljava/lang/String;)Landroid/database/Cursor;
    .locals 1

    const/4 v0, 0x0

    .line 1
    new-array v0, v0, [Ljava/lang/Object;

    invoke-virtual {p0, p1, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/Object;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public query(Ljava/lang/String;[Ljava/lang/Object;)Landroid/database/Cursor;
    .locals 0

    .line 2
    invoke-virtual {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/Object;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 10

    const/4 v1, 0x0

    const/4 v9, 0x0

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move-object v6, p5

    move-object/from16 v7, p6

    move-object/from16 v8, p7

    .line 14
    invoke-virtual/range {v0 .. v9}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->query(ZLjava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 10

    const/4 v1, 0x0

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move-object v6, p5

    move-object/from16 v7, p6

    move-object/from16 v8, p7

    move-object/from16 v9, p8

    .line 15
    invoke-virtual/range {v0 .. v9}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->query(ZLjava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public query(ZLjava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 12

    const/4 v1, 0x0

    const/4 v11, 0x0

    move-object v0, p0

    move v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move-object/from16 v8, p7

    move-object/from16 v9, p8

    move-object/from16 v10, p9

    .line 12
    invoke-virtual/range {v0 .. v11}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->queryWithFactory(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ZLjava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public query(ZLjava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;
    .locals 12

    const/4 v1, 0x0

    move-object v0, p0

    move v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move-object/from16 v8, p7

    move-object/from16 v9, p8

    move-object/from16 v10, p9

    move-object/from16 v11, p10

    .line 13
    invoke-virtual/range {v0 .. v11}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->queryWithFactory(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ZLjava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public queryWithFactory(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ZLjava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 12

    const/4 v11, 0x0

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move-object v3, p3

    move-object/from16 v4, p4

    move-object/from16 v5, p5

    move-object/from16 v6, p6

    move-object/from16 v7, p7

    move-object/from16 v8, p8

    move-object/from16 v9, p9

    move-object/from16 v10, p10

    .line 1
    invoke-virtual/range {v0 .. v11}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->queryWithFactory(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ZLjava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public queryWithFactory(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ZLjava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;
    .locals 8

    .line 2
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    move v0, p2

    move-object v1, p3

    move-object v2, p4

    move-object v3, p5

    move-object v4, p7

    move-object/from16 v5, p8

    move-object/from16 v6, p9

    move-object/from16 v7, p10

    .line 3
    :try_start_0
    invoke-static/range {v0 .. v7}, Lnet/zetetic/database/sqlcipher/SQLiteQueryBuilder;->buildQueryString(ZLjava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    .line 4
    invoke-static {p3}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->findEditTable(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    move-object v1, p0

    move-object v2, p1

    move-object v4, p6

    move-object/from16 v6, p11

    .line 5
    invoke-virtual/range {v1 .. v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->rawQueryWithFactory(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 6
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    return-object p1

    :catchall_0
    move-exception v0

    move-object p1, v0

    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 7
    throw p1
.end method

.method public varargs rawExecSQL(Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 5
    .line 6
    invoke-direct {v0, p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    .line 8
    .line 9
    :try_start_1
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;->executeRaw()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 10
    .line 11
    .line 12
    :try_start_2
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :catchall_0
    move-exception p1

    .line 20
    goto :goto_0

    .line 21
    :catchall_1
    move-exception p1

    .line 22
    :try_start_3
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 23
    .line 24
    .line 25
    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 26
    :goto_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 27
    .line 28
    .line 29
    throw p1
.end method

.method public varargs rawQuery(Ljava/lang/String;[Ljava/lang/Object;)Landroid/database/Cursor;
    .locals 2

    .line 2
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 3
    :try_start_0
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteDirectCursorDriver;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, v1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteDirectCursorDriver;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)V

    .line 4
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mCursorFactory:Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;

    invoke-virtual {v0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteDirectCursorDriver;->query(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;[Ljava/lang/Object;)Landroid/database/Cursor;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    return-object p1

    :catchall_0
    move-exception p1

    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 6
    throw p1
.end method

.method public rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;
    .locals 6

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v1, 0x0

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    .line 1
    invoke-virtual/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->rawQueryWithFactory(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public rawQuery(Ljava/lang/String;[Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;
    .locals 6

    const/4 v1, 0x0

    const/4 v4, 0x0

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v5, p3

    .line 7
    invoke-virtual/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->rawQueryWithFactory(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public rawQueryWithFactory(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 6

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    .line 1
    invoke-virtual/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->rawQueryWithFactory(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;

    move-result-object p0

    return-object p0
.end method

.method public rawQueryWithFactory(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;
    .locals 1

    .line 2
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 3
    :try_start_0
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteDirectCursorDriver;

    invoke-direct {v0, p0, p2, p4, p5}, Lnet/zetetic/database/sqlcipher/SQLiteDirectCursorDriver;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)V

    if-eqz p1, :cond_0

    goto :goto_0

    .line 4
    :cond_0
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mCursorFactory:Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;

    :goto_0
    invoke-interface {v0, p1, p3}, Lnet/zetetic/database/sqlcipher/SQLiteCursorDriver;->query(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;[Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    return-object p1

    :catchall_0
    move-exception p1

    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 6
    throw p1
.end method

.method public reopenReadWrite()V
    .locals 4

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->throwIfNotOpenLocked()V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isReadOnlyLocked()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    monitor-exit v0

    .line 14
    return-void

    .line 15
    :catchall_0
    move-exception p0

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 18
    .line 19
    iget v2, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 20
    .line 21
    and-int/lit8 v3, v2, -0x2

    .line 22
    .line 23
    iput v3, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 24
    .line 25
    :try_start_1
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 26
    .line 27
    invoke-virtual {v3, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->reconfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 28
    .line 29
    .line 30
    :try_start_2
    monitor-exit v0

    .line 31
    return-void

    .line 32
    :catch_0
    move-exception v1

    .line 33
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 34
    .line 35
    iput v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 36
    .line 37
    throw v1

    .line 38
    :goto_0
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 39
    throw p0
.end method

.method public replace(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J
    .locals 1

    .line 1
    const/4 v0, 0x5

    .line 2
    :try_start_0
    invoke-virtual {p0, p1, p2, p3, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    .line 3
    .line 4
    .line 5
    move-result-wide p0
    :try_end_0
    .catch Landroid/database/SQLException; {:try_start_0 .. :try_end_0} :catch_0

    .line 6
    return-wide p0

    .line 7
    :catch_0
    move-exception p0

    .line 8
    const-string p1, "SQLiteDatabase"

    .line 9
    .line 10
    const-string p2, "Error inserting"

    .line 11
    .line 12
    invoke-static {p1, p2, p0}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 13
    .line 14
    .line 15
    const-wide/16 p0, -0x1

    .line 16
    .line 17
    return-wide p0
.end method

.method public replaceOrThrow(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J
    .locals 1

    .line 1
    const/4 v0, 0x5

    .line 2
    invoke-virtual {p0, p1, p2, p3, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->insertWithOnConflict(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;I)J

    .line 3
    .line 4
    .line 5
    move-result-wide p0

    .line 6
    return-wide p0
.end method

.method public setForeignKeyConstraintsEnabled(Z)V
    .locals 3

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->throwIfNotOpenLocked()V

    .line 5
    .line 6
    .line 7
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 8
    .line 9
    iget-boolean v2, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->foreignKeyConstraintsEnabled:Z

    .line 10
    .line 11
    if-ne v2, p1, :cond_0

    .line 12
    .line 13
    monitor-exit v0

    .line 14
    return-void

    .line 15
    :catchall_0
    move-exception p0

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    iput-boolean p1, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->foreignKeyConstraintsEnabled:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    .line 19
    :try_start_1
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 20
    .line 21
    invoke-virtual {v2, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->reconfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 22
    .line 23
    .line 24
    :try_start_2
    monitor-exit v0

    .line 25
    return-void

    .line 26
    :catch_0
    move-exception v1

    .line 27
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 28
    .line 29
    xor-int/lit8 p1, p1, 0x1

    .line 30
    .line 31
    iput-boolean p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->foreignKeyConstraintsEnabled:Z

    .line 32
    .line 33
    throw v1

    .line 34
    :goto_0
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 35
    throw p0
.end method

.method public setLocale(Ljava/util/Locale;)V
    .locals 3

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->throwIfNotOpenLocked()V

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 10
    .line 11
    iget-object v2, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->locale:Ljava/util/Locale;

    .line 12
    .line 13
    iput-object p1, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->locale:Ljava/util/Locale;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    .line 15
    :try_start_1
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 16
    .line 17
    invoke-virtual {p1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->reconfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 18
    .line 19
    .line 20
    :try_start_2
    monitor-exit v0

    .line 21
    return-void

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    goto :goto_0

    .line 24
    :catch_0
    move-exception p1

    .line 25
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 26
    .line 27
    iput-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->locale:Ljava/util/Locale;

    .line 28
    .line 29
    throw p1

    .line 30
    :goto_0
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 31
    throw p0

    .line 32
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 33
    .line 34
    const-string p1, "locale must not be null."

    .line 35
    .line 36
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw p0
.end method

.method public setLockingEnabled(Z)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    return-void
.end method

.method public setMaxSqlCacheSize(I)V
    .locals 3

    .line 1
    const/16 v0, 0x64

    .line 2
    .line 3
    if-gt p1, v0, :cond_0

    .line 4
    .line 5
    if-ltz p1, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mLock:Ljava/lang/Object;

    .line 8
    .line 9
    monitor-enter v0

    .line 10
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->throwIfNotOpenLocked()V

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 14
    .line 15
    iget v2, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->maxSqlCacheSize:I

    .line 16
    .line 17
    iput p1, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->maxSqlCacheSize:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    .line 19
    :try_start_1
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConnectionPoolLocked:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 20
    .line 21
    invoke-virtual {p1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->reconfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 22
    .line 23
    .line 24
    :try_start_2
    monitor-exit v0

    .line 25
    return-void

    .line 26
    :catchall_0
    move-exception p0

    .line 27
    goto :goto_0

    .line 28
    :catch_0
    move-exception p1

    .line 29
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->mConfigurationLocked:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 30
    .line 31
    iput v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->maxSqlCacheSize:I

    .line 32
    .line 33
    throw p1

    .line 34
    :goto_0
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 35
    throw p0

    .line 36
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "expected value between 0 and 100"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0
.end method

.method public setMaximumSize(J)J
    .locals 6

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getPageSize()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    div-long v2, p1, v0

    .line 6
    .line 7
    rem-long/2addr p1, v0

    .line 8
    const-wide/16 v4, 0x0

    .line 9
    .line 10
    cmp-long p1, p1, v4

    .line 11
    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    const-wide/16 p1, 0x1

    .line 15
    .line 16
    add-long/2addr v2, p1

    .line 17
    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    .line 18
    .line 19
    const-string p2, "PRAGMA max_page_count = "

    .line 20
    .line 21
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    const/4 p2, 0x0

    .line 32
    invoke-static {p0, p1, p2}, Lnet/zetetic/database/DatabaseUtils;->longForQuery(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/String;)J

    .line 33
    .line 34
    .line 35
    move-result-wide p0

    .line 36
    mul-long/2addr p0, v0

    .line 37
    return-wide p0
.end method

.method public setPageSize(J)V
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "PRAGMA page_size = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1, p2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public setTransactionSuccessful()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getThreadSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->setTransactionSuccessful()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :catchall_0
    move-exception v0

    .line 16
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 17
    .line 18
    .line 19
    throw v0
.end method

.method public setVersion(I)V
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "PRAGMA user_version = "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SQLiteDatabase: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getPath()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public update(Ljava/lang/String;ILandroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/Object;)I
    .locals 8

    const/4 v0, 0x0

    if-nez p5, :cond_0

    move v1, v0

    goto :goto_0

    .line 1
    :cond_0
    array-length v1, p5

    .line 2
    :goto_0
    new-array v6, v1, [Ljava/lang/String;

    :goto_1
    if-ge v0, v1, :cond_1

    .line 3
    aget-object v2, p5, v0

    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v2

    aput-object v2, v6, v0

    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :cond_1
    move-object v2, p0

    move-object v3, p1

    move v7, p2

    move-object v4, p3

    move-object v5, p4

    .line 4
    invoke-virtual/range {v2 .. v7}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->updateWithOnConflict(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;I)I

    move-result p0

    return p0
.end method

.method public update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    .locals 6

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    .line 5
    invoke-virtual/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->updateWithOnConflict(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;I)I

    move-result p0

    return p0
.end method

.method public updateWithOnConflict(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;I)I
    .locals 6

    .line 1
    if-eqz p2, :cond_5

    .line 2
    .line 3
    invoke-virtual {p2}, Landroid/content/ContentValues;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_5

    .line 8
    .line 9
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 10
    .line 11
    .line 12
    :try_start_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const/16 v1, 0x78

    .line 15
    .line 16
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 17
    .line 18
    .line 19
    const-string v1, "UPDATE "

    .line 20
    .line 21
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    sget-object v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->CONFLICT_VALUES:[Ljava/lang/String;

    .line 25
    .line 26
    aget-object p5, v1, p5

    .line 27
    .line 28
    invoke-virtual {v0, p5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    const-string p1, " SET "

    .line 35
    .line 36
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {p2}, Landroid/content/ContentValues;->size()I

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    if-nez p4, :cond_0

    .line 44
    .line 45
    move p5, p1

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    array-length p5, p4

    .line 48
    add-int/2addr p5, p1

    .line 49
    :goto_0
    new-array v1, p5, [Ljava/lang/Object;

    .line 50
    .line 51
    invoke-virtual {p2}, Landroid/content/ContentValues;->keySet()Ljava/util/Set;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    const/4 v3, 0x0

    .line 60
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    if-eqz v4, :cond_2

    .line 65
    .line 66
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v4

    .line 70
    check-cast v4, Ljava/lang/String;

    .line 71
    .line 72
    if-lez v3, :cond_1

    .line 73
    .line 74
    const-string v5, ","

    .line 75
    .line 76
    goto :goto_2

    .line 77
    :catchall_0
    move-exception p1

    .line 78
    goto :goto_4

    .line 79
    :cond_1
    const-string v5, ""

    .line 80
    .line 81
    :goto_2
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    add-int/lit8 v5, v3, 0x1

    .line 88
    .line 89
    invoke-virtual {p2, v4}, Landroid/content/ContentValues;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v4

    .line 93
    aput-object v4, v1, v3

    .line 94
    .line 95
    const-string v3, "=?"

    .line 96
    .line 97
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    move v3, v5

    .line 101
    goto :goto_1

    .line 102
    :cond_2
    if-eqz p4, :cond_3

    .line 103
    .line 104
    move p2, p1

    .line 105
    :goto_3
    if-ge p2, p5, :cond_3

    .line 106
    .line 107
    sub-int v2, p2, p1

    .line 108
    .line 109
    aget-object v2, p4, v2

    .line 110
    .line 111
    aput-object v2, v1, p2

    .line 112
    .line 113
    add-int/lit8 p2, p2, 0x1

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_3
    invoke-static {p3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 117
    .line 118
    .line 119
    move-result p1

    .line 120
    if-nez p1, :cond_4

    .line 121
    .line 122
    const-string p1, " WHERE "

    .line 123
    .line 124
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    :cond_4
    new-instance p1, Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 131
    .line 132
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object p2

    .line 136
    invoke-direct {p1, p0, p2, v1}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 137
    .line 138
    .line 139
    :try_start_1
    invoke-virtual {p1}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;->executeUpdateDelete()I

    .line 140
    .line 141
    .line 142
    move-result p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 143
    :try_start_2
    invoke-virtual {p1}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 144
    .line 145
    .line 146
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 147
    .line 148
    .line 149
    return p2

    .line 150
    :catchall_1
    move-exception p2

    .line 151
    :try_start_3
    invoke-virtual {p1}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 152
    .line 153
    .line 154
    throw p2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 155
    :goto_4
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 156
    .line 157
    .line 158
    throw p1

    .line 159
    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 160
    .line 161
    const-string p1, "Empty values"

    .line 162
    .line 163
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    throw p0
.end method

.method public validateSql(Ljava/lang/String;Landroid/os/CancellationSignal;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getThreadSession()Lnet/zetetic/database/sqlcipher/SQLiteSession;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-virtual {p0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getThreadDefaultConnectionFlags(Z)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-virtual {v0, p1, p0, p2, v1}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->prepare(Ljava/lang/String;ILandroid/os/CancellationSignal;Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public yieldIfContended()Z
    .locals 3
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    const-wide/16 v1, -0x1

    .line 3
    .line 4
    invoke-direct {p0, v0, v1, v2}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->yieldIfContendedHelper(ZJ)Z

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    return p0
.end method

.method public yieldIfContendedSafely()Z
    .locals 3

    const/4 v0, 0x1

    const-wide/16 v1, -0x1

    .line 1
    invoke-direct {p0, v0, v1, v2}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->yieldIfContendedHelper(ZJ)Z

    move-result p0

    return p0
.end method

.method public yieldIfContendedSafely(J)Z
    .locals 1

    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, v0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->yieldIfContendedHelper(ZJ)Z

    move-result p0

    return p0
.end method
