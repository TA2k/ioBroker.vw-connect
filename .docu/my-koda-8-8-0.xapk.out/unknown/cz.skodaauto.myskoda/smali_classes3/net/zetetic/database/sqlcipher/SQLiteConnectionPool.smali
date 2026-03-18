.class public final Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;,
        Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;
    }
.end annotation


# static fields
.field static final synthetic $assertionsDisabled:Z = false

.field public static final CONNECTION_FLAG_INTERACTIVE:I = 0x4

.field public static final CONNECTION_FLAG_PRIMARY_CONNECTION_AFFINITY:I = 0x2

.field public static final CONNECTION_FLAG_READ_ONLY:I = 0x1

.field private static final CONNECTION_POOL_BUSY_MILLIS:J = 0x7530L

.field private static final TAG:Ljava/lang/String; = "SQLiteConnectionPool"


# instance fields
.field private final mAcquiredConnections:Ljava/util/WeakHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/WeakHashMap<",
            "Lnet/zetetic/database/sqlcipher/SQLiteConnection;",
            "Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;",
            ">;"
        }
    .end annotation
.end field

.field private final mAvailableNonPrimaryConnections:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lnet/zetetic/database/sqlcipher/SQLiteConnection;",
            ">;"
        }
    .end annotation
.end field

.field private mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

.field private final mCloseGuard:Lnet/zetetic/database/sqlcipher/CloseGuard;

.field private final mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

.field private final mConnectionLeaked:Ljava/util/concurrent/atomic/AtomicBoolean;

.field private mConnectionWaiterPool:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

.field private mConnectionWaiterQueue:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

.field private mIsOpen:Z

.field private final mLock:Ljava/lang/Object;

.field private mMaxConnectionPoolSize:I

.field private mNextConnectionId:I


# direct methods
.method private constructor <init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lnet/zetetic/database/sqlcipher/CloseGuard;->get()Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mCloseGuard:Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 9
    .line 10
    new-instance v0, Ljava/lang/Object;

    .line 11
    .line 12
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mLock:Ljava/lang/Object;

    .line 16
    .line 17
    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 18
    .line 19
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>()V

    .line 20
    .line 21
    .line 22
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionLeaked:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 23
    .line 24
    new-instance v0, Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 30
    .line 31
    new-instance v0, Ljava/util/WeakHashMap;

    .line 32
    .line 33
    invoke-direct {v0}, Ljava/util/WeakHashMap;-><init>()V

    .line 34
    .line 35
    .line 36
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 37
    .line 38
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 39
    .line 40
    invoke-direct {v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V

    .line 41
    .line 42
    .line 43
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 44
    .line 45
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->setMaxConnectionPoolSizeLocked()V

    .line 46
    .line 47
    .line 48
    return-void
.end method

.method public static bridge synthetic a(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public static bridge synthetic b(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->cancelConnectionWaiterLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private cancelConnectionWaiterLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;)V
    .locals 3

    .line 1
    iget-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mAssignedConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 2
    .line 3
    if-nez v0, :cond_3

    .line 4
    .line 5
    iget-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mException:Ljava/lang/RuntimeException;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_2

    .line 10
    :cond_0
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionWaiterQueue:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    :goto_0
    if-eq v0, p1, :cond_1

    .line 14
    .line 15
    iget-object v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 16
    .line 17
    move-object v2, v1

    .line 18
    move-object v1, v0

    .line 19
    move-object v0, v2

    .line 20
    goto :goto_0

    .line 21
    :cond_1
    if-eqz v1, :cond_2

    .line 22
    .line 23
    iget-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 24
    .line 25
    iput-object v0, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 26
    .line 27
    goto :goto_1

    .line 28
    :cond_2
    iget-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 29
    .line 30
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionWaiterQueue:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 31
    .line 32
    :goto_1
    new-instance v0, Landroid/os/OperationCanceledException;

    .line 33
    .line 34
    invoke-direct {v0}, Landroid/os/OperationCanceledException;-><init>()V

    .line 35
    .line 36
    .line 37
    iput-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mException:Ljava/lang/RuntimeException;

    .line 38
    .line 39
    iget-object p1, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mThread:Ljava/lang/Thread;

    .line 40
    .line 41
    invoke-static {p1}, Ljava/util/concurrent/locks/LockSupport;->unpark(Ljava/lang/Thread;)V

    .line 42
    .line 43
    .line 44
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->wakeConnectionWaitersLocked()V

    .line 45
    .line 46
    .line 47
    :cond_3
    :goto_2
    return-void
.end method

.method private closeAvailableConnectionsAndLogExceptionsLocked()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeAvailableNonPrimaryConnectionsAndLogExceptionsLocked()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeConnectionAndLogExceptionsLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method private closeAvailableNonPrimaryConnectionsAndLogExceptionsLocked()V
    .locals 3

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    :goto_0
    if-ge v1, v0, :cond_0

    .line 9
    .line 10
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    check-cast v2, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 17
    .line 18
    invoke-direct {p0, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeConnectionAndLogExceptionsLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V

    .line 19
    .line 20
    .line 21
    add-int/lit8 v1, v1, 0x1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/util/ArrayList;->clear()V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method private closeConnectionAndLogExceptionsLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V
    .locals 2

    .line 1
    :try_start_0
    invoke-virtual {p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->close()V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 2
    .line 3
    .line 4
    return-void

    .line 5
    :catch_0
    move-exception p0

    .line 6
    new-instance v0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    const-string v1, "Failed to close connection, its fate is now in the hands of the merciful GC: "

    .line 9
    .line 10
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    const-string v0, "SQLiteConnectionPool"

    .line 21
    .line 22
    invoke-static {v0, p1, p0}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method private closeExcessConnectionsAndLogExceptionsLocked()V
    .locals 3

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    :goto_0
    add-int/lit8 v1, v0, -0x1

    .line 8
    .line 9
    iget v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mMaxConnectionPoolSize:I

    .line 10
    .line 11
    add-int/lit8 v2, v2, -0x1

    .line 12
    .line 13
    if-le v0, v2, :cond_0

    .line 14
    .line 15
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 22
    .line 23
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeConnectionAndLogExceptionsLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V

    .line 24
    .line 25
    .line 26
    move v0, v1

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    return-void
.end method

.method private discardAcquiredConnectionsLocked()V
    .locals 1

    .line 1
    sget-object v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;->DISCARD:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->markAcquiredConnectionsLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private dispose(Z)V
    .locals 4

    .line 1
    const-string v0, "The connection pool for "

    .line 2
    .line 3
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mCloseGuard:Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 4
    .line 5
    if-eqz v1, :cond_1

    .line 6
    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v1}, Lnet/zetetic/database/sqlcipher/CloseGuard;->warnIfOpen()V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mCloseGuard:Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 13
    .line 14
    invoke-virtual {v1}, Lnet/zetetic/database/sqlcipher/CloseGuard;->close()V

    .line 15
    .line 16
    .line 17
    :cond_1
    if-nez p1, :cond_3

    .line 18
    .line 19
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mLock:Ljava/lang/Object;

    .line 20
    .line 21
    monitor-enter p1

    .line 22
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->throwIfClosedLocked()V

    .line 23
    .line 24
    .line 25
    const/4 v1, 0x0

    .line 26
    iput-boolean v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mIsOpen:Z

    .line 27
    .line 28
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeAvailableConnectionsAndLogExceptionsLocked()V

    .line 29
    .line 30
    .line 31
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 32
    .line 33
    invoke-virtual {v1}, Ljava/util/WeakHashMap;->size()I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_2

    .line 38
    .line 39
    const-string v2, "SQLiteConnectionPool"

    .line 40
    .line 41
    new-instance v3, Ljava/lang/StringBuilder;

    .line 42
    .line 43
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 47
    .line 48
    iget-object v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->label:Ljava/lang/String;

    .line 49
    .line 50
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v0, " has been closed but there are still "

    .line 54
    .line 55
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v0, " connections in use.  They will be closed as they are released back to the pool."

    .line 62
    .line 63
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    invoke-static {v2, v0}, Lnet/zetetic/database/Logger;->i(Ljava/lang/String;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :catchall_0
    move-exception p0

    .line 75
    goto :goto_1

    .line 76
    :cond_2
    :goto_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->wakeConnectionWaitersLocked()V

    .line 77
    .line 78
    .line 79
    monitor-exit p1

    .line 80
    return-void

    .line 81
    :goto_1
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 82
    throw p0

    .line 83
    :cond_3
    return-void
.end method

.method private finishAcquireConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;I)V
    .locals 3

    .line 1
    and-int/lit8 v0, p2, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    :goto_0
    :try_start_0
    invoke-virtual {p1, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setOnlyAllowReadOnlyOperations(Z)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 12
    .line 13
    sget-object v1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;->NORMAL:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;

    .line 14
    .line 15
    invoke-virtual {v0, p1, v1}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :catch_0
    move-exception v0

    .line 20
    new-instance v1, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    const-string v2, "Failed to prepare acquired connection for session, closing it: "

    .line 23
    .line 24
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v2, ", connectionFlags="

    .line 31
    .line 32
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    const-string v1, "SQLiteConnectionPool"

    .line 43
    .line 44
    invoke-static {v1, p2}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeConnectionAndLogExceptionsLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V

    .line 48
    .line 49
    .line 50
    throw v0
.end method

.method private static getPriority(I)I
    .locals 0

    .line 1
    and-int/lit8 p0, p0, 0x4

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method private isSessionBlockingImportantConnectionWaitersLocked(ZI)Z
    .locals 1

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionWaiterQueue:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 2
    .line 3
    if-eqz p0, :cond_4

    .line 4
    .line 5
    invoke-static {p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->getPriority(I)I

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    :cond_0
    iget v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mPriority:I

    .line 10
    .line 11
    if-le p2, v0, :cond_1

    .line 12
    .line 13
    goto :goto_1

    .line 14
    :cond_1
    if-nez p1, :cond_3

    .line 15
    .line 16
    iget-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mWantPrimaryConnection:Z

    .line 17
    .line 18
    if-nez v0, :cond_2

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_2
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 27
    return p0

    .line 28
    :cond_4
    :goto_1
    const/4 p0, 0x0

    .line 29
    return p0
.end method

.method private logConnectionPoolBusyLocked(JI)V
    .locals 4

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "The connection pool for database \'"

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 13
    .line 14
    iget-object v2, v2, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->label:Ljava/lang/String;

    .line 15
    .line 16
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v2, "\' has been unable to grant a connection to thread "

    .line 20
    .line 21
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/lang/Thread;->getId()J

    .line 25
    .line 26
    .line 27
    move-result-wide v2

    .line 28
    invoke-virtual {v1, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v2, " ("

    .line 32
    .line 33
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v0, ") with flags 0x"

    .line 44
    .line 45
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-static {p3}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p3

    .line 52
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const-string p3, " for "

    .line 56
    .line 57
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    long-to-float p1, p1

    .line 61
    const p2, 0x3a83126f    # 0.001f

    .line 62
    .line 63
    .line 64
    mul-float/2addr p1, p2

    .line 65
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string p1, " seconds.\n"

    .line 69
    .line 70
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    new-instance p1, Ljava/util/ArrayList;

    .line 74
    .line 75
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 76
    .line 77
    .line 78
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 79
    .line 80
    invoke-virtual {p2}, Ljava/util/WeakHashMap;->isEmpty()Z

    .line 81
    .line 82
    .line 83
    move-result p2

    .line 84
    const/4 p3, 0x0

    .line 85
    if-nez p2, :cond_1

    .line 86
    .line 87
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 88
    .line 89
    invoke-virtual {p2}, Ljava/util/WeakHashMap;->keySet()Ljava/util/Set;

    .line 90
    .line 91
    .line 92
    move-result-object p2

    .line 93
    invoke-interface {p2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    move v0, p3

    .line 98
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    if-eqz v2, :cond_2

    .line 103
    .line 104
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    check-cast v2, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 109
    .line 110
    invoke-virtual {v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->describeCurrentOperationUnsafe()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    if-eqz v2, :cond_0

    .line 115
    .line 116
    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    add-int/lit8 p3, p3, 0x1

    .line 120
    .line 121
    goto :goto_0

    .line 122
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 123
    .line 124
    goto :goto_0

    .line 125
    :cond_1
    move v0, p3

    .line 126
    :cond_2
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 127
    .line 128
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 129
    .line 130
    .line 131
    move-result p2

    .line 132
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 133
    .line 134
    if-eqz p0, :cond_3

    .line 135
    .line 136
    add-int/lit8 p2, p2, 0x1

    .line 137
    .line 138
    :cond_3
    const-string p0, "Connections: "

    .line 139
    .line 140
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 141
    .line 142
    .line 143
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 144
    .line 145
    .line 146
    const-string p0, " active, "

    .line 147
    .line 148
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 149
    .line 150
    .line 151
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 152
    .line 153
    .line 154
    const-string p0, " idle, "

    .line 155
    .line 156
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 160
    .line 161
    .line 162
    const-string p0, " available.\n"

    .line 163
    .line 164
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 165
    .line 166
    .line 167
    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 168
    .line 169
    .line 170
    move-result p0

    .line 171
    if-nez p0, :cond_4

    .line 172
    .line 173
    const-string p0, "\nRequests in progress:\n"

    .line 174
    .line 175
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 176
    .line 177
    .line 178
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 179
    .line 180
    .line 181
    move-result-object p0

    .line 182
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 183
    .line 184
    .line 185
    move-result p1

    .line 186
    if-eqz p1, :cond_4

    .line 187
    .line 188
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object p1

    .line 192
    check-cast p1, Ljava/lang/String;

    .line 193
    .line 194
    const-string p2, "  "

    .line 195
    .line 196
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 197
    .line 198
    .line 199
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 200
    .line 201
    .line 202
    const-string p1, "\n"

    .line 203
    .line 204
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 205
    .line 206
    .line 207
    goto :goto_1

    .line 208
    :cond_4
    const-string p0, "SQLiteConnectionPool"

    .line 209
    .line 210
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object p1

    .line 214
    invoke-static {p0, p1}, Lnet/zetetic/database/Logger;->w(Ljava/lang/String;Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    return-void
.end method

.method private markAcquiredConnectionsLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/WeakHashMap;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_2

    .line 8
    .line 9
    new-instance v0, Ljava/util/ArrayList;

    .line 10
    .line 11
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/util/WeakHashMap;->size()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/util/WeakHashMap;->entrySet()Ljava/util/Set;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    :cond_0
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eqz v2, :cond_1

    .line 35
    .line 36
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    check-cast v2, Ljava/util/Map$Entry;

    .line 41
    .line 42
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    check-cast v3, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;

    .line 47
    .line 48
    if-eq p1, v3, :cond_0

    .line 49
    .line 50
    sget-object v4, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;->DISCARD:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;

    .line 51
    .line 52
    if-eq v3, v4, :cond_0

    .line 53
    .line 54
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    check-cast v2, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 59
    .line 60
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 65
    .line 66
    .line 67
    move-result v1

    .line 68
    const/4 v2, 0x0

    .line 69
    :goto_1
    if-ge v2, v1, :cond_2

    .line 70
    .line 71
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 72
    .line 73
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    check-cast v4, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 78
    .line 79
    invoke-virtual {v3, v4, p1}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    add-int/lit8 v2, v2, 0x1

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_2
    return-void
.end method

.method private obtainConnectionWaiterLocked(Ljava/lang/Thread;JIZLjava/lang/String;I)Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;
    .locals 2

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionWaiterPool:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 6
    .line 7
    iput-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionWaiterPool:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    iput-object p0, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 14
    .line 15
    const/4 p0, 0x0

    .line 16
    invoke-direct {v0, p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;-><init>(I)V

    .line 17
    .line 18
    .line 19
    :goto_0
    iput-object p1, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mThread:Ljava/lang/Thread;

    .line 20
    .line 21
    iput-wide p2, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mStartTime:J

    .line 22
    .line 23
    iput p4, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mPriority:I

    .line 24
    .line 25
    iput-boolean p5, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mWantPrimaryConnection:Z

    .line 26
    .line 27
    iput-object p6, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mSql:Ljava/lang/String;

    .line 28
    .line 29
    iput p7, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mConnectionFlags:I

    .line 30
    .line 31
    return-object v0
.end method

.method public static open(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;
    .locals 1

    if-eqz p0, :cond_0

    .line 1
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    invoke-direct {v0, p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V

    .line 2
    invoke-direct {v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->open()V

    return-object v0

    .line 3
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string v0, "configuration must not be null."

    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method private open()V
    .locals 2

    .line 4
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    const/4 v1, 0x1

    invoke-direct {p0, v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->openConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;Z)Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    move-result-object v0

    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 5
    iput-boolean v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mIsOpen:Z

    .line 6
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mCloseGuard:Lnet/zetetic/database/sqlcipher/CloseGuard;

    const-string v0, "close"

    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/CloseGuard;->open(Ljava/lang/String;)V

    return-void
.end method

.method private openConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;Z)Lnet/zetetic/database/sqlcipher/SQLiteConnection;
    .locals 2

    .line 1
    iget v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mNextConnectionId:I

    .line 2
    .line 3
    add-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    iput v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mNextConnectionId:I

    .line 6
    .line 7
    invoke-static {p0, p1, v0, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->open(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;IZ)Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method private reconfigureAllConnectionsLocked()V
    .locals 7

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 2
    .line 3
    const-string v1, "SQLiteConnectionPool"

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    :try_start_0
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 8
    .line 9
    invoke-virtual {v0, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->reconfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 10
    .line 11
    .line 12
    goto :goto_0

    .line 13
    :catch_0
    move-exception v0

    .line 14
    new-instance v2, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string v3, "Failed to reconfigure available primary connection, closing it: "

    .line 17
    .line 18
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 22
    .line 23
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    invoke-static {v1, v2, v0}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 31
    .line 32
    .line 33
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 34
    .line 35
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeConnectionAndLogExceptionsLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V

    .line 36
    .line 37
    .line 38
    const/4 v0, 0x0

    .line 39
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 40
    .line 41
    :cond_0
    :goto_0
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    const/4 v2, 0x0

    .line 48
    :goto_1
    if-ge v2, v0, :cond_1

    .line 49
    .line 50
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 51
    .line 52
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    check-cast v3, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 57
    .line 58
    :try_start_1
    iget-object v4, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 59
    .line 60
    invoke-virtual {v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->reconfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_1

    .line 61
    .line 62
    .line 63
    goto :goto_2

    .line 64
    :catch_1
    move-exception v4

    .line 65
    new-instance v5, Ljava/lang/StringBuilder;

    .line 66
    .line 67
    const-string v6, "Failed to reconfigure available non-primary connection, closing it: "

    .line 68
    .line 69
    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v5

    .line 79
    invoke-static {v1, v5, v4}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 80
    .line 81
    .line 82
    invoke-direct {p0, v3}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeConnectionAndLogExceptionsLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V

    .line 83
    .line 84
    .line 85
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 86
    .line 87
    add-int/lit8 v4, v2, -0x1

    .line 88
    .line 89
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    add-int/lit8 v0, v0, -0x1

    .line 93
    .line 94
    move v2, v4

    .line 95
    :goto_2
    add-int/lit8 v2, v2, 0x1

    .line 96
    .line 97
    goto :goto_1

    .line 98
    :cond_1
    sget-object v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;->RECONFIGURE:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;

    .line 99
    .line 100
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->markAcquiredConnectionsLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;)V

    .line 101
    .line 102
    .line 103
    return-void
.end method

.method private recycleConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;)Z
    .locals 2

    .line 1
    sget-object v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;->RECONFIGURE:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;

    .line 2
    .line 3
    if-ne p2, v0, :cond_0

    .line 4
    .line 5
    :try_start_0
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 6
    .line 7
    invoke-virtual {p1, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->reconfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 8
    .line 9
    .line 10
    goto :goto_0

    .line 11
    :catch_0
    move-exception p2

    .line 12
    new-instance v0, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v1, "Failed to reconfigure released connection, closing it: "

    .line 15
    .line 16
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    const-string v1, "SQLiteConnectionPool"

    .line 27
    .line 28
    invoke-static {v1, v0, p2}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 29
    .line 30
    .line 31
    sget-object p2, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;->DISCARD:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;

    .line 32
    .line 33
    :cond_0
    :goto_0
    sget-object v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;->DISCARD:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;

    .line 34
    .line 35
    if-ne p2, v0, :cond_1

    .line 36
    .line 37
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeConnectionAndLogExceptionsLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V

    .line 38
    .line 39
    .line 40
    const/4 p0, 0x0

    .line 41
    return p0

    .line 42
    :cond_1
    const/4 p0, 0x1

    .line 43
    return p0
.end method

.method private recycleConnectionWaiterLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionWaiterPool:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 2
    .line 3
    iput-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iput-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mThread:Ljava/lang/Thread;

    .line 7
    .line 8
    iput-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mSql:Ljava/lang/String;

    .line 9
    .line 10
    iput-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mAssignedConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 11
    .line 12
    iput-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mException:Ljava/lang/RuntimeException;

    .line 13
    .line 14
    iget v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNonce:I

    .line 15
    .line 16
    add-int/lit8 v0, v0, 0x1

    .line 17
    .line 18
    iput v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNonce:I

    .line 19
    .line 20
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionWaiterPool:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 21
    .line 22
    return-void
.end method

.method private setMaxConnectionPoolSizeLocked()V
    .locals 2

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 2
    .line 3
    iget v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 4
    .line 5
    const/high16 v1, 0x20000000

    .line 6
    .line 7
    and-int/2addr v0, v1

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->getWALConnectionPoolSize()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    iput v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mMaxConnectionPoolSize:I

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    const/4 v0, 0x1

    .line 18
    iput v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mMaxConnectionPoolSize:I

    .line 19
    .line 20
    return-void
.end method

.method private throwIfClosedLocked()V
    .locals 1

    .line 1
    iget-boolean p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mIsOpen:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    const-string v0, "Cannot perform this operation because the connection pool has been closed."

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method private tryAcquireNonPrimaryConnectionLocked(Ljava/lang/String;I)Lnet/zetetic/database/sqlcipher/SQLiteConnection;
    .locals 6

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    const/4 v2, 0x1

    .line 9
    if-le v0, v2, :cond_1

    .line 10
    .line 11
    if-eqz p1, :cond_1

    .line 12
    .line 13
    move v3, v1

    .line 14
    :goto_0
    if-ge v3, v0, :cond_1

    .line 15
    .line 16
    iget-object v4, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    check-cast v4, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 23
    .line 24
    invoke-virtual {v4, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->isPreparedStatementInCache(Ljava/lang/String;)Z

    .line 25
    .line 26
    .line 27
    move-result v5

    .line 28
    if-eqz v5, :cond_0

    .line 29
    .line 30
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 31
    .line 32
    invoke-virtual {p1, v3}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    invoke-direct {p0, v4, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->finishAcquireConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;I)V

    .line 36
    .line 37
    .line 38
    return-object v4

    .line 39
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    if-lez v0, :cond_2

    .line 43
    .line 44
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 45
    .line 46
    sub-int/2addr v0, v2

    .line 47
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    check-cast p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 52
    .line 53
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->finishAcquireConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;I)V

    .line 54
    .line 55
    .line 56
    return-object p1

    .line 57
    :cond_2
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 58
    .line 59
    invoke-virtual {p1}, Ljava/util/WeakHashMap;->size()I

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 64
    .line 65
    if-eqz v0, :cond_3

    .line 66
    .line 67
    add-int/lit8 p1, p1, 0x1

    .line 68
    .line 69
    :cond_3
    iget v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mMaxConnectionPoolSize:I

    .line 70
    .line 71
    if-lt p1, v0, :cond_4

    .line 72
    .line 73
    const/4 p0, 0x0

    .line 74
    return-object p0

    .line 75
    :cond_4
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 76
    .line 77
    invoke-direct {p0, p1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->openConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;Z)Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->finishAcquireConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;I)V

    .line 82
    .line 83
    .line 84
    return-object p1
.end method

.method private tryAcquirePrimaryConnectionLocked(I)Lnet/zetetic/database/sqlcipher/SQLiteConnection;
    .locals 3

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iput-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 7
    .line 8
    invoke-direct {p0, v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->finishAcquireConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;I)V

    .line 9
    .line 10
    .line 11
    return-object v0

    .line 12
    :cond_0
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/util/WeakHashMap;->keySet()Ljava/util/Set;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_2

    .line 27
    .line 28
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    check-cast v2, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 33
    .line 34
    invoke-virtual {v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->isPrimaryConnection()Z

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-eqz v2, :cond_1

    .line 39
    .line 40
    return-object v1

    .line 41
    :cond_2
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 42
    .line 43
    const/4 v1, 0x1

    .line 44
    invoke-direct {p0, v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->openConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;Z)Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    invoke-direct {p0, v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->finishAcquireConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;I)V

    .line 49
    .line 50
    .line 51
    return-object v0
.end method

.method private waitForConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)Lnet/zetetic/database/sqlcipher/SQLiteConnection;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v7, p2

    .line 4
    .line 5
    move-object/from16 v8, p3

    .line 6
    .line 7
    and-int/lit8 v1, v7, 0x2

    .line 8
    .line 9
    const/4 v9, 0x0

    .line 10
    const/4 v10, 0x1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    move v5, v10

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v5, v9

    .line 16
    :goto_0
    iget-object v11, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mLock:Ljava/lang/Object;

    .line 17
    .line 18
    monitor-enter v11

    .line 19
    :try_start_0
    invoke-direct {v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->throwIfClosedLocked()V

    .line 20
    .line 21
    .line 22
    if-eqz v8, :cond_1

    .line 23
    .line 24
    invoke-virtual {v8}, Landroid/os/CancellationSignal;->throwIfCanceled()V

    .line 25
    .line 26
    .line 27
    goto :goto_1

    .line 28
    :catchall_0
    move-exception v0

    .line 29
    goto/16 :goto_b

    .line 30
    .line 31
    :cond_1
    :goto_1
    iget-object v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 32
    .line 33
    if-eqz v1, :cond_2

    .line 34
    .line 35
    iget-object v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 36
    .line 37
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-nez v1, :cond_3

    .line 42
    .line 43
    :cond_2
    if-eqz v5, :cond_4

    .line 44
    .line 45
    :cond_3
    invoke-direct {v0, v7}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->tryAcquirePrimaryConnectionLocked(I)Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    if-eqz v1, :cond_4

    .line 50
    .line 51
    monitor-exit v11

    .line 52
    return-object v1

    .line 53
    :cond_4
    if-nez v5, :cond_5

    .line 54
    .line 55
    invoke-direct/range {p0 .. p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->tryAcquireNonPrimaryConnectionLocked(Ljava/lang/String;I)Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    if-eqz v1, :cond_5

    .line 60
    .line 61
    monitor-exit v11

    .line 62
    return-object v1

    .line 63
    :cond_5
    invoke-static {v7}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->getPriority(I)I

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 68
    .line 69
    .line 70
    move-result-wide v2

    .line 71
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    move-object/from16 v6, p1

    .line 76
    .line 77
    invoke-direct/range {v0 .. v7}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->obtainConnectionWaiterLocked(Ljava/lang/Thread;JIZLjava/lang/String;I)Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    iget-object v2, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionWaiterQueue:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 82
    .line 83
    const/4 v3, 0x0

    .line 84
    move-object v5, v3

    .line 85
    :goto_2
    if-eqz v2, :cond_7

    .line 86
    .line 87
    iget v6, v2, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mPriority:I

    .line 88
    .line 89
    if-le v4, v6, :cond_6

    .line 90
    .line 91
    iput-object v2, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 92
    .line 93
    goto :goto_3

    .line 94
    :cond_6
    iget-object v5, v2, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 95
    .line 96
    move-object/from16 v17, v5

    .line 97
    .line 98
    move-object v5, v2

    .line 99
    move-object/from16 v2, v17

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_7
    :goto_3
    if-eqz v5, :cond_8

    .line 103
    .line 104
    iput-object v1, v5, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_8
    iput-object v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionWaiterQueue:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 108
    .line 109
    :goto_4
    iget v2, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNonce:I

    .line 110
    .line 111
    monitor-exit v11
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 112
    if-eqz v8, :cond_9

    .line 113
    .line 114
    new-instance v4, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$1;

    .line 115
    .line 116
    invoke-direct {v4, v0, v1, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$1;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;I)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v8, v4}, Landroid/os/CancellationSignal;->setOnCancelListener(Landroid/os/CancellationSignal$OnCancelListener;)V

    .line 120
    .line 121
    .line 122
    :cond_9
    :try_start_1
    iget-wide v4, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mStartTime:J

    .line 123
    .line 124
    const-wide/16 v11, 0x7530

    .line 125
    .line 126
    add-long/2addr v4, v11

    .line 127
    move-wide v13, v11

    .line 128
    :goto_5
    iget-object v2, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionLeaked:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 129
    .line 130
    invoke-virtual {v2, v10, v9}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 131
    .line 132
    .line 133
    move-result v2

    .line 134
    if-eqz v2, :cond_a

    .line 135
    .line 136
    iget-object v2, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mLock:Ljava/lang/Object;

    .line 137
    .line 138
    monitor-enter v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 139
    :try_start_2
    invoke-direct {v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->wakeConnectionWaitersLocked()V

    .line 140
    .line 141
    .line 142
    monitor-exit v2

    .line 143
    goto :goto_6

    .line 144
    :catchall_1
    move-exception v0

    .line 145
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 146
    :try_start_3
    throw v0

    .line 147
    :catchall_2
    move-exception v0

    .line 148
    goto :goto_a

    .line 149
    :cond_a
    :goto_6
    const-wide/32 v15, 0xf4240

    .line 150
    .line 151
    .line 152
    mul-long/2addr v13, v15

    .line 153
    invoke-static {v0, v13, v14}, Ljava/util/concurrent/locks/LockSupport;->parkNanos(Ljava/lang/Object;J)V

    .line 154
    .line 155
    .line 156
    invoke-static {}, Ljava/lang/Thread;->interrupted()Z

    .line 157
    .line 158
    .line 159
    iget-object v2, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mLock:Ljava/lang/Object;

    .line 160
    .line 161
    monitor-enter v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 162
    :try_start_4
    invoke-direct {v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->throwIfClosedLocked()V

    .line 163
    .line 164
    .line 165
    iget-object v6, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mAssignedConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 166
    .line 167
    iget-object v13, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mException:Ljava/lang/RuntimeException;

    .line 168
    .line 169
    if-nez v6, :cond_d

    .line 170
    .line 171
    if-eqz v13, :cond_b

    .line 172
    .line 173
    goto :goto_8

    .line 174
    :cond_b
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 175
    .line 176
    .line 177
    move-result-wide v13

    .line 178
    cmp-long v6, v13, v4

    .line 179
    .line 180
    if-gez v6, :cond_c

    .line 181
    .line 182
    sub-long/2addr v13, v4

    .line 183
    goto :goto_7

    .line 184
    :cond_c
    iget-wide v4, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mStartTime:J

    .line 185
    .line 186
    sub-long v4, v13, v4

    .line 187
    .line 188
    invoke-direct {v0, v4, v5, v7}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->logConnectionPoolBusyLocked(JI)V

    .line 189
    .line 190
    .line 191
    add-long/2addr v13, v11

    .line 192
    move-wide v4, v13

    .line 193
    move-wide v13, v11

    .line 194
    :goto_7
    monitor-exit v2

    .line 195
    goto :goto_5

    .line 196
    :catchall_3
    move-exception v0

    .line 197
    goto :goto_9

    .line 198
    :cond_d
    :goto_8
    invoke-direct {v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->recycleConnectionWaiterLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;)V

    .line 199
    .line 200
    .line 201
    if-eqz v6, :cond_f

    .line 202
    .line 203
    monitor-exit v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 204
    if-eqz v8, :cond_e

    .line 205
    .line 206
    invoke-virtual {v8, v3}, Landroid/os/CancellationSignal;->setOnCancelListener(Landroid/os/CancellationSignal$OnCancelListener;)V

    .line 207
    .line 208
    .line 209
    :cond_e
    return-object v6

    .line 210
    :cond_f
    :try_start_5
    throw v13

    .line 211
    :goto_9
    monitor-exit v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 212
    :try_start_6
    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 213
    :goto_a
    if-eqz v8, :cond_10

    .line 214
    .line 215
    invoke-virtual {v8, v3}, Landroid/os/CancellationSignal;->setOnCancelListener(Landroid/os/CancellationSignal$OnCancelListener;)V

    .line 216
    .line 217
    .line 218
    :cond_10
    throw v0

    .line 219
    :goto_b
    :try_start_7
    monitor-exit v11
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 220
    throw v0
.end method

.method private wakeConnectionWaitersLocked()V
    .locals 9

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionWaiterQueue:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    move-object v4, v1

    .line 6
    move v3, v2

    .line 7
    move v5, v3

    .line 8
    :goto_0
    if-eqz v0, :cond_8

    .line 9
    .line 10
    iget-boolean v6, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mIsOpen:Z

    .line 11
    .line 12
    const/4 v7, 0x1

    .line 13
    if-nez v6, :cond_0

    .line 14
    .line 15
    goto :goto_3

    .line 16
    :cond_0
    :try_start_0
    iget-boolean v6, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mWantPrimaryConnection:Z

    .line 17
    .line 18
    if-nez v6, :cond_1

    .line 19
    .line 20
    if-nez v3, :cond_1

    .line 21
    .line 22
    iget-object v6, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mSql:Ljava/lang/String;

    .line 23
    .line 24
    iget v8, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mConnectionFlags:I

    .line 25
    .line 26
    invoke-direct {p0, v6, v8}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->tryAcquireNonPrimaryConnectionLocked(Ljava/lang/String;I)Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 27
    .line 28
    .line 29
    move-result-object v6

    .line 30
    if-nez v6, :cond_2

    .line 31
    .line 32
    move v3, v7

    .line 33
    goto :goto_1

    .line 34
    :catch_0
    move-exception v6

    .line 35
    goto :goto_2

    .line 36
    :cond_1
    move-object v6, v1

    .line 37
    :cond_2
    :goto_1
    if-nez v6, :cond_3

    .line 38
    .line 39
    if-nez v5, :cond_3

    .line 40
    .line 41
    iget v6, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mConnectionFlags:I

    .line 42
    .line 43
    invoke-direct {p0, v6}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->tryAcquirePrimaryConnectionLocked(I)Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    if-nez v6, :cond_3

    .line 48
    .line 49
    move v5, v7

    .line 50
    :cond_3
    if-eqz v6, :cond_4

    .line 51
    .line 52
    iput-object v6, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mAssignedConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 53
    .line 54
    goto :goto_3

    .line 55
    :cond_4
    if-eqz v3, :cond_5

    .line 56
    .line 57
    if-eqz v5, :cond_5

    .line 58
    .line 59
    goto :goto_6

    .line 60
    :cond_5
    move v7, v2

    .line 61
    goto :goto_3

    .line 62
    :goto_2
    iput-object v6, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mException:Ljava/lang/RuntimeException;

    .line 63
    .line 64
    :goto_3
    iget-object v6, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 65
    .line 66
    if-eqz v7, :cond_7

    .line 67
    .line 68
    if-eqz v4, :cond_6

    .line 69
    .line 70
    iput-object v6, v4, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_6
    iput-object v6, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionWaiterQueue:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 74
    .line 75
    :goto_4
    iput-object v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 76
    .line 77
    iget-object v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mThread:Ljava/lang/Thread;

    .line 78
    .line 79
    invoke-static {v0}, Ljava/util/concurrent/locks/LockSupport;->unpark(Ljava/lang/Thread;)V

    .line 80
    .line 81
    .line 82
    goto :goto_5

    .line 83
    :cond_7
    move-object v4, v0

    .line 84
    :goto_5
    move-object v0, v6

    .line 85
    goto :goto_0

    .line 86
    :cond_8
    :goto_6
    return-void
.end method


# virtual methods
.method public acquireConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)Lnet/zetetic/database/sqlcipher/SQLiteConnection;
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->waitForConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public close()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->dispose(Z)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public collectDbStats(Ljava/util/ArrayList;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/ArrayList<",
            "Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;",
            ">;)V"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {v1, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->collectDbStats(Ljava/util/ArrayList;)V

    .line 9
    .line 10
    .line 11
    goto :goto_0

    .line 12
    :catchall_0
    move-exception p0

    .line 13
    goto :goto_3

    .line 14
    :cond_0
    :goto_0
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    check-cast v2, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 31
    .line 32
    invoke-virtual {v2, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->collectDbStats(Ljava/util/ArrayList;)V

    .line 33
    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/util/WeakHashMap;->keySet()Ljava/util/Set;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-eqz v1, :cond_2

    .line 51
    .line 52
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    check-cast v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 57
    .line 58
    invoke-virtual {v1, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->collectDbStatsUnsafe(Ljava/util/ArrayList;)V

    .line 59
    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_2
    monitor-exit v0

    .line 63
    return-void

    .line 64
    :goto_3
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 65
    throw p0
.end method

.method public dump(Landroid/util/Printer;Z)V
    .locals 8

    .line 1
    const-string v0, "  Max connections: "

    .line 2
    .line 3
    const-string v1, "  Open: "

    .line 4
    .line 5
    const-string v2, "Connection pool for "

    .line 6
    .line 7
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mLock:Ljava/lang/Object;

    .line 8
    .line 9
    monitor-enter v3

    .line 10
    :try_start_0
    new-instance v4, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    invoke-direct {v4, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 16
    .line 17
    iget-object v2, v2, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->path:Ljava/lang/String;

    .line 18
    .line 19
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string v2, ":"

    .line 23
    .line 24
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    invoke-interface {p1, v2}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    new-instance v2, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget-boolean v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mIsOpen:Z

    .line 40
    .line 41
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-interface {p1, v1}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    new-instance v1, Ljava/lang/StringBuilder;

    .line 52
    .line 53
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mMaxConnectionPoolSize:I

    .line 57
    .line 58
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    invoke-interface {p1, v0}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    const-string v0, "  Available primary connection:"

    .line 69
    .line 70
    invoke-interface {p1, v0}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 74
    .line 75
    if-eqz v0, :cond_0

    .line 76
    .line 77
    invoke-virtual {v0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->dump(Landroid/util/Printer;Z)V

    .line 78
    .line 79
    .line 80
    goto :goto_0

    .line 81
    :catchall_0
    move-exception p0

    .line 82
    goto/16 :goto_4

    .line 83
    .line 84
    :cond_0
    const-string v0, "<none>"

    .line 85
    .line 86
    invoke-interface {p1, v0}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    :goto_0
    const-string v0, "  Available non-primary connections:"

    .line 90
    .line 91
    invoke-interface {p1, v0}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 95
    .line 96
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    const/4 v1, 0x0

    .line 101
    if-nez v0, :cond_1

    .line 102
    .line 103
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 104
    .line 105
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    move v2, v1

    .line 110
    :goto_1
    if-ge v2, v0, :cond_2

    .line 111
    .line 112
    iget-object v4, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 113
    .line 114
    invoke-virtual {v4, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v4

    .line 118
    check-cast v4, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 119
    .line 120
    invoke-virtual {v4, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->dump(Landroid/util/Printer;Z)V

    .line 121
    .line 122
    .line 123
    add-int/lit8 v2, v2, 0x1

    .line 124
    .line 125
    goto :goto_1

    .line 126
    :cond_1
    const-string v0, "<none>"

    .line 127
    .line 128
    invoke-interface {p1, v0}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    :cond_2
    const-string v0, "  Acquired connections:"

    .line 132
    .line 133
    invoke-interface {p1, v0}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 137
    .line 138
    invoke-virtual {v0}, Ljava/util/WeakHashMap;->isEmpty()Z

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    if-nez v0, :cond_3

    .line 143
    .line 144
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 145
    .line 146
    invoke-virtual {v0}, Ljava/util/WeakHashMap;->entrySet()Ljava/util/Set;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 155
    .line 156
    .line 157
    move-result v2

    .line 158
    if-eqz v2, :cond_4

    .line 159
    .line 160
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    check-cast v2, Ljava/util/Map$Entry;

    .line 165
    .line 166
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v4

    .line 170
    check-cast v4, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 171
    .line 172
    invoke-virtual {v4, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->dumpUnsafe(Landroid/util/Printer;Z)V

    .line 173
    .line 174
    .line 175
    new-instance v4, Ljava/lang/StringBuilder;

    .line 176
    .line 177
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 178
    .line 179
    .line 180
    const-string v5, "  Status: "

    .line 181
    .line 182
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 183
    .line 184
    .line 185
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v2

    .line 189
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 190
    .line 191
    .line 192
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object v2

    .line 196
    invoke-interface {p1, v2}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    goto :goto_2

    .line 200
    :cond_3
    const-string p2, "<none>"

    .line 201
    .line 202
    invoke-interface {p1, p2}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    :cond_4
    const-string p2, "  Connection waiters:"

    .line 206
    .line 207
    invoke-interface {p1, p2}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 208
    .line 209
    .line 210
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionWaiterQueue:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 211
    .line 212
    if-eqz p2, :cond_5

    .line 213
    .line 214
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 215
    .line 216
    .line 217
    move-result-wide v4

    .line 218
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionWaiterQueue:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 219
    .line 220
    :goto_3
    if-eqz p0, :cond_6

    .line 221
    .line 222
    new-instance p2, Ljava/lang/StringBuilder;

    .line 223
    .line 224
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 225
    .line 226
    .line 227
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 228
    .line 229
    .line 230
    const-string v0, ": waited for "

    .line 231
    .line 232
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 233
    .line 234
    .line 235
    iget-wide v6, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mStartTime:J

    .line 236
    .line 237
    sub-long v6, v4, v6

    .line 238
    .line 239
    long-to-float v0, v6

    .line 240
    const v2, 0x3a83126f    # 0.001f

    .line 241
    .line 242
    .line 243
    mul-float/2addr v0, v2

    .line 244
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 245
    .line 246
    .line 247
    const-string v0, " ms - thread="

    .line 248
    .line 249
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 250
    .line 251
    .line 252
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mThread:Ljava/lang/Thread;

    .line 253
    .line 254
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 255
    .line 256
    .line 257
    const-string v0, ", priority="

    .line 258
    .line 259
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 260
    .line 261
    .line 262
    iget v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mPriority:I

    .line 263
    .line 264
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 265
    .line 266
    .line 267
    const-string v0, ", sql=\'"

    .line 268
    .line 269
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 270
    .line 271
    .line 272
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mSql:Ljava/lang/String;

    .line 273
    .line 274
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 275
    .line 276
    .line 277
    const-string v0, "\'"

    .line 278
    .line 279
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 280
    .line 281
    .line 282
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 283
    .line 284
    .line 285
    move-result-object p2

    .line 286
    invoke-interface {p1, p2}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;->mNext:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$ConnectionWaiter;

    .line 290
    .line 291
    add-int/lit8 v1, v1, 0x1

    .line 292
    .line 293
    goto :goto_3

    .line 294
    :cond_5
    const-string p0, "<none>"

    .line 295
    .line 296
    invoke-interface {p1, p0}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 297
    .line 298
    .line 299
    :cond_6
    monitor-exit v3

    .line 300
    return-void

    .line 301
    :goto_4
    monitor-exit v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 302
    throw p0
.end method

.method public enableLocalizedCollators()V
    .locals 2

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/util/WeakHashMap;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 13
    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->enableLocalizedCollators()V

    .line 17
    .line 18
    .line 19
    monitor-exit v0

    .line 20
    return-void

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string v1, "Cannot enable localized collators while database is in use"

    .line 26
    .line 27
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    throw p0
.end method

.method public finalize()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    :try_start_0
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->dispose(Z)V
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

.method public onConnectionLeaked()V
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "A SQLiteConnection object for database \'"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 9
    .line 10
    iget-object v1, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->label:Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v1, "\' was leaked!  Please fix your application to end transactions in progress properly and to close the database when it is no longer needed."

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    const-string v1, "SQLiteConnectionPool"

    .line 25
    .line 26
    invoke-static {v1, v0}, Lnet/zetetic/database/Logger;->w(Ljava/lang/String;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConnectionLeaked:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 30
    .line 31
    const/4 v0, 0x1

    .line 32
    invoke-virtual {p0, v0}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public reconfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    .locals 6

    .line 1
    if-eqz p1, :cond_8

    .line 2
    .line 3
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mLock:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->throwIfClosedLocked()V

    .line 7
    .line 8
    .line 9
    iget v1, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 10
    .line 11
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 12
    .line 13
    iget v2, v2, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 14
    .line 15
    xor-int/2addr v1, v2

    .line 16
    const/high16 v2, 0x20000000

    .line 17
    .line 18
    and-int/2addr v1, v2

    .line 19
    const/4 v2, 0x1

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    move v1, v2

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 v1, 0x0

    .line 25
    :goto_0
    if-eqz v1, :cond_2

    .line 26
    .line 27
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 28
    .line 29
    invoke-virtual {v3}, Ljava/util/WeakHashMap;->isEmpty()Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eqz v3, :cond_1

    .line 34
    .line 35
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeAvailableNonPrimaryConnectionsAndLogExceptionsLocked()V

    .line 36
    .line 37
    .line 38
    goto :goto_1

    .line 39
    :catchall_0
    move-exception p0

    .line 40
    goto :goto_4

    .line 41
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string p1, "Write Ahead Logging (WAL) mode cannot be enabled or disabled while there are transactions in progress.  Finish all transactions and release all active database connections first."

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    :goto_1
    iget-boolean v3, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->foreignKeyConstraintsEnabled:Z

    .line 50
    .line 51
    iget-object v4, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 52
    .line 53
    iget-boolean v4, v4, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->foreignKeyConstraintsEnabled:Z

    .line 54
    .line 55
    if-eq v3, v4, :cond_4

    .line 56
    .line 57
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 58
    .line 59
    invoke-virtual {v3}, Ljava/util/WeakHashMap;->isEmpty()Z

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    if-eqz v3, :cond_3

    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    const-string p1, "Foreign Key Constraints cannot be enabled or disabled while there are transactions in progress.  Finish all transactions and release all active database connections first."

    .line 69
    .line 70
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    throw p0

    .line 74
    :cond_4
    :goto_2
    iget-object v3, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->password:[B

    .line 75
    .line 76
    iget-object v4, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 77
    .line 78
    iget-object v4, v4, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->password:[B

    .line 79
    .line 80
    invoke-static {v3, v4}, Ljava/util/Arrays;->equals([B[B)Z

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    if-nez v3, :cond_5

    .line 85
    .line 86
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 87
    .line 88
    iget-object v4, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->password:[B

    .line 89
    .line 90
    invoke-virtual {v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->changePassword([B)V

    .line 91
    .line 92
    .line 93
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 94
    .line 95
    invoke-virtual {v3, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->updateParametersFrom(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V

    .line 96
    .line 97
    .line 98
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeAvailableNonPrimaryConnectionsAndLogExceptionsLocked()V

    .line 99
    .line 100
    .line 101
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->reconfigureAllConnectionsLocked()V

    .line 102
    .line 103
    .line 104
    :cond_5
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 105
    .line 106
    iget v4, v3, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 107
    .line 108
    iget v5, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 109
    .line 110
    if-eq v4, v5, :cond_7

    .line 111
    .line 112
    if-eqz v1, :cond_6

    .line 113
    .line 114
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeAvailableConnectionsAndLogExceptionsLocked()V

    .line 115
    .line 116
    .line 117
    :cond_6
    invoke-direct {p0, p1, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->openConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;Z)Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeAvailableConnectionsAndLogExceptionsLocked()V

    .line 122
    .line 123
    .line 124
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->discardAcquiredConnectionsLocked()V

    .line 125
    .line 126
    .line 127
    iput-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 128
    .line 129
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 130
    .line 131
    invoke-virtual {v1, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->updateParametersFrom(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V

    .line 132
    .line 133
    .line 134
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->setMaxConnectionPoolSizeLocked()V

    .line 135
    .line 136
    .line 137
    goto :goto_3

    .line 138
    :cond_7
    invoke-virtual {v3, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->updateParametersFrom(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V

    .line 139
    .line 140
    .line 141
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->setMaxConnectionPoolSizeLocked()V

    .line 142
    .line 143
    .line 144
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeExcessConnectionsAndLogExceptionsLocked()V

    .line 145
    .line 146
    .line 147
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->reconfigureAllConnectionsLocked()V

    .line 148
    .line 149
    .line 150
    :goto_3
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->wakeConnectionWaitersLocked()V

    .line 151
    .line 152
    .line 153
    monitor-exit v0

    .line 154
    return-void

    .line 155
    :goto_4
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 156
    throw p0

    .line 157
    :cond_8
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 158
    .line 159
    const-string p1, "configuration must not be null."

    .line 160
    .line 161
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    throw p0
.end method

.method public releaseConnection(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 5
    .line 6
    invoke-virtual {v1, p1}, Ljava/util/WeakHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    check-cast v1, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;

    .line 11
    .line 12
    if-eqz v1, :cond_5

    .line 13
    .line 14
    iget-boolean v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mIsOpen:Z

    .line 15
    .line 16
    if-nez v2, :cond_0

    .line 17
    .line 18
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeConnectionAndLogExceptionsLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    invoke-virtual {p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->isPrimaryConnection()Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-eqz v2, :cond_2

    .line 29
    .line 30
    invoke-direct {p0, p1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->recycleConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;)Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailablePrimaryConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 37
    .line 38
    :cond_1
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->wakeConnectionWaitersLocked()V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_2
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 43
    .line 44
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    iget v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mMaxConnectionPoolSize:I

    .line 49
    .line 50
    add-int/lit8 v3, v3, -0x1

    .line 51
    .line 52
    if-lt v2, v3, :cond_3

    .line 53
    .line 54
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->closeConnectionAndLogExceptionsLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_3
    invoke-direct {p0, p1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->recycleConnectionLocked(Lnet/zetetic/database/sqlcipher/SQLiteConnection;Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool$AcquiredConnectionStatus;)Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-eqz v1, :cond_4

    .line 63
    .line 64
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAvailableNonPrimaryConnections:Ljava/util/ArrayList;

    .line 65
    .line 66
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    :cond_4
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->wakeConnectionWaitersLocked()V

    .line 70
    .line 71
    .line 72
    :goto_0
    monitor-exit v0

    .line 73
    return-void

    .line 74
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 75
    .line 76
    const-string p1, "Cannot perform this operation because the specified connection was not acquired from this pool or has already been released."

    .line 77
    .line 78
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0

    .line 82
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 83
    throw p0
.end method

.method public shouldYieldConnection(Lnet/zetetic/database/sqlcipher/SQLiteConnection;I)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mAcquiredConnections:Ljava/util/WeakHashMap;

    .line 5
    .line 6
    invoke-virtual {v1, p1}, Ljava/util/WeakHashMap;->containsKey(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    if-eqz v1, :cond_1

    .line 11
    .line 12
    iget-boolean v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mIsOpen:Z

    .line 13
    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    monitor-exit v0

    .line 18
    return p0

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    invoke-virtual {p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->isPrimaryConnection()Z

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->isSessionBlockingImportantConnectionWaitersLocked(ZI)Z

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    monitor-exit v0

    .line 30
    return p0

    .line 31
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    const-string p1, "Cannot perform this operation because the specified connection was not acquired from this pool or has already been released."

    .line 34
    .line 35
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    throw p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SQLiteConnectionPool: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 9
    .line 10
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->path:Ljava/lang/String;

    .line 11
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
