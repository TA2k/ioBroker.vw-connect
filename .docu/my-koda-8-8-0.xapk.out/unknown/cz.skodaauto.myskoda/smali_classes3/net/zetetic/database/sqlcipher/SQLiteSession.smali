.class public final Lnet/zetetic/database/sqlcipher/SQLiteSession;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;
    }
.end annotation


# static fields
.field static final synthetic $assertionsDisabled:Z = false

.field public static final TRANSACTION_MODE_DEFERRED:I = 0x0

.field public static final TRANSACTION_MODE_EXCLUSIVE:I = 0x2

.field public static final TRANSACTION_MODE_IMMEDIATE:I = 0x1


# instance fields
.field private mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

.field private mConnectionFlags:I

.field private final mConnectionPool:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

.field private mConnectionUseCount:I

.field private mTransactionPool:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

.field private mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;


# direct methods
.method public constructor <init>(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnectionPool:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 10
    .line 11
    const-string p1, "connectionPool must not be null"

    .line 12
    .line 13
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    throw p0
.end method

.method private acquireConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnectionPool:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 6
    .line 7
    invoke-virtual {v0, p1, p2, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->acquireConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 12
    .line 13
    iput p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnectionFlags:I

    .line 14
    .line 15
    :cond_0
    iget p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnectionUseCount:I

    .line 16
    .line 17
    add-int/lit8 p1, p1, 0x1

    .line 18
    .line 19
    iput p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnectionUseCount:I

    .line 20
    .line 21
    return-void
.end method

.method private beginTransactionUnchecked(ILnet/zetetic/database/sqlcipher/SQLiteTransactionListener;ILandroid/os/CancellationSignal;)V
    .locals 2

    .line 1
    if-eqz p4, :cond_0

    .line 2
    .line 3
    invoke-virtual {p4}, Landroid/os/CancellationSignal;->throwIfCanceled()V

    .line 4
    .line 5
    .line 6
    :cond_0
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-nez v0, :cond_1

    .line 10
    .line 11
    invoke-direct {p0, v1, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->acquireConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)V

    .line 12
    .line 13
    .line 14
    :cond_1
    :try_start_0
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 15
    .line 16
    if-nez p3, :cond_4

    .line 17
    .line 18
    const/4 p3, 0x1

    .line 19
    if-eq p1, p3, :cond_3

    .line 20
    .line 21
    const/4 p3, 0x2

    .line 22
    if-eq p1, p3, :cond_2

    .line 23
    .line 24
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 25
    .line 26
    const-string v0, "BEGIN;"

    .line 27
    .line 28
    invoke-virtual {p3, v0, v1, p4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :catchall_0
    move-exception p1

    .line 33
    goto :goto_2

    .line 34
    :cond_2
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 35
    .line 36
    const-string v0, "BEGIN EXCLUSIVE;"

    .line 37
    .line 38
    invoke-virtual {p3, v0, v1, p4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_3
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 43
    .line 44
    const-string v0, "BEGIN IMMEDIATE;"

    .line 45
    .line 46
    invoke-virtual {p3, v0, v1, p4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 47
    .line 48
    .line 49
    :cond_4
    :goto_0
    if-eqz p2, :cond_6

    .line 50
    .line 51
    :try_start_1
    invoke-interface {p2}, Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;->onBegin()V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :catch_0
    move-exception p1

    .line 56
    :try_start_2
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 57
    .line 58
    if-nez p2, :cond_5

    .line 59
    .line 60
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 61
    .line 62
    const-string p3, "ROLLBACK;"

    .line 63
    .line 64
    invoke-virtual {p2, p3, v1, p4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 65
    .line 66
    .line 67
    :cond_5
    throw p1

    .line 68
    :cond_6
    :goto_1
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->obtainTransaction(ILnet/zetetic/database/sqlcipher/SQLiteTransactionListener;)Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 73
    .line 74
    iput-object p2, p1, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mParent:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 75
    .line 76
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 77
    .line 78
    return-void

    .line 79
    :goto_2
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 80
    .line 81
    if-nez p2, :cond_7

    .line 82
    .line 83
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 84
    .line 85
    .line 86
    :cond_7
    throw p1
.end method

.method private endTransactionUnchecked(Landroid/os/CancellationSignal;Z)V
    .locals 5

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/os/CancellationSignal;->throwIfCanceled()V

    .line 4
    .line 5
    .line 6
    :cond_0
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 7
    .line 8
    iget-boolean v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mMarkedSuccessful:Z

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x1

    .line 12
    if-nez v1, :cond_1

    .line 13
    .line 14
    if-eqz p2, :cond_2

    .line 15
    .line 16
    :cond_1
    iget-boolean p2, v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mChildFailed:Z

    .line 17
    .line 18
    if-nez p2, :cond_2

    .line 19
    .line 20
    move p2, v3

    .line 21
    goto :goto_0

    .line 22
    :cond_2
    move p2, v2

    .line 23
    :goto_0
    iget-object v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mListener:Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;

    .line 24
    .line 25
    const/4 v4, 0x0

    .line 26
    if-eqz v1, :cond_4

    .line 27
    .line 28
    if-eqz p2, :cond_3

    .line 29
    .line 30
    :try_start_0
    invoke-interface {v1}, Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;->onCommit()V

    .line 31
    .line 32
    .line 33
    goto :goto_1

    .line 34
    :catch_0
    move-exception p2

    .line 35
    goto :goto_2

    .line 36
    :cond_3
    invoke-interface {v1}, Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;->onRollback()V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 37
    .line 38
    .line 39
    :cond_4
    :goto_1
    move v2, p2

    .line 40
    move-object p2, v4

    .line 41
    :goto_2
    iget-object v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mParent:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 42
    .line 43
    iput-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 44
    .line 45
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->recycleTransaction(Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;)V

    .line 46
    .line 47
    .line 48
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 49
    .line 50
    if-eqz v0, :cond_5

    .line 51
    .line 52
    if-nez v2, :cond_7

    .line 53
    .line 54
    iput-boolean v3, v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mChildFailed:Z

    .line 55
    .line 56
    goto :goto_4

    .line 57
    :cond_5
    if-eqz v2, :cond_6

    .line 58
    .line 59
    :try_start_1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 60
    .line 61
    const-string v1, "COMMIT;"

    .line 62
    .line 63
    invoke-virtual {v0, v1, v4, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 64
    .line 65
    .line 66
    goto :goto_3

    .line 67
    :catchall_0
    move-exception p1

    .line 68
    goto :goto_5

    .line 69
    :cond_6
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 70
    .line 71
    const-string v1, "ROLLBACK;"

    .line 72
    .line 73
    invoke-virtual {v0, v1, v4, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 74
    .line 75
    .line 76
    :goto_3
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 77
    .line 78
    .line 79
    :cond_7
    :goto_4
    if-nez p2, :cond_8

    .line 80
    .line 81
    return-void

    .line 82
    :cond_8
    throw p2

    .line 83
    :goto_5
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 84
    .line 85
    .line 86
    throw p1
.end method

.method private executeSpecial(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)Z
    .locals 1

    .line 1
    if-eqz p4, :cond_0

    .line 2
    .line 3
    invoke-virtual {p4}, Landroid/os/CancellationSignal;->throwIfCanceled()V

    .line 4
    .line 5
    .line 6
    :cond_0
    invoke-static {p1}, Landroid/database/DatabaseUtils;->getSqlStatementType(Ljava/lang/String;)I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    const/4 p2, 0x4

    .line 11
    const/4 v0, 0x1

    .line 12
    if-eq p1, p2, :cond_3

    .line 13
    .line 14
    const/4 p2, 0x5

    .line 15
    if-eq p1, p2, :cond_2

    .line 16
    .line 17
    const/4 p2, 0x6

    .line 18
    if-eq p1, p2, :cond_1

    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    return p0

    .line 22
    :cond_1
    invoke-virtual {p0, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->endTransaction(Landroid/os/CancellationSignal;)V

    .line 23
    .line 24
    .line 25
    return v0

    .line 26
    :cond_2
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->setTransactionSuccessful()V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->endTransaction(Landroid/os/CancellationSignal;)V

    .line 30
    .line 31
    .line 32
    return v0

    .line 33
    :cond_3
    const/4 p1, 0x2

    .line 34
    const/4 p2, 0x0

    .line 35
    invoke-virtual {p0, p1, p2, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->beginTransaction(ILnet/zetetic/database/sqlcipher/SQLiteTransactionListener;ILandroid/os/CancellationSignal;)V

    .line 36
    .line 37
    .line 38
    return v0
.end method

.method private obtainTransaction(ILnet/zetetic/database/sqlcipher/SQLiteTransactionListener;)Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;
    .locals 3

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionPool:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-object v2, v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mParent:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 7
    .line 8
    iput-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionPool:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    iput-object p0, v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mParent:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 12
    .line 13
    iput-boolean v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mMarkedSuccessful:Z

    .line 14
    .line 15
    iput-boolean v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mChildFailed:Z

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 19
    .line 20
    invoke-direct {v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;-><init>(I)V

    .line 21
    .line 22
    .line 23
    :goto_0
    iput p1, v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mMode:I

    .line 24
    .line 25
    iput-object p2, v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mListener:Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;

    .line 26
    .line 27
    return-object v0
.end method

.method private recycleTransaction(Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionPool:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 2
    .line 3
    iput-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mParent:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iput-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mListener:Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;

    .line 7
    .line 8
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionPool:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 9
    .line 10
    return-void
.end method

.method private releaseConnection()V
    .locals 3

    .line 1
    iget v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnectionUseCount:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    iput v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnectionUseCount:I

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    :try_start_0
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnectionPool:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 11
    .line 12
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 13
    .line 14
    invoke-virtual {v1, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->releaseConnection(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 18
    .line 19
    return-void

    .line 20
    :catchall_0
    move-exception v1

    .line 21
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 22
    .line 23
    throw v1

    .line 24
    :cond_0
    return-void
.end method

.method private throwIfNestedTransaction()V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->hasNestedTransaction()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 9
    .line 10
    const-string v0, "Cannot perform this operation because a nested transaction is in progress."

    .line 11
    .line 12
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    throw p0
.end method

.method private throwIfNoTransaction()V
    .locals 1

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

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
    const-string v0, "Cannot perform this operation because there is no current transaction."

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method private throwIfTransactionMarkedSuccessful()V
    .locals 1

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    iget-boolean p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mMarkedSuccessful:Z

    .line 6
    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string v0, "Cannot perform this operation because the transaction has already been marked successful.  The only thing you can do now is call endTransaction()."

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0

    .line 18
    :cond_1
    :goto_0
    return-void
.end method

.method private yieldTransactionUnchecked(JLandroid/os/CancellationSignal;)Z
    .locals 6

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    invoke-virtual {p3}, Landroid/os/CancellationSignal;->throwIfCanceled()V

    .line 4
    .line 5
    .line 6
    :cond_0
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnectionPool:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 7
    .line 8
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 9
    .line 10
    iget v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnectionFlags:I

    .line 11
    .line 12
    invoke-virtual {v0, v1, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->shouldYieldConnection(Lnet/zetetic/database/sqlcipher/SQLiteConnection;I)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 21
    .line 22
    iget v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mMode:I

    .line 23
    .line 24
    iget-object v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mListener:Lnet/zetetic/database/sqlcipher/SQLiteTransactionListener;

    .line 25
    .line 26
    iget v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnectionFlags:I

    .line 27
    .line 28
    const/4 v3, 0x1

    .line 29
    invoke-direct {p0, p3, v3}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->endTransactionUnchecked(Landroid/os/CancellationSignal;Z)V

    .line 30
    .line 31
    .line 32
    const-wide/16 v4, 0x0

    .line 33
    .line 34
    cmp-long v4, p1, v4

    .line 35
    .line 36
    if-lez v4, :cond_2

    .line 37
    .line 38
    :try_start_0
    invoke-static {p1, p2}, Ljava/lang/Thread;->sleep(J)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 39
    .line 40
    .line 41
    :catch_0
    :cond_2
    invoke-direct {p0, v1, v0, v2, p3}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->beginTransactionUnchecked(ILnet/zetetic/database/sqlcipher/SQLiteTransactionListener;ILandroid/os/CancellationSignal;)V

    .line 42
    .line 43
    .line 44
    return v3
.end method


# virtual methods
.method public beginTransaction(ILnet/zetetic/database/sqlcipher/SQLiteTransactionListener;ILandroid/os/CancellationSignal;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->throwIfTransactionMarkedSuccessful()V

    .line 2
    .line 3
    .line 4
    invoke-direct {p0, p1, p2, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->beginTransactionUnchecked(ILnet/zetetic/database/sqlcipher/SQLiteTransactionListener;ILandroid/os/CancellationSignal;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public endTransaction(Landroid/os/CancellationSignal;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->throwIfNoTransaction()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    invoke-direct {p0, p1, v0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->endTransactionUnchecked(Landroid/os/CancellationSignal;Z)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public execute(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)V
    .locals 1

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeSpecial(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    invoke-direct {p0, p1, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->acquireConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)V

    .line 11
    .line 12
    .line 13
    :try_start_0
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 14
    .line 15
    invoke-virtual {p3, p1, p2, p4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    .line 17
    .line 18
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :catchall_0
    move-exception p1

    .line 23
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 24
    .line 25
    .line 26
    throw p1

    .line 27
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 28
    .line 29
    const-string p1, "sql must not be null."

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0
.end method

.method public executeForBlobFileDescriptor(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)Landroid/os/ParcelFileDescriptor;
    .locals 1

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeSpecial(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return-object p0

    .line 11
    :cond_0
    invoke-direct {p0, p1, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->acquireConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)V

    .line 12
    .line 13
    .line 14
    :try_start_0
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 15
    .line 16
    invoke-virtual {p3, p1, p2, p4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForBlobFileDescriptor(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)Landroid/os/ParcelFileDescriptor;

    .line 17
    .line 18
    .line 19
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :catchall_0
    move-exception p1

    .line 25
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 26
    .line 27
    .line 28
    throw p1

    .line 29
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 30
    .line 31
    const-string p1, "sql must not be null."

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0
.end method

.method public executeForChangedRowCount(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)I
    .locals 1

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeSpecial(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_0
    invoke-direct {p0, p1, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->acquireConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)V

    .line 12
    .line 13
    .line 14
    :try_start_0
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 15
    .line 16
    invoke-virtual {p3, p1, p2, p4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForChangedRowCount(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)I

    .line 17
    .line 18
    .line 19
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 21
    .line 22
    .line 23
    return p1

    .line 24
    :catchall_0
    move-exception p1

    .line 25
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 26
    .line 27
    .line 28
    throw p1

    .line 29
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 30
    .line 31
    const-string p1, "sql must not be null."

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0
.end method

.method public executeForCursorWindow(Ljava/lang/String;[Ljava/lang/Object;Lnet/zetetic/database/CursorWindow;IIZILandroid/os/CancellationSignal;)I
    .locals 1

    .line 1
    if-eqz p1, :cond_2

    .line 2
    .line 3
    if-eqz p3, :cond_1

    .line 4
    .line 5
    invoke-direct {p0, p1, p2, p7, p8}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeSpecial(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p3}, Lnet/zetetic/database/CursorWindow;->clear()V

    .line 12
    .line 13
    .line 14
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :cond_0
    invoke-direct {p0, p1, p7, p8}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->acquireConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)V

    .line 17
    .line 18
    .line 19
    move p7, p6

    .line 20
    move p6, p5

    .line 21
    move p5, p4

    .line 22
    move-object p4, p3

    .line 23
    move-object p3, p2

    .line 24
    move-object p2, p1

    .line 25
    :try_start_0
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 26
    .line 27
    invoke-virtual/range {p1 .. p8}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForCursorWindow(Ljava/lang/String;[Ljava/lang/Object;Lnet/zetetic/database/CursorWindow;IIZLandroid/os/CancellationSignal;)I

    .line 28
    .line 29
    .line 30
    move-result p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 32
    .line 33
    .line 34
    return p1

    .line 35
    :catchall_0
    move-exception v0

    .line 36
    move-object p1, v0

    .line 37
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 38
    .line 39
    .line 40
    throw p1

    .line 41
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 42
    .line 43
    const-string p1, "window must not be null."

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 50
    .line 51
    const-string p1, "sql must not be null."

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0
.end method

.method public executeForLastInsertedRowId(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)J
    .locals 1

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeSpecial(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const-wide/16 p0, 0x0

    .line 10
    .line 11
    return-wide p0

    .line 12
    :cond_0
    invoke-direct {p0, p1, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->acquireConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)V

    .line 13
    .line 14
    .line 15
    :try_start_0
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 16
    .line 17
    invoke-virtual {p3, p1, p2, p4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForLastInsertedRowId(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J

    .line 18
    .line 19
    .line 20
    move-result-wide p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 22
    .line 23
    .line 24
    return-wide p1

    .line 25
    :catchall_0
    move-exception p1

    .line 26
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 27
    .line 28
    .line 29
    throw p1

    .line 30
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 31
    .line 32
    const-string p1, "sql must not be null."

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0
.end method

.method public executeForLong(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)J
    .locals 1

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeSpecial(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const-wide/16 p0, 0x0

    .line 10
    .line 11
    return-wide p0

    .line 12
    :cond_0
    invoke-direct {p0, p1, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->acquireConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)V

    .line 13
    .line 14
    .line 15
    :try_start_0
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 16
    .line 17
    invoke-virtual {p3, p1, p2, p4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForLong(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J

    .line 18
    .line 19
    .line 20
    move-result-wide p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 22
    .line 23
    .line 24
    return-wide p1

    .line 25
    :catchall_0
    move-exception p1

    .line 26
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 27
    .line 28
    .line 29
    throw p1

    .line 30
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 31
    .line 32
    const-string p1, "sql must not be null."

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0
.end method

.method public executeForString(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)Ljava/lang/String;
    .locals 1

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->executeSpecial(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return-object p0

    .line 11
    :cond_0
    invoke-direct {p0, p1, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->acquireConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)V

    .line 12
    .line 13
    .line 14
    :try_start_0
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 15
    .line 16
    invoke-virtual {p3, p1, p2, p4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForString(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :catchall_0
    move-exception p1

    .line 25
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 26
    .line 27
    .line 28
    throw p1

    .line 29
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 30
    .line 31
    const-string p1, "sql must not be null."

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0
.end method

.method public executeRaw(Ljava/lang/String;[Ljava/lang/Object;ILandroid/os/CancellationSignal;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-direct {p0, p1, p3, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->acquireConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 7
    .line 8
    invoke-virtual {p3, p1, p2, p4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeRaw(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :catchall_0
    move-exception p1

    .line 16
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 17
    .line 18
    .line 19
    throw p1

    .line 20
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 21
    .line 22
    const-string p1, "sql must not be null."

    .line 23
    .line 24
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0
.end method

.method public hasConnection()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

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

.method public hasNestedTransaction()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mParent:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public hasTransaction()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

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

.method public prepare(Ljava/lang/String;ILandroid/os/CancellationSignal;Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    invoke-virtual {p3}, Landroid/os/CancellationSignal;->throwIfCanceled()V

    .line 6
    .line 7
    .line 8
    :cond_0
    invoke-direct {p0, p1, p2, p3}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->acquireConnection(Ljava/lang/String;ILandroid/os/CancellationSignal;)V

    .line 9
    .line 10
    .line 11
    :try_start_0
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mConnection:Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    .line 12
    .line 13
    invoke-virtual {p2, p1, p4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->prepare(Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :catchall_0
    move-exception p1

    .line 21
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->releaseConnection()V

    .line 22
    .line 23
    .line 24
    throw p1

    .line 25
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 26
    .line 27
    const-string p1, "sql must not be null."

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0
.end method

.method public setTransactionSuccessful()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->throwIfNoTransaction()V

    .line 2
    .line 3
    .line 4
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->throwIfTransactionMarkedSuccessful()V

    .line 5
    .line 6
    .line 7
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    iput-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mMarkedSuccessful:Z

    .line 11
    .line 12
    return-void
.end method

.method public yieldTransaction(JZLandroid/os/CancellationSignal;)Z
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p3, :cond_0

    .line 3
    .line 4
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->throwIfNoTransaction()V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->throwIfTransactionMarkedSuccessful()V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->throwIfNestedTransaction()V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 15
    .line 16
    if-eqz p3, :cond_3

    .line 17
    .line 18
    iget-boolean v1, p3, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mMarkedSuccessful:Z

    .line 19
    .line 20
    if-nez v1, :cond_3

    .line 21
    .line 22
    iget-object p3, p3, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mParent:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 23
    .line 24
    if-eqz p3, :cond_1

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    :goto_0
    iget-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteSession;->mTransactionStack:Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;

    .line 28
    .line 29
    iget-boolean p3, p3, Lnet/zetetic/database/sqlcipher/SQLiteSession$Transaction;->mChildFailed:Z

    .line 30
    .line 31
    if-eqz p3, :cond_2

    .line 32
    .line 33
    return v0

    .line 34
    :cond_2
    invoke-direct {p0, p1, p2, p4}, Lnet/zetetic/database/sqlcipher/SQLiteSession;->yieldTransactionUnchecked(JLandroid/os/CancellationSignal;)Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    return p0

    .line 39
    :cond_3
    :goto_1
    return v0
.end method
