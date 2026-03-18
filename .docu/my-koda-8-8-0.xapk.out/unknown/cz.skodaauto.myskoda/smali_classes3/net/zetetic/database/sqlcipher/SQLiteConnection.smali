.class public final Lnet/zetetic/database/sqlcipher/SQLiteConnection;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/CancellationSignal$OnCancelListener;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;,
        Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;,
        Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;,
        Lnet/zetetic/database/sqlcipher/SQLiteConnection$Operation;
    }
.end annotation


# static fields
.field static final synthetic $assertionsDisabled:Z = false

.field private static final DEBUG:Z = false

.field private static final EMPTY_BYTE_ARRAY:[B

.field private static final EMPTY_STRING_ARRAY:[Ljava/lang/String;

.field private static final TAG:Ljava/lang/String; = "SQLiteConnection"


# instance fields
.field private mCancellationSignalAttachCount:I

.field private final mCloseGuard:Lnet/zetetic/database/sqlcipher/CloseGuard;

.field private final mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

.field private final mConnectionId:I

.field private mConnectionPtr:J

.field private final mIsPrimaryConnection:Z

.field private final mIsReadOnlyConnection:Z

.field private mOnlyAllowReadOnlyOperations:Z

.field private final mPool:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

.field private final mPreparedStatementCache:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;

.field private mPreparedStatementPool:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

.field private final mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v1, v0, [Ljava/lang/String;

    .line 3
    .line 4
    sput-object v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->EMPTY_STRING_ARRAY:[Ljava/lang/String;

    .line 5
    .line 6
    new-array v0, v0, [B

    .line 7
    .line 8
    sput-object v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->EMPTY_BYTE_ARRAY:[B

    .line 9
    .line 10
    return-void
.end method

.method private constructor <init>(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;IZ)V
    .locals 3

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
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mCloseGuard:Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 9
    .line 10
    new-instance v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-direct {v1, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;-><init>(I)V

    .line 14
    .line 15
    .line 16
    iput-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 17
    .line 18
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPool:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 19
    .line 20
    new-instance p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 21
    .line 22
    invoke-direct {p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 26
    .line 27
    iput p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionId:I

    .line 28
    .line 29
    iput-boolean p4, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mIsPrimaryConnection:Z

    .line 30
    .line 31
    iget p2, p2, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 32
    .line 33
    const/4 p3, 0x1

    .line 34
    and-int/2addr p2, p3

    .line 35
    if-eqz p2, :cond_0

    .line 36
    .line 37
    move v2, p3

    .line 38
    :cond_0
    iput-boolean v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mIsReadOnlyConnection:Z

    .line 39
    .line 40
    new-instance p2, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;

    .line 41
    .line 42
    iget p1, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->maxSqlCacheSize:I

    .line 43
    .line 44
    invoke-direct {p2, p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteConnection;I)V

    .line 45
    .line 46
    .line 47
    iput-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementCache:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;

    .line 48
    .line 49
    const-string p0, "close"

    .line 50
    .line 51
    invoke-virtual {v0, p0}, Lnet/zetetic/database/sqlcipher/CloseGuard;->open(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    return-void
.end method

.method public static bridge synthetic a(Lnet/zetetic/database/sqlcipher/SQLiteConnection;Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->finalizePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private acquirePreparedStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;
    .locals 12

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementCache:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Landroid/util/LruCache;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    iget-boolean v2, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mInUse:Z

    .line 14
    .line 15
    if-nez v2, :cond_0

    .line 16
    .line 17
    return-object v1

    .line 18
    :cond_0
    move v2, v0

    .line 19
    goto :goto_0

    .line 20
    :cond_1
    const/4 v2, 0x0

    .line 21
    :goto_0
    iget-wide v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 22
    .line 23
    invoke-static {v3, v4, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativePrepareStatement(JLjava/lang/String;)J

    .line 24
    .line 25
    .line 26
    move-result-wide v7

    .line 27
    :try_start_0
    iget-wide v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 28
    .line 29
    invoke-static {v3, v4, v7, v8}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeGetParameterCount(JJ)I

    .line 30
    .line 31
    .line 32
    move-result v9

    .line 33
    invoke-static {p1}, Lnet/zetetic/database/DatabaseUtils;->getSqlStatementType(Ljava/lang/String;)I

    .line 34
    .line 35
    .line 36
    move-result v10

    .line 37
    iget-wide v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 38
    .line 39
    invoke-static {v3, v4, v7, v8}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeIsReadOnly(JJ)Z

    .line 40
    .line 41
    .line 42
    move-result v11
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_1

    .line 43
    move-object v5, p0

    .line 44
    move-object v6, p1

    .line 45
    :try_start_1
    invoke-direct/range {v5 .. v11}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->obtainPreparedStatement(Ljava/lang/String;JIIZ)Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    if-nez v2, :cond_2

    .line 50
    .line 51
    invoke-static {v10}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->isCacheable(I)Z

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    if-eqz p0, :cond_2

    .line 56
    .line 57
    iget-object p0, v5, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementCache:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;

    .line 58
    .line 59
    invoke-virtual {p0, v6, v1}, Landroid/util/LruCache;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    iput-boolean v0, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mInCache:Z
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0

    .line 63
    .line 64
    goto :goto_2

    .line 65
    :catch_0
    move-exception v0

    .line 66
    :goto_1
    move-object p0, v0

    .line 67
    goto :goto_3

    .line 68
    :cond_2
    :goto_2
    iput-boolean v0, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mInUse:Z

    .line 69
    .line 70
    return-object v1

    .line 71
    :catch_1
    move-exception v0

    .line 72
    move-object v5, p0

    .line 73
    goto :goto_1

    .line 74
    :goto_3
    if-eqz v1, :cond_3

    .line 75
    .line 76
    iget-boolean p1, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mInCache:Z

    .line 77
    .line 78
    if-nez p1, :cond_4

    .line 79
    .line 80
    :cond_3
    iget-wide v0, v5, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 81
    .line 82
    invoke-static {v0, v1, v7, v8}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeFinalizeStatement(JJ)V

    .line 83
    .line 84
    .line 85
    :cond_4
    throw p0
.end method

.method private applyBlockGuardPolicy(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    .locals 0

    .line 1
    return-void
.end method

.method private attachCancellationSignal(Landroid/os/CancellationSignal;)V
    .locals 4

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/os/CancellationSignal;->throwIfCanceled()V

    .line 4
    .line 5
    .line 6
    iget v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mCancellationSignalAttachCount:I

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    add-int/2addr v0, v1

    .line 10
    iput v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mCancellationSignalAttachCount:I

    .line 11
    .line 12
    if-ne v0, v1, :cond_0

    .line 13
    .line 14
    iget-wide v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 15
    .line 16
    invoke-static {v2, v3, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeResetCancel(JZ)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1, p0}, Landroid/os/CancellationSignal;->setOnCancelListener(Landroid/os/CancellationSignal$OnCancelListener;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    return-void
.end method

.method public static bridge synthetic b()[B
    .locals 1

    .line 1
    sget-object v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->EMPTY_BYTE_ARRAY:[B

    .line 2
    .line 3
    return-object v0
.end method

.method private bindArguments(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;[Ljava/lang/Object;)V
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p2, :cond_0

    .line 3
    .line 4
    array-length v1, p2

    .line 5
    goto :goto_0

    .line 6
    :cond_0
    move v1, v0

    .line 7
    :goto_0
    iget v2, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mNumParameters:I

    .line 8
    .line 9
    if-ne v1, v2, :cond_9

    .line 10
    .line 11
    if-nez v1, :cond_1

    .line 12
    .line 13
    goto/16 :goto_4

    .line 14
    .line 15
    :cond_1
    iget-wide v5, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 16
    .line 17
    :goto_1
    if-ge v0, v1, :cond_8

    .line 18
    .line 19
    aget-object p1, p2, v0

    .line 20
    .line 21
    invoke-static {p1}, Lnet/zetetic/database/DatabaseUtils;->getTypeOfObject(Ljava/lang/Object;)I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    if-eqz v2, :cond_7

    .line 26
    .line 27
    const/4 v3, 0x1

    .line 28
    if-eq v2, v3, :cond_6

    .line 29
    .line 30
    const/4 v3, 0x2

    .line 31
    if-eq v2, v3, :cond_5

    .line 32
    .line 33
    const/4 v3, 0x4

    .line 34
    if-eq v2, v3, :cond_4

    .line 35
    .line 36
    instance-of v2, p1, Ljava/lang/Boolean;

    .line 37
    .line 38
    if-eqz v2, :cond_3

    .line 39
    .line 40
    iget-wide v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 41
    .line 42
    add-int/lit8 v7, v0, 0x1

    .line 43
    .line 44
    check-cast p1, Ljava/lang/Boolean;

    .line 45
    .line 46
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    if-eqz p1, :cond_2

    .line 51
    .line 52
    const-wide/16 v8, 0x1

    .line 53
    .line 54
    goto :goto_2

    .line 55
    :cond_2
    const-wide/16 v8, 0x0

    .line 56
    .line 57
    :goto_2
    invoke-static/range {v3 .. v9}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeBindLong(JJIJ)V

    .line 58
    .line 59
    .line 60
    goto :goto_3

    .line 61
    :cond_3
    iget-wide v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 62
    .line 63
    add-int/lit8 v7, v0, 0x1

    .line 64
    .line 65
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v8

    .line 69
    invoke-static/range {v3 .. v8}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeBindString(JJILjava/lang/String;)V

    .line 70
    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_4
    iget-wide v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 74
    .line 75
    add-int/lit8 v7, v0, 0x1

    .line 76
    .line 77
    move-object v8, p1

    .line 78
    check-cast v8, [B

    .line 79
    .line 80
    invoke-static/range {v3 .. v8}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeBindBlob(JJI[B)V

    .line 81
    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_5
    iget-wide v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 85
    .line 86
    add-int/lit8 v7, v0, 0x1

    .line 87
    .line 88
    check-cast p1, Ljava/lang/Number;

    .line 89
    .line 90
    invoke-virtual {p1}, Ljava/lang/Number;->doubleValue()D

    .line 91
    .line 92
    .line 93
    move-result-wide v8

    .line 94
    invoke-static/range {v3 .. v9}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeBindDouble(JJID)V

    .line 95
    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_6
    iget-wide v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 99
    .line 100
    add-int/lit8 v7, v0, 0x1

    .line 101
    .line 102
    check-cast p1, Ljava/lang/Number;

    .line 103
    .line 104
    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    .line 105
    .line 106
    .line 107
    move-result-wide v8

    .line 108
    invoke-static/range {v3 .. v9}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeBindLong(JJIJ)V

    .line 109
    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_7
    iget-wide v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 113
    .line 114
    add-int/lit8 p1, v0, 0x1

    .line 115
    .line 116
    invoke-static {v2, v3, v5, v6, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeBindNull(JJI)V

    .line 117
    .line 118
    .line 119
    :goto_3
    add-int/lit8 v0, v0, 0x1

    .line 120
    .line 121
    goto :goto_1

    .line 122
    :cond_8
    :goto_4
    return-void

    .line 123
    :cond_9
    new-instance p0, Landroid/database/sqlite/SQLiteBindOrColumnIndexOutOfRangeException;

    .line 124
    .line 125
    new-instance p2, Ljava/lang/StringBuilder;

    .line 126
    .line 127
    const-string v0, "Expected "

    .line 128
    .line 129
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    iget p1, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mNumParameters:I

    .line 133
    .line 134
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    const-string p1, " bind arguments but "

    .line 138
    .line 139
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    const-string p1, " were provided."

    .line 146
    .line 147
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 148
    .line 149
    .line 150
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    invoke-direct {p0, p1}, Landroid/database/sqlite/SQLiteBindOrColumnIndexOutOfRangeException;-><init>(Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    throw p0
.end method

.method public static bridge synthetic c(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->trimSqlForDisplay(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static canonicalizeSyncMode(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "0"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const-string p0, "OFF"

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    const-string v0, "1"

    .line 13
    .line 14
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    const-string p0, "NORMAL"

    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_1
    const-string v0, "2"

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_2

    .line 30
    .line 31
    const-string p0, "FULL"

    .line 32
    .line 33
    :cond_2
    return-object p0
.end method

.method private detachCancellationSignal(Landroid/os/CancellationSignal;)V
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mCancellationSignalAttachCount:I

    .line 4
    .line 5
    add-int/lit8 v0, v0, -0x1

    .line 6
    .line 7
    iput v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mCancellationSignalAttachCount:I

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-virtual {p1, v0}, Landroid/os/CancellationSignal;->setOnCancelListener(Landroid/os/CancellationSignal$OnCancelListener;)V

    .line 13
    .line 14
    .line 15
    iget-wide p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    invoke-static {p0, p1, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeResetCancel(JZ)V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void
.end method

.method private dispose(Z)V
    .locals 4

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mCloseGuard:Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/CloseGuard;->warnIfOpen()V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mCloseGuard:Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 11
    .line 12
    invoke-virtual {p1}, Lnet/zetetic/database/sqlcipher/CloseGuard;->close()V

    .line 13
    .line 14
    .line 15
    :cond_1
    iget-wide v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 16
    .line 17
    const-wide/16 v2, 0x0

    .line 18
    .line 19
    cmp-long p1, v0, v2

    .line 20
    .line 21
    if-eqz p1, :cond_2

    .line 22
    .line 23
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 24
    .line 25
    const-string v0, "close"

    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    invoke-virtual {p1, v0, v1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->beginOperation(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    :try_start_0
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementCache:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;

    .line 33
    .line 34
    invoke-virtual {v0}, Landroid/util/LruCache;->evictAll()V

    .line 35
    .line 36
    .line 37
    iget-wide v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 38
    .line 39
    invoke-static {v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeClose(J)V

    .line 40
    .line 41
    .line 42
    iput-wide v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 45
    .line 46
    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :catchall_0
    move-exception v0

    .line 51
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 52
    .line 53
    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 54
    .line 55
    .line 56
    throw v0

    .line 57
    :cond_2
    return-void
.end method

.method private finalizePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    .locals 4

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 2
    .line 3
    iget-wide v2, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 4
    .line 5
    invoke-static {v0, v1, v2, v3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeFinalizeStatement(JJ)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->recyclePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method private getMainDbStatsUnsafe(IJJ)Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;
    .locals 11

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 2
    .line 3
    iget-object v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->path:Ljava/lang/String;

    .line 4
    .line 5
    iget-boolean v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mIsPrimaryConnection:Z

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    const-string v1, " ("

    .line 10
    .line 11
    invoke-static {v0, v1}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionId:I

    .line 16
    .line 17
    const-string v2, ")"

    .line 18
    .line 19
    invoke-static {v1, v2, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    :cond_0
    move-object v2, v0

    .line 24
    new-instance v1, Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;

    .line 25
    .line 26
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementCache:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;

    .line 27
    .line 28
    invoke-virtual {v0}, Landroid/util/LruCache;->hitCount()I

    .line 29
    .line 30
    .line 31
    move-result v8

    .line 32
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementCache:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;

    .line 33
    .line 34
    invoke-virtual {v0}, Landroid/util/LruCache;->missCount()I

    .line 35
    .line 36
    .line 37
    move-result v9

    .line 38
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementCache:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;

    .line 39
    .line 40
    invoke-virtual {p0}, Landroid/util/LruCache;->size()I

    .line 41
    .line 42
    .line 43
    move-result v10

    .line 44
    move v7, p1

    .line 45
    move-wide v3, p2

    .line 46
    move-wide v5, p4

    .line 47
    invoke-direct/range {v1 .. v10}, Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;-><init>(Ljava/lang/String;JJIIII)V

    .line 48
    .line 49
    .line 50
    return-object v1
.end method

.method public static hasCodec()Z
    .locals 1

    .line 1
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeHasCodec()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    return v0
.end method

.method private static isCacheable(I)Z
    .locals 2

    .line 1
    const/4 v0, 0x2

    .line 2
    const/4 v1, 0x1

    .line 3
    if-eq p0, v0, :cond_1

    .line 4
    .line 5
    if-ne p0, v1, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return p0

    .line 10
    :cond_1
    :goto_0
    return v1
.end method

.method private static native nativeBindBlob(JJI[B)V
.end method

.method private static native nativeBindDouble(JJID)V
.end method

.method private static native nativeBindLong(JJIJ)V
.end method

.method private static native nativeBindNull(JJI)V
.end method

.method private static native nativeBindString(JJILjava/lang/String;)V
.end method

.method private static native nativeCancel(J)V
.end method

.method private static native nativeClose(J)V
.end method

.method private static native nativeExecute(JJ)V
.end method

.method private static native nativeExecuteForBlobFileDescriptor(JJ)I
.end method

.method private static native nativeExecuteForChangedRowCount(JJ)I
.end method

.method private static native nativeExecuteForCursorWindow(JJJIIZ)J
.end method

.method private static native nativeExecuteForLastInsertedRowId(JJ)J
.end method

.method private static native nativeExecuteForLong(JJ)J
.end method

.method private static native nativeExecuteForString(JJ)Ljava/lang/String;
.end method

.method private static native nativeExecuteRaw(JJ)V
.end method

.method private static native nativeFinalizeStatement(JJ)V
.end method

.method private static native nativeGetColumnCount(JJ)I
.end method

.method private static native nativeGetColumnName(JJI)Ljava/lang/String;
.end method

.method private static native nativeGetDbLookaside(J)I
.end method

.method private static native nativeGetParameterCount(JJ)I
.end method

.method private static native nativeHasCodec()Z
.end method

.method private static native nativeIsReadOnly(JJ)Z
.end method

.method private static native nativeKey(J[B)I
.end method

.method private static native nativeOpen(Ljava/lang/String;ILjava/lang/String;ZZ)J
.end method

.method private static native nativePrepareStatement(JLjava/lang/String;)J
.end method

.method private static native nativeReKey(J[B)I
.end method

.method private static native nativeRegisterCustomFunction(JLnet/zetetic/database/sqlcipher/SQLiteCustomFunction;)V
.end method

.method private static native nativeRegisterLocalizedCollators(JLjava/lang/String;)V
.end method

.method private static native nativeResetCancel(JZ)V
.end method

.method private static native nativeResetStatementAndClearBindings(JJ)V
.end method

.method private obtainPreparedStatement(Ljava/lang/String;JIIZ)Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;
    .locals 3

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementPool:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-object v2, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mPoolNext:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 7
    .line 8
    iput-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementPool:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    iput-object p0, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mPoolNext:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 12
    .line 13
    iput-boolean v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mInCache:Z

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 17
    .line 18
    invoke-direct {v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;-><init>(I)V

    .line 19
    .line 20
    .line 21
    :goto_0
    iput-object p1, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mSql:Ljava/lang/String;

    .line 22
    .line 23
    iput-wide p2, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 24
    .line 25
    iput p4, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mNumParameters:I

    .line 26
    .line 27
    iput p5, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mType:I

    .line 28
    .line 29
    iput-boolean p6, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mReadOnly:Z

    .line 30
    .line 31
    return-object v0
.end method

.method public static open(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;IZ)Lnet/zetetic/database/sqlcipher/SQLiteConnection;
    .locals 1

    .line 1
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;

    invoke-direct {v0, p0, p1, p2, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;-><init>(Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;IZ)V

    .line 2
    :try_start_0
    invoke-direct {v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->open()V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception p0

    const/4 p1, 0x0

    .line 3
    invoke-direct {v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->dispose(Z)V

    .line 4
    throw p0
.end method

.method private open()V
    .locals 5

    .line 5
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    iget-object v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->path:Ljava/lang/String;

    iget v2, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    iget-object v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->label:Ljava/lang/String;

    sget-boolean v3, Lnet/zetetic/database/sqlcipher/SQLiteDebug;->DEBUG_SQL_STATEMENTS:Z

    sget-boolean v4, Lnet/zetetic/database/sqlcipher/SQLiteDebug;->DEBUG_SQL_TIME:Z

    invoke-static {v1, v2, v0, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeOpen(Ljava/lang/String;ILjava/lang/String;ZZ)J

    move-result-wide v0

    iput-wide v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 6
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    iget-object v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->databaseHook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

    if-eqz v0, :cond_0

    .line 7
    invoke-interface {v0, p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;->preKey(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V

    .line 8
    :cond_0
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    iget-object v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->password:[B

    if-eqz v0, :cond_1

    array-length v1, v0

    if-lez v1, :cond_1

    .line 9
    iget-wide v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    invoke-static {v1, v2, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeKey(J[B)I

    move-result v0

    .line 10
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Database keying operation returned:"

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "SQLiteConnection"

    invoke-static {v1, v0}, Lnet/zetetic/database/Logger;->i(Ljava/lang/String;Ljava/lang/String;)V

    .line 11
    :cond_1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    iget-object v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->databaseHook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

    if-eqz v0, :cond_2

    .line 12
    invoke-interface {v0, p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;->postKey(Lnet/zetetic/database/sqlcipher/SQLiteConnection;)V

    .line 13
    :cond_2
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    iget-object v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->password:[B

    if-eqz v0, :cond_3

    array-length v0, v0

    if-lez v0, :cond_3

    .line 14
    const-string v0, "SELECT COUNT(*) FROM sqlite_schema;"

    const/4 v1, 0x0

    invoke-virtual {p0, v0, v1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForLong(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J

    .line 15
    :cond_3
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setPageSize()V

    .line 16
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setForeignKeyModeFromConfiguration()V

    .line 17
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setJournalSizeLimit()V

    .line 18
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setAutoCheckpointInterval()V

    .line 19
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setWalModeFromConfiguration()V

    .line 20
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeHasCodec()Z

    move-result v0

    if-nez v0, :cond_4

    .line 21
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setLocaleFromConfiguration()V

    .line 22
    :cond_4
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    iget-object v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->customFunctions:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_5

    .line 23
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    iget-object v2, v2, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->customFunctions:Ljava/util/ArrayList;

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lnet/zetetic/database/sqlcipher/SQLiteCustomFunction;

    .line 24
    iget-wide v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    invoke-static {v3, v4, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeRegisterCustomFunction(JLnet/zetetic/database/sqlcipher/SQLiteCustomFunction;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_5
    return-void
.end method

.method private recyclePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mSql:Ljava/lang/String;

    .line 3
    .line 4
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementPool:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 5
    .line 6
    iput-object v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mPoolNext:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 7
    .line 8
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementPool:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 9
    .line 10
    return-void
.end method

.method private releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mInUse:Z

    .line 3
    .line 4
    iget-boolean v0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mInCache:Z

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    :try_start_0
    iget-wide v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 9
    .line 10
    iget-wide v2, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 11
    .line 12
    invoke-static {v0, v1, v2, v3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeResetStatementAndClearBindings(JJ)V
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :catch_0
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementCache:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;

    .line 17
    .line 18
    iget-object p1, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mSql:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {p0, p1}, Landroid/util/LruCache;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->finalizePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method private setAutoCheckpointInterval()V
    .locals 6

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 2
    .line 3
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->isInMemoryDb()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mIsReadOnlyConnection:Z

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->getWALAutoCheckpoint()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    int-to-long v0, v0

    .line 18
    const-string v2, "PRAGMA wal_autocheckpoint"

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    invoke-virtual {p0, v2, v3, v3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForLong(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J

    .line 22
    .line 23
    .line 24
    move-result-wide v4

    .line 25
    cmp-long v2, v4, v0

    .line 26
    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    const-string v2, "PRAGMA wal_autocheckpoint="

    .line 30
    .line 31
    invoke-static {v0, v1, v2}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {p0, v0, v3, v3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForLong(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J

    .line 36
    .line 37
    .line 38
    :cond_0
    return-void
.end method

.method private setForeignKeyModeFromConfiguration()V
    .locals 6

    .line 1
    iget-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mIsReadOnlyConnection:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 6
    .line 7
    iget-boolean v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->foreignKeyConstraintsEnabled:Z

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    const-wide/16 v0, 0x1

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const-wide/16 v0, 0x0

    .line 15
    .line 16
    :goto_0
    const-string v2, "PRAGMA foreign_keys"

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    invoke-virtual {p0, v2, v3, v3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForLong(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J

    .line 20
    .line 21
    .line 22
    move-result-wide v4

    .line 23
    cmp-long v2, v4, v0

    .line 24
    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    const-string v2, "PRAGMA foreign_keys="

    .line 28
    .line 29
    invoke-static {v0, v1, v2}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-virtual {p0, v0, v3, v3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 34
    .line 35
    .line 36
    :cond_1
    return-void
.end method

.method private setJournalMode(Ljava/lang/String;)V
    .locals 4

    .line 1
    const-string v0, "PRAGMA journal_mode="

    .line 2
    .line 3
    const-string v1, "PRAGMA journal_mode"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-virtual {p0, v1, v2, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForString(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v1, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    if-nez v3, :cond_1

    .line 15
    .line 16
    :try_start_0
    new-instance v3, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {p0, v0, v2, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForString(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-virtual {v0, p1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 33
    .line 34
    .line 35
    move-result v0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 36
    if-eqz v0, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :catch_0
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 40
    .line 41
    const-string v2, "Could not change the database journal mode of \'"

    .line 42
    .line 43
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 47
    .line 48
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->label:Ljava/lang/String;

    .line 49
    .line 50
    const-string v2, "\' from \'"

    .line 51
    .line 52
    const-string v3, "\' to \'"

    .line 53
    .line 54
    invoke-static {v0, p0, v2, v1, v3}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string p0, "\' because the database is locked.  This usually means that there are other open connections to the database which prevents the database from enabling or disabling write-ahead logging mode.  Proceeding without changing the journal mode."

    .line 61
    .line 62
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    const-string p1, "SQLiteConnection"

    .line 70
    .line 71
    invoke-static {p1, p0}, Lnet/zetetic/database/Logger;->w(Ljava/lang/String;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    :cond_1
    :goto_0
    return-void
.end method

.method private setJournalSizeLimit()V
    .locals 6

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 2
    .line 3
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->isInMemoryDb()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mIsReadOnlyConnection:Z

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->getJournalSizeLimit()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    int-to-long v0, v0

    .line 18
    const-string v2, "PRAGMA journal_size_limit"

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    invoke-virtual {p0, v2, v3, v3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForLong(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J

    .line 22
    .line 23
    .line 24
    move-result-wide v4

    .line 25
    cmp-long v2, v4, v0

    .line 26
    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    const-string v2, "PRAGMA journal_size_limit="

    .line 30
    .line 31
    invoke-static {v0, v1, v2}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {p0, v0, v3, v3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForLong(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J

    .line 36
    .line 37
    .line 38
    :cond_0
    return-void
.end method

.method private setLocaleFromConfiguration()V
    .locals 6

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 2
    .line 3
    iget v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 4
    .line 5
    and-int/lit8 v1, v1, 0x10

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    iget-object v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->locale:Ljava/util/Locale;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/util/Locale;->toString()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    iget-wide v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 17
    .line 18
    invoke-static {v1, v2, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeRegisterLocalizedCollators(JLjava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-boolean v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mIsReadOnlyConnection:Z

    .line 22
    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    :try_start_0
    const-string v1, "CREATE TABLE IF NOT EXISTS android_metadata (locale TEXT)"

    .line 27
    .line 28
    const/4 v2, 0x0

    .line 29
    invoke-virtual {p0, v1, v2, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 30
    .line 31
    .line 32
    const-string v1, "SELECT locale FROM android_metadata UNION SELECT NULL ORDER BY locale DESC LIMIT 1"

    .line 33
    .line 34
    invoke-virtual {p0, v1, v2, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForString(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-eqz v1, :cond_2

    .line 45
    .line 46
    :goto_0
    return-void

    .line 47
    :catch_0
    move-exception v1

    .line 48
    goto :goto_1

    .line 49
    :cond_2
    const-string v1, "BEGIN"

    .line 50
    .line 51
    invoke-virtual {p0, v1, v2, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 52
    .line 53
    .line 54
    :try_start_1
    const-string v1, "DELETE FROM android_metadata"

    .line 55
    .line 56
    invoke-virtual {p0, v1, v2, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 57
    .line 58
    .line 59
    const-string v1, "INSERT INTO android_metadata (locale) VALUES(?)"

    .line 60
    .line 61
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    invoke-virtual {p0, v1, v3, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 66
    .line 67
    .line 68
    const-string v1, "REINDEX LOCALIZED"

    .line 69
    .line 70
    invoke-virtual {p0, v1, v2, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 71
    .line 72
    .line 73
    :try_start_2
    const-string v1, "COMMIT"

    .line 74
    .line 75
    invoke-virtual {p0, v1, v2, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 76
    .line 77
    .line 78
    return-void

    .line 79
    :catchall_0
    move-exception v1

    .line 80
    const-string v3, "ROLLBACK"

    .line 81
    .line 82
    invoke-virtual {p0, v3, v2, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 83
    .line 84
    .line 85
    throw v1
    :try_end_2
    .catch Ljava/lang/RuntimeException; {:try_start_2 .. :try_end_2} :catch_0

    .line 86
    :goto_1
    new-instance v2, Landroid/database/sqlite/SQLiteException;

    .line 87
    .line 88
    new-instance v3, Ljava/lang/StringBuilder;

    .line 89
    .line 90
    const-string v4, "Failed to change locale for db \'"

    .line 91
    .line 92
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 96
    .line 97
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->label:Ljava/lang/String;

    .line 98
    .line 99
    const-string v4, "\' to \'"

    .line 100
    .line 101
    const-string v5, "\'."

    .line 102
    .line 103
    invoke-static {v3, p0, v4, v0, v5}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    invoke-direct {v2, p0, v1}, Landroid/database/sqlite/SQLiteException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 108
    .line 109
    .line 110
    throw v2
.end method

.method private setPageSize()V
    .locals 6

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 2
    .line 3
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->isInMemoryDb()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mIsReadOnlyConnection:Z

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->hasCodec()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->getDefaultPageSize()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    int-to-long v0, v0

    .line 24
    const-string v2, "PRAGMA page_size"

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    invoke-virtual {p0, v2, v3, v3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForLong(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J

    .line 28
    .line 29
    .line 30
    move-result-wide v4

    .line 31
    cmp-long v2, v4, v0

    .line 32
    .line 33
    if-eqz v2, :cond_0

    .line 34
    .line 35
    const-string v2, "PRAGMA page_size="

    .line 36
    .line 37
    invoke-static {v0, v1, v2}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-virtual {p0, v0, v3, v3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 42
    .line 43
    .line 44
    :cond_0
    return-void
.end method

.method private setSyncMode(Ljava/lang/String;)V
    .locals 3

    .line 1
    const-string v0, "PRAGMA synchronous"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {p0, v0, v1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForString(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-static {v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->canonicalizeSyncMode(Ljava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-static {p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->canonicalizeSyncMode(Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-virtual {v0, v2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    new-instance v0, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string v2, "PRAGMA synchronous="

    .line 25
    .line 26
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    invoke-virtual {p0, p1, v1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V

    .line 37
    .line 38
    .line 39
    :cond_0
    return-void
.end method

.method private setWalModeFromConfiguration()V
    .locals 2

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 2
    .line 3
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->isInMemoryDb()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mIsReadOnlyConnection:Z

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 14
    .line 15
    iget v0, v0, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 16
    .line 17
    const/high16 v1, 0x20000000

    .line 18
    .line 19
    and-int/2addr v0, v1

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    const-string v0, "WAL"

    .line 23
    .line 24
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setJournalMode(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->getWALSyncMode()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setSyncMode(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_0
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->getDefaultJournalMode()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setJournalMode(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->getDefaultSyncMode()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setSyncMode(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    :cond_1
    return-void
.end method

.method private throwIfStatementForbidden(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    .locals 0

    .line 1
    iget-boolean p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mOnlyAllowReadOnlyOperations:Z

    .line 2
    .line 3
    if-eqz p0, :cond_1

    .line 4
    .line 5
    iget-boolean p0, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mReadOnly:Z

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    new-instance p0, Landroid/database/sqlite/SQLiteException;

    .line 11
    .line 12
    const-string p1, "Cannot execute this statement because it might modify the database but the connection is read-only."

    .line 13
    .line 14
    invoke-direct {p0, p1}, Landroid/database/sqlite/SQLiteException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0

    .line 18
    :cond_1
    :goto_0
    return-void
.end method

.method private static trimSqlForDisplay(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "[\\s]*\\n+[\\s]*"

    .line 2
    .line 3
    const-string v1, " "

    .line 4
    .line 5
    invoke-virtual {p0, v0, v1}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method


# virtual methods
.method public changePassword([B)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeReKey(J[B)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    new-instance p1, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v0, "Database rekey operation returned:"

    .line 10
    .line 11
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    const-string v0, "SQLiteConnection"

    .line 22
    .line 23
    invoke-static {v0, p1}, Lnet/zetetic/database/Logger;->i(Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    if-nez p0, :cond_0

    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    new-instance p1, Landroid/database/sqlite/SQLiteException;

    .line 30
    .line 31
    const-string v0, "Failed to rekey database, result code:"

    .line 32
    .line 33
    invoke-static {p0, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-direct {p1, p0}, Landroid/database/sqlite/SQLiteException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p1
.end method

.method public close()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->dispose(Z)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public collectDbStats(Ljava/util/ArrayList;)V
    .locals 23
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/ArrayList<",
            "Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;",
            ">;)V"
        }
    .end annotation

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v8, p1

    .line 4
    .line 5
    const-string v9, "PRAGMA "

    .line 6
    .line 7
    iget-wide v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 8
    .line 9
    invoke-static {v1, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeGetDbLookaside(J)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    const/4 v10, 0x0

    .line 14
    const-wide/16 v11, 0x0

    .line 15
    .line 16
    :try_start_0
    const-string v2, "PRAGMA page_count;"

    .line 17
    .line 18
    invoke-virtual {v0, v2, v10, v10}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForLong(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J

    .line 19
    .line 20
    .line 21
    move-result-wide v2
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    :try_start_1
    const-string v4, "PRAGMA page_size;"

    .line 23
    .line 24
    invoke-virtual {v0, v4, v10, v10}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForLong(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J

    .line 25
    .line 26
    .line 27
    move-result-wide v4
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_1

    .line 28
    goto :goto_0

    .line 29
    :catch_0
    move-wide v2, v11

    .line 30
    :catch_1
    move-wide v4, v11

    .line 31
    :goto_0
    invoke-direct/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->getMainDbStatsUnsafe(IJJ)Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-virtual {v8, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    new-instance v3, Lnet/zetetic/database/CursorWindow;

    .line 39
    .line 40
    const-string v0, "collectDbStats"

    .line 41
    .line 42
    invoke-direct {v3, v0}, Lnet/zetetic/database/CursorWindow;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    :try_start_2
    const-string v1, "PRAGMA database_list;"

    .line 46
    .line 47
    const/4 v6, 0x0

    .line 48
    const/4 v7, 0x0

    .line 49
    const/4 v2, 0x0

    .line 50
    const/4 v4, 0x0

    .line 51
    const/4 v5, 0x0

    .line 52
    move-object/from16 v0, p0

    .line 53
    .line 54
    invoke-virtual/range {v0 .. v7}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForCursorWindow(Ljava/lang/String;[Ljava/lang/Object;Lnet/zetetic/database/CursorWindow;IIZLandroid/os/CancellationSignal;)I

    .line 55
    .line 56
    .line 57
    const/4 v1, 0x1

    .line 58
    move v2, v1

    .line 59
    :goto_1
    invoke-virtual {v3}, Lnet/zetetic/database/CursorWindow;->getNumRows()I

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    if-ge v2, v4, :cond_1

    .line 64
    .line 65
    invoke-virtual {v3, v2, v1}, Lnet/zetetic/database/CursorWindow;->getString(II)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    const/4 v5, 0x2

    .line 70
    invoke-virtual {v3, v2, v5}, Lnet/zetetic/database/CursorWindow;->getString(II)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v5
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_4
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 74
    :try_start_3
    new-instance v6, Ljava/lang/StringBuilder;

    .line 75
    .line 76
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 77
    .line 78
    .line 79
    invoke-virtual {v6, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string v7, ".page_count;"

    .line 86
    .line 87
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v6

    .line 94
    invoke-virtual {v0, v6, v10, v10}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForLong(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J

    .line 95
    .line 96
    .line 97
    move-result-wide v6
    :try_end_3
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_3 .. :try_end_3} :catch_2
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 98
    :try_start_4
    new-instance v13, Ljava/lang/StringBuilder;

    .line 99
    .line 100
    invoke-direct {v13}, Ljava/lang/StringBuilder;-><init>()V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v13, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v13, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const-string v14, ".page_size;"

    .line 110
    .line 111
    invoke-virtual {v13, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v13

    .line 118
    invoke-virtual {v0, v13, v10, v10}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->executeForLong(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J

    .line 119
    .line 120
    .line 121
    move-result-wide v13
    :try_end_4
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_4 .. :try_end_4} :catch_3
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 122
    move-wide/from16 v17, v13

    .line 123
    .line 124
    :goto_2
    move-wide v15, v6

    .line 125
    goto :goto_3

    .line 126
    :catchall_0
    move-exception v0

    .line 127
    goto :goto_4

    .line 128
    :catch_2
    move-wide v6, v11

    .line 129
    :catch_3
    move-wide/from16 v17, v11

    .line 130
    .line 131
    goto :goto_2

    .line 132
    :goto_3
    :try_start_5
    new-instance v6, Ljava/lang/StringBuilder;

    .line 133
    .line 134
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 135
    .line 136
    .line 137
    const-string v7, "  (attached) "

    .line 138
    .line 139
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v4

    .line 149
    invoke-virtual {v5}, Ljava/lang/String;->isEmpty()Z

    .line 150
    .line 151
    .line 152
    move-result v6

    .line 153
    if-nez v6, :cond_0

    .line 154
    .line 155
    new-instance v6, Ljava/lang/StringBuilder;

    .line 156
    .line 157
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 158
    .line 159
    .line 160
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    const-string v4, ": "

    .line 164
    .line 165
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v4

    .line 175
    :cond_0
    move-object v14, v4

    .line 176
    new-instance v13, Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;

    .line 177
    .line 178
    const/16 v21, 0x0

    .line 179
    .line 180
    const/16 v22, 0x0

    .line 181
    .line 182
    const/16 v19, 0x0

    .line 183
    .line 184
    const/16 v20, 0x0

    .line 185
    .line 186
    invoke-direct/range {v13 .. v22}, Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;-><init>(Ljava/lang/String;JJIIII)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v8, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_5
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_5 .. :try_end_5} :catch_4
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 190
    .line 191
    .line 192
    add-int/lit8 v2, v2, 0x1

    .line 193
    .line 194
    goto/16 :goto_1

    .line 195
    .line 196
    :catch_4
    :cond_1
    invoke-virtual {v3}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 197
    .line 198
    .line 199
    goto :goto_5

    .line 200
    :goto_4
    invoke-virtual {v3}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 201
    .line 202
    .line 203
    throw v0

    .line 204
    :goto_5
    return-void
.end method

.method public collectDbStatsUnsafe(Ljava/util/ArrayList;)V
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/ArrayList<",
            "Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-wide/16 v2, 0x0

    .line 2
    .line 3
    const-wide/16 v4, 0x0

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    move-object v0, p0

    .line 7
    invoke-direct/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->getMainDbStatsUnsafe(IJJ)Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public describeCurrentOperationUnsafe()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 2
    .line 3
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->describeCurrentOperation()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public dump(Landroid/util/Printer;Z)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->dumpUnsafe(Landroid/util/Printer;Z)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public dumpUnsafe(Landroid/util/Printer;Z)V
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Connection #"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionId:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ":"

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-interface {p1, v0}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    if-eqz p2, :cond_0

    .line 26
    .line 27
    new-instance v0, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    const-string v1, "  connectionPtr: 0x"

    .line 30
    .line 31
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    iget-wide v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 35
    .line 36
    invoke-static {v1, v2}, Ljava/lang/Long;->toHexString(J)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-interface {p1, v0}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    const-string v1, "  isPrimaryConnection: "

    .line 53
    .line 54
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-boolean v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mIsPrimaryConnection:Z

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    invoke-interface {p1, v0}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    new-instance v0, Ljava/lang/StringBuilder;

    .line 70
    .line 71
    const-string v1, "  onlyAllowReadOnlyOperations: "

    .line 72
    .line 73
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    iget-boolean v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mOnlyAllowReadOnlyOperations:Z

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    invoke-interface {p1, v0}, Landroid/util/Printer;->println(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 89
    .line 90
    invoke-virtual {v0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->dump(Landroid/util/Printer;Z)V

    .line 91
    .line 92
    .line 93
    if-eqz p2, :cond_1

    .line 94
    .line 95
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementCache:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;

    .line 96
    .line 97
    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;->dump(Landroid/util/Printer;)V

    .line 98
    .line 99
    .line 100
    :cond_1
    return-void
.end method

.method public enableLocalizedCollators()V
    .locals 1

    .line 1
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeHasCodec()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setLocaleFromConfiguration()V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public execute(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V
    .locals 5

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 4
    .line 5
    const-string v1, "execute"

    .line 6
    .line 7
    invoke-virtual {v0, v1, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->beginOperation(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    :try_start_0
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->acquirePreparedStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 12
    .line 13
    .line 14
    move-result-object p1
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    :try_start_1
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->throwIfStatementForbidden(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->bindArguments(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->applyBlockGuardPolicy(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 22
    .line 23
    .line 24
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->attachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 25
    .line 26
    .line 27
    :try_start_2
    iget-wide v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 28
    .line 29
    iget-wide v3, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 30
    .line 31
    invoke-static {v1, v2, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeExecute(JJ)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 32
    .line 33
    .line 34
    :try_start_3
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 35
    .line 36
    .line 37
    :try_start_4
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    :try_end_4
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 38
    .line 39
    .line 40
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 41
    .line 42
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 43
    .line 44
    .line 45
    return-void

    .line 46
    :catchall_0
    move-exception p1

    .line 47
    goto :goto_2

    .line 48
    :catch_0
    move-exception p1

    .line 49
    goto :goto_1

    .line 50
    :catchall_1
    move-exception p2

    .line 51
    goto :goto_0

    .line 52
    :catchall_2
    move-exception p2

    .line 53
    :try_start_5
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V

    .line 54
    .line 55
    .line 56
    throw p2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 57
    :goto_0
    :try_start_6
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 58
    .line 59
    .line 60
    throw p2
    :try_end_6
    .catch Ljava/lang/RuntimeException; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 61
    :goto_1
    :try_start_7
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 62
    .line 63
    invoke-virtual {p2, v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->failOperation(ILjava/lang/Exception;)V

    .line 64
    .line 65
    .line 66
    throw p1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 67
    :goto_2
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 68
    .line 69
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 70
    .line 71
    .line 72
    throw p1

    .line 73
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 74
    .line 75
    const-string p1, "sql must not be null."

    .line 76
    .line 77
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p0
.end method

.method public executeForBlobFileDescriptor(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)Landroid/os/ParcelFileDescriptor;
    .locals 5

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 4
    .line 5
    const-string v1, "executeForBlobFileDescriptor"

    .line 6
    .line 7
    invoke-virtual {v0, v1, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->beginOperation(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    :try_start_0
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->acquirePreparedStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 12
    .line 13
    .line 14
    move-result-object p1
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 15
    :try_start_1
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->throwIfStatementForbidden(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->bindArguments(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->applyBlockGuardPolicy(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 22
    .line 23
    .line 24
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->attachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 25
    .line 26
    .line 27
    :try_start_2
    iget-wide v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 28
    .line 29
    iget-wide v3, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 30
    .line 31
    invoke-static {v1, v2, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeExecuteForBlobFileDescriptor(JJ)I

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    if-ltz p2, :cond_0

    .line 36
    .line 37
    invoke-static {p2}, Landroid/os/ParcelFileDescriptor;->adoptFd(I)Landroid/os/ParcelFileDescriptor;

    .line 38
    .line 39
    .line 40
    move-result-object p2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 41
    goto :goto_0

    .line 42
    :catchall_0
    move-exception p2

    .line 43
    goto :goto_1

    .line 44
    :cond_0
    const/4 p2, 0x0

    .line 45
    :goto_0
    :try_start_3
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 46
    .line 47
    .line 48
    :try_start_4
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    :try_end_4
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 52
    .line 53
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 54
    .line 55
    .line 56
    return-object p2

    .line 57
    :catchall_1
    move-exception p1

    .line 58
    goto :goto_4

    .line 59
    :catch_0
    move-exception p1

    .line 60
    goto :goto_3

    .line 61
    :catchall_2
    move-exception p2

    .line 62
    goto :goto_2

    .line 63
    :goto_1
    :try_start_5
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V

    .line 64
    .line 65
    .line 66
    throw p2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 67
    :goto_2
    :try_start_6
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 68
    .line 69
    .line 70
    throw p2
    :try_end_6
    .catch Ljava/lang/RuntimeException; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 71
    :goto_3
    :try_start_7
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 72
    .line 73
    invoke-virtual {p2, v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->failOperation(ILjava/lang/Exception;)V

    .line 74
    .line 75
    .line 76
    throw p1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 77
    :goto_4
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 78
    .line 79
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 80
    .line 81
    .line 82
    throw p1

    .line 83
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 84
    .line 85
    const-string p1, "sql must not be null."

    .line 86
    .line 87
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw p0
.end method

.method public executeForChangedRowCount(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)I
    .locals 7

    .line 1
    const-string v0, "changedRows="

    .line 2
    .line 3
    if-eqz p1, :cond_2

    .line 4
    .line 5
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 6
    .line 7
    const-string v2, "executeForChangedRowCount"

    .line 8
    .line 9
    invoke-virtual {v1, v2, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->beginOperation(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    const/4 v2, 0x0

    .line 14
    :try_start_0
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->acquirePreparedStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 15
    .line 16
    .line 17
    move-result-object p1
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    :try_start_1
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->throwIfStatementForbidden(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->bindArguments(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;[Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->applyBlockGuardPolicy(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 25
    .line 26
    .line 27
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->attachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 28
    .line 29
    .line 30
    :try_start_2
    iget-wide v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 31
    .line 32
    iget-wide v5, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 33
    .line 34
    invoke-static {v3, v4, v5, v6}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeExecuteForChangedRowCount(JJ)I

    .line 35
    .line 36
    .line 37
    move-result v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 38
    :try_start_3
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 39
    .line 40
    .line 41
    :try_start_4
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    :try_end_4
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 42
    .line 43
    .line 44
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 45
    .line 46
    invoke-virtual {p1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperationDeferLog(I)Z

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    if-eqz p1, :cond_0

    .line 51
    .line 52
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 53
    .line 54
    invoke-static {v2, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    invoke-virtual {p0, v1, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->logOperation(ILjava/lang/String;)V

    .line 59
    .line 60
    .line 61
    :cond_0
    return v2

    .line 62
    :catchall_0
    move-exception p1

    .line 63
    goto :goto_2

    .line 64
    :catch_0
    move-exception p1

    .line 65
    goto :goto_1

    .line 66
    :catchall_1
    move-exception p2

    .line 67
    goto :goto_0

    .line 68
    :catchall_2
    move-exception p2

    .line 69
    :try_start_5
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V

    .line 70
    .line 71
    .line 72
    throw p2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 73
    :goto_0
    :try_start_6
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 74
    .line 75
    .line 76
    throw p2
    :try_end_6
    .catch Ljava/lang/RuntimeException; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 77
    :goto_1
    :try_start_7
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 78
    .line 79
    invoke-virtual {p2, v1, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->failOperation(ILjava/lang/Exception;)V

    .line 80
    .line 81
    .line 82
    throw p1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 83
    :goto_2
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 84
    .line 85
    invoke-virtual {p2, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperationDeferLog(I)Z

    .line 86
    .line 87
    .line 88
    move-result p2

    .line 89
    if-eqz p2, :cond_1

    .line 90
    .line 91
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 92
    .line 93
    invoke-static {v2, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    invoke-virtual {p0, v1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->logOperation(ILjava/lang/String;)V

    .line 98
    .line 99
    .line 100
    :cond_1
    throw p1

    .line 101
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 102
    .line 103
    const-string p1, "sql must not be null."

    .line 104
    .line 105
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    throw p0
.end method

.method public executeForCursorWindow(Ljava/lang/String;[Ljava/lang/Object;Lnet/zetetic/database/CursorWindow;IIZLandroid/os/CancellationSignal;)I
    .locals 19

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    move-object/from16 v13, p7

    .line 10
    .line 11
    const-string v14, ", countedRows="

    .line 12
    .line 13
    const-string v15, ", filledRows="

    .line 14
    .line 15
    const-string v4, ", actualPos="

    .line 16
    .line 17
    const-string v5, "\', startPos="

    .line 18
    .line 19
    const-string v6, "window=\'"

    .line 20
    .line 21
    if-eqz v0, :cond_3

    .line 22
    .line 23
    if-eqz v3, :cond_2

    .line 24
    .line 25
    invoke-virtual {v3}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->acquireReference()V

    .line 26
    .line 27
    .line 28
    :try_start_0
    iget-object v7, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 29
    .line 30
    const-string v8, "executeForCursorWindow"

    .line 31
    .line 32
    invoke-virtual {v7, v8, v0, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->beginOperation(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)I

    .line 33
    .line 34
    .line 35
    move-result v7
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    const/16 v16, -0x1

    .line 37
    .line 38
    :try_start_1
    invoke-direct/range {p0 .. p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->acquirePreparedStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 39
    .line 40
    .line 41
    move-result-object v8
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_2
    .catchall {:try_start_1 .. :try_end_1} :catchall_c

    .line 42
    :try_start_2
    invoke-direct {v1, v8}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->throwIfStatementForbidden(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 43
    .line 44
    .line 45
    invoke-direct {v1, v8, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->bindArguments(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;[Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    invoke-direct {v1, v8}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->applyBlockGuardPolicy(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 49
    .line 50
    .line 51
    invoke-direct {v1, v13}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->attachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_a

    .line 52
    .line 53
    .line 54
    move-object v2, v4

    .line 55
    move-object v9, v5

    .line 56
    :try_start_3
    iget-wide v4, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_8

    .line 57
    .line 58
    move-object v10, v6

    .line 59
    move v11, v7

    .line 60
    :try_start_4
    iget-wide v6, v8, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_7

    .line 61
    .line 62
    move-object/from16 v17, v8

    .line 63
    .line 64
    move-object v12, v9

    .line 65
    :try_start_5
    iget-wide v8, v3, Lnet/zetetic/database/CursorWindow;->mWindowPtr:J
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_6

    .line 66
    .line 67
    move-object/from16 p1, v17

    .line 68
    .line 69
    move-object/from16 v17, v14

    .line 70
    .line 71
    move-object/from16 v14, p1

    .line 72
    .line 73
    move-object/from16 p1, v2

    .line 74
    .line 75
    move v2, v11

    .line 76
    move-object/from16 p2, v12

    .line 77
    .line 78
    move-object/from16 v18, v15

    .line 79
    .line 80
    move/from16 v11, p5

    .line 81
    .line 82
    move/from16 v12, p6

    .line 83
    .line 84
    move-object v15, v10

    .line 85
    move/from16 v10, p4

    .line 86
    .line 87
    :try_start_6
    invoke-static/range {v4 .. v12}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeExecuteForCursorWindow(JJJIIZ)J

    .line 88
    .line 89
    .line 90
    move-result-wide v4
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_5

    .line 91
    const/16 v0, 0x20

    .line 92
    .line 93
    shr-long v6, v4, v0

    .line 94
    .line 95
    long-to-int v6, v6

    .line 96
    long-to-int v4, v4

    .line 97
    :try_start_7
    invoke-virtual {v3}, Lnet/zetetic/database/CursorWindow;->getNumRows()I

    .line 98
    .line 99
    .line 100
    move-result v5
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_4

    .line 101
    :try_start_8
    invoke-virtual {v3, v6}, Lnet/zetetic/database/CursorWindow;->setStartPosition(I)V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_3

    .line 102
    .line 103
    .line 104
    :try_start_9
    invoke-direct {v1, v13}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_2

    .line 105
    .line 106
    .line 107
    :try_start_a
    invoke-direct {v1, v14}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    :try_end_a
    .catch Ljava/lang/RuntimeException; {:try_start_a .. :try_end_a} :catch_0
    .catchall {:try_start_a .. :try_end_a} :catchall_1

    .line 108
    .line 109
    .line 110
    :try_start_b
    iget-object v0, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 111
    .line 112
    invoke-virtual {v0, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperationDeferLog(I)Z

    .line 113
    .line 114
    .line 115
    move-result v0

    .line 116
    if-eqz v0, :cond_0

    .line 117
    .line 118
    iget-object v0, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 119
    .line 120
    new-instance v1, Ljava/lang/StringBuilder;

    .line 121
    .line 122
    invoke-direct {v1, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    move-object/from16 v9, p2

    .line 129
    .line 130
    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v1, v10}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    move-object/from16 v7, p1

    .line 137
    .line 138
    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    move-object/from16 v8, v18

    .line 145
    .line 146
    invoke-virtual {v1, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    move-object/from16 v11, v17

    .line 153
    .line 154
    invoke-virtual {v1, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v1

    .line 164
    invoke-virtual {v0, v2, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->logOperation(ILjava/lang/String;)V
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_0

    .line 165
    .line 166
    .line 167
    goto :goto_0

    .line 168
    :catchall_0
    move-exception v0

    .line 169
    goto/16 :goto_8

    .line 170
    .line 171
    :cond_0
    :goto_0
    invoke-virtual {v3}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 172
    .line 173
    .line 174
    return v4

    .line 175
    :catchall_1
    move-exception v0

    .line 176
    move-object/from16 v7, p1

    .line 177
    .line 178
    move-object/from16 v9, p2

    .line 179
    .line 180
    move-object/from16 v11, v17

    .line 181
    .line 182
    move-object/from16 v8, v18

    .line 183
    .line 184
    goto/16 :goto_7

    .line 185
    .line 186
    :catch_0
    move-exception v0

    .line 187
    move-object/from16 v7, p1

    .line 188
    .line 189
    move-object/from16 v9, p2

    .line 190
    .line 191
    move-object/from16 v11, v17

    .line 192
    .line 193
    move-object/from16 v8, v18

    .line 194
    .line 195
    move/from16 v16, v6

    .line 196
    .line 197
    goto/16 :goto_6

    .line 198
    .line 199
    :catchall_2
    move-exception v0

    .line 200
    move-object/from16 v7, p1

    .line 201
    .line 202
    move-object/from16 v9, p2

    .line 203
    .line 204
    move-object/from16 v11, v17

    .line 205
    .line 206
    move-object/from16 v8, v18

    .line 207
    .line 208
    move/from16 v16, v6

    .line 209
    .line 210
    goto/16 :goto_5

    .line 211
    .line 212
    :catchall_3
    move-exception v0

    .line 213
    move-object/from16 v7, p1

    .line 214
    .line 215
    move-object/from16 v9, p2

    .line 216
    .line 217
    move-object/from16 v11, v17

    .line 218
    .line 219
    move-object/from16 v8, v18

    .line 220
    .line 221
    :goto_1
    move/from16 v16, v6

    .line 222
    .line 223
    goto :goto_4

    .line 224
    :catchall_4
    move-exception v0

    .line 225
    move-object/from16 v7, p1

    .line 226
    .line 227
    move-object/from16 v9, p2

    .line 228
    .line 229
    move-object/from16 v11, v17

    .line 230
    .line 231
    move-object/from16 v8, v18

    .line 232
    .line 233
    move/from16 v5, v16

    .line 234
    .line 235
    goto :goto_1

    .line 236
    :catchall_5
    move-exception v0

    .line 237
    move-object/from16 v7, p1

    .line 238
    .line 239
    move-object/from16 v9, p2

    .line 240
    .line 241
    move-object/from16 v11, v17

    .line 242
    .line 243
    move-object/from16 v8, v18

    .line 244
    .line 245
    :goto_2
    move/from16 v4, v16

    .line 246
    .line 247
    move v5, v4

    .line 248
    goto :goto_4

    .line 249
    :catchall_6
    move-exception v0

    .line 250
    move-object v7, v2

    .line 251
    move v2, v11

    .line 252
    move-object v9, v12

    .line 253
    move-object v11, v14

    .line 254
    move-object v8, v15

    .line 255
    move-object/from16 v14, v17

    .line 256
    .line 257
    :goto_3
    move-object v15, v10

    .line 258
    move/from16 v10, p4

    .line 259
    .line 260
    goto :goto_2

    .line 261
    :catchall_7
    move-exception v0

    .line 262
    move-object v7, v2

    .line 263
    move v2, v11

    .line 264
    move-object v11, v14

    .line 265
    move-object v14, v8

    .line 266
    move-object v8, v15

    .line 267
    goto :goto_3

    .line 268
    :catchall_8
    move-exception v0

    .line 269
    move v10, v7

    .line 270
    move-object v7, v2

    .line 271
    move v2, v10

    .line 272
    move/from16 v10, p4

    .line 273
    .line 274
    move-object v11, v14

    .line 275
    move-object v14, v8

    .line 276
    move-object v8, v15

    .line 277
    move-object v15, v6

    .line 278
    goto :goto_2

    .line 279
    :goto_4
    :try_start_c
    invoke-direct {v1, v13}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V

    .line 280
    .line 281
    .line 282
    throw v0
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_9

    .line 283
    :catchall_9
    move-exception v0

    .line 284
    goto :goto_5

    .line 285
    :catchall_a
    move-exception v0

    .line 286
    move/from16 v10, p4

    .line 287
    .line 288
    move-object v9, v5

    .line 289
    move v2, v7

    .line 290
    move-object v11, v14

    .line 291
    move-object v7, v4

    .line 292
    move-object v14, v8

    .line 293
    move-object v8, v15

    .line 294
    move-object v15, v6

    .line 295
    move/from16 v4, v16

    .line 296
    .line 297
    move v5, v4

    .line 298
    :goto_5
    :try_start_d
    invoke-direct {v1, v14}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 299
    .line 300
    .line 301
    throw v0
    :try_end_d
    .catch Ljava/lang/RuntimeException; {:try_start_d .. :try_end_d} :catch_1
    .catchall {:try_start_d .. :try_end_d} :catchall_b

    .line 302
    :catchall_b
    move-exception v0

    .line 303
    move/from16 v6, v16

    .line 304
    .line 305
    goto :goto_7

    .line 306
    :catch_1
    move-exception v0

    .line 307
    goto :goto_6

    .line 308
    :catchall_c
    move-exception v0

    .line 309
    move/from16 v10, p4

    .line 310
    .line 311
    move-object v9, v5

    .line 312
    move v2, v7

    .line 313
    move-object v11, v14

    .line 314
    move-object v8, v15

    .line 315
    move-object v7, v4

    .line 316
    move-object v15, v6

    .line 317
    move/from16 v4, v16

    .line 318
    .line 319
    move v5, v4

    .line 320
    move v6, v5

    .line 321
    goto :goto_7

    .line 322
    :catch_2
    move-exception v0

    .line 323
    move/from16 v10, p4

    .line 324
    .line 325
    move-object v9, v5

    .line 326
    move v2, v7

    .line 327
    move-object v11, v14

    .line 328
    move-object v8, v15

    .line 329
    move-object v7, v4

    .line 330
    move-object v15, v6

    .line 331
    move/from16 v4, v16

    .line 332
    .line 333
    move v5, v4

    .line 334
    :goto_6
    :try_start_e
    iget-object v6, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 335
    .line 336
    invoke-virtual {v6, v2, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->failOperation(ILjava/lang/Exception;)V

    .line 337
    .line 338
    .line 339
    throw v0
    :try_end_e
    .catchall {:try_start_e .. :try_end_e} :catchall_b

    .line 340
    :goto_7
    :try_start_f
    iget-object v12, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 341
    .line 342
    invoke-virtual {v12, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperationDeferLog(I)Z

    .line 343
    .line 344
    .line 345
    move-result v12

    .line 346
    if-eqz v12, :cond_1

    .line 347
    .line 348
    iget-object v1, v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 349
    .line 350
    new-instance v12, Ljava/lang/StringBuilder;

    .line 351
    .line 352
    invoke-direct {v12, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 353
    .line 354
    .line 355
    invoke-virtual {v12, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 356
    .line 357
    .line 358
    invoke-virtual {v12, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 359
    .line 360
    .line 361
    invoke-virtual {v12, v10}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 362
    .line 363
    .line 364
    invoke-virtual {v12, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 365
    .line 366
    .line 367
    invoke-virtual {v12, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 368
    .line 369
    .line 370
    invoke-virtual {v12, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 371
    .line 372
    .line 373
    invoke-virtual {v12, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 374
    .line 375
    .line 376
    invoke-virtual {v12, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 377
    .line 378
    .line 379
    invoke-virtual {v12, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 380
    .line 381
    .line 382
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 383
    .line 384
    .line 385
    move-result-object v4

    .line 386
    invoke-virtual {v1, v2, v4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->logOperation(ILjava/lang/String;)V

    .line 387
    .line 388
    .line 389
    :cond_1
    throw v0
    :try_end_f
    .catchall {:try_start_f .. :try_end_f} :catchall_0

    .line 390
    :goto_8
    invoke-virtual {v3}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->releaseReference()V

    .line 391
    .line 392
    .line 393
    throw v0

    .line 394
    :cond_2
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 395
    .line 396
    const-string v1, "window must not be null."

    .line 397
    .line 398
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 399
    .line 400
    .line 401
    throw v0

    .line 402
    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 403
    .line 404
    const-string v1, "sql must not be null."

    .line 405
    .line 406
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 407
    .line 408
    .line 409
    throw v0
.end method

.method public executeForLastInsertedRowId(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J
    .locals 5

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 4
    .line 5
    const-string v1, "executeForLastInsertedRowId"

    .line 6
    .line 7
    invoke-virtual {v0, v1, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->beginOperation(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    :try_start_0
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->acquirePreparedStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 12
    .line 13
    .line 14
    move-result-object p1
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    :try_start_1
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->throwIfStatementForbidden(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->bindArguments(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->applyBlockGuardPolicy(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 22
    .line 23
    .line 24
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->attachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 25
    .line 26
    .line 27
    :try_start_2
    iget-wide v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 28
    .line 29
    iget-wide v3, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 30
    .line 31
    invoke-static {v1, v2, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeExecuteForLastInsertedRowId(JJ)J

    .line 32
    .line 33
    .line 34
    move-result-wide v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 35
    :try_start_3
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 36
    .line 37
    .line 38
    :try_start_4
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    :try_end_4
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 44
    .line 45
    .line 46
    return-wide v1

    .line 47
    :catchall_0
    move-exception p1

    .line 48
    goto :goto_2

    .line 49
    :catch_0
    move-exception p1

    .line 50
    goto :goto_1

    .line 51
    :catchall_1
    move-exception p2

    .line 52
    goto :goto_0

    .line 53
    :catchall_2
    move-exception p2

    .line 54
    :try_start_5
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V

    .line 55
    .line 56
    .line 57
    throw p2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 58
    :goto_0
    :try_start_6
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 59
    .line 60
    .line 61
    throw p2
    :try_end_6
    .catch Ljava/lang/RuntimeException; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 62
    :goto_1
    :try_start_7
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 63
    .line 64
    invoke-virtual {p2, v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->failOperation(ILjava/lang/Exception;)V

    .line 65
    .line 66
    .line 67
    throw p1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 68
    :goto_2
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 69
    .line 70
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 71
    .line 72
    .line 73
    throw p1

    .line 74
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 75
    .line 76
    const-string p1, "sql must not be null."

    .line 77
    .line 78
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0
.end method

.method public executeForLong(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)J
    .locals 5

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 4
    .line 5
    const-string v1, "executeForLong"

    .line 6
    .line 7
    invoke-virtual {v0, v1, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->beginOperation(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    :try_start_0
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->acquirePreparedStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 12
    .line 13
    .line 14
    move-result-object p1
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    :try_start_1
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->throwIfStatementForbidden(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->bindArguments(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->applyBlockGuardPolicy(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 22
    .line 23
    .line 24
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->attachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 25
    .line 26
    .line 27
    :try_start_2
    iget-wide v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 28
    .line 29
    iget-wide v3, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 30
    .line 31
    invoke-static {v1, v2, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeExecuteForLong(JJ)J

    .line 32
    .line 33
    .line 34
    move-result-wide v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 35
    :try_start_3
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 36
    .line 37
    .line 38
    :try_start_4
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    :try_end_4
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 44
    .line 45
    .line 46
    return-wide v1

    .line 47
    :catchall_0
    move-exception p1

    .line 48
    goto :goto_2

    .line 49
    :catch_0
    move-exception p1

    .line 50
    goto :goto_1

    .line 51
    :catchall_1
    move-exception p2

    .line 52
    goto :goto_0

    .line 53
    :catchall_2
    move-exception p2

    .line 54
    :try_start_5
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V

    .line 55
    .line 56
    .line 57
    throw p2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 58
    :goto_0
    :try_start_6
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 59
    .line 60
    .line 61
    throw p2
    :try_end_6
    .catch Ljava/lang/RuntimeException; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 62
    :goto_1
    :try_start_7
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 63
    .line 64
    invoke-virtual {p2, v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->failOperation(ILjava/lang/Exception;)V

    .line 65
    .line 66
    .line 67
    throw p1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 68
    :goto_2
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 69
    .line 70
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 71
    .line 72
    .line 73
    throw p1

    .line 74
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 75
    .line 76
    const-string p1, "sql must not be null."

    .line 77
    .line 78
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0
.end method

.method public executeForString(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)Ljava/lang/String;
    .locals 5

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 4
    .line 5
    const-string v1, "executeForString"

    .line 6
    .line 7
    invoke-virtual {v0, v1, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->beginOperation(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    :try_start_0
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->acquirePreparedStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 12
    .line 13
    .line 14
    move-result-object p1
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    :try_start_1
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->throwIfStatementForbidden(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->bindArguments(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->applyBlockGuardPolicy(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 22
    .line 23
    .line 24
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->attachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 25
    .line 26
    .line 27
    :try_start_2
    iget-wide v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 28
    .line 29
    iget-wide v3, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 30
    .line 31
    invoke-static {v1, v2, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeExecuteForString(JJ)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 35
    :try_start_3
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 36
    .line 37
    .line 38
    :try_start_4
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    :try_end_4
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 42
    .line 43
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 44
    .line 45
    .line 46
    return-object p2

    .line 47
    :catchall_0
    move-exception p1

    .line 48
    goto :goto_2

    .line 49
    :catch_0
    move-exception p1

    .line 50
    goto :goto_1

    .line 51
    :catchall_1
    move-exception p2

    .line 52
    goto :goto_0

    .line 53
    :catchall_2
    move-exception p2

    .line 54
    :try_start_5
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V

    .line 55
    .line 56
    .line 57
    throw p2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 58
    :goto_0
    :try_start_6
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 59
    .line 60
    .line 61
    throw p2
    :try_end_6
    .catch Ljava/lang/RuntimeException; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 62
    :goto_1
    :try_start_7
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 63
    .line 64
    invoke-virtual {p2, v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->failOperation(ILjava/lang/Exception;)V

    .line 65
    .line 66
    .line 67
    throw p1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 68
    :goto_2
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 69
    .line 70
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 71
    .line 72
    .line 73
    throw p1

    .line 74
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 75
    .line 76
    const-string p1, "sql must not be null."

    .line 77
    .line 78
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw p0
.end method

.method public executeRaw(Ljava/lang/String;[Ljava/lang/Object;Landroid/os/CancellationSignal;)V
    .locals 6

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    if-eqz p1, :cond_2

    .line 4
    .line 5
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 6
    .line 7
    const-string v2, "executeRaw"

    .line 8
    .line 9
    invoke-virtual {v1, v2, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->beginOperation(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    :try_start_0
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->acquirePreparedStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 14
    .line 15
    .line 16
    move-result-object p1
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    :try_start_1
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->throwIfStatementForbidden(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 18
    .line 19
    .line 20
    invoke-direct {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->bindArguments(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;[Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->applyBlockGuardPolicy(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->attachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 27
    .line 28
    .line 29
    :try_start_2
    iget-wide v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 30
    .line 31
    iget-wide v4, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 32
    .line 33
    invoke-static {v2, v3, v4, v5}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeExecuteRaw(JJ)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 34
    .line 35
    .line 36
    :try_start_3
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 37
    .line 38
    .line 39
    :try_start_4
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    :try_end_4
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 40
    .line 41
    .line 42
    iget-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 43
    .line 44
    invoke-virtual {p1, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperationDeferLog(I)Z

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    if-eqz p1, :cond_0

    .line 49
    .line 50
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 51
    .line 52
    invoke-virtual {p0, v1, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->logOperation(ILjava/lang/String;)V

    .line 53
    .line 54
    .line 55
    :cond_0
    return-void

    .line 56
    :catchall_0
    move-exception p1

    .line 57
    goto :goto_2

    .line 58
    :catch_0
    move-exception p1

    .line 59
    goto :goto_1

    .line 60
    :catchall_1
    move-exception p2

    .line 61
    goto :goto_0

    .line 62
    :catchall_2
    move-exception p2

    .line 63
    :try_start_5
    invoke-direct {p0, p3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->detachCancellationSignal(Landroid/os/CancellationSignal;)V

    .line 64
    .line 65
    .line 66
    throw p2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 67
    :goto_0
    :try_start_6
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 68
    .line 69
    .line 70
    throw p2
    :try_end_6
    .catch Ljava/lang/RuntimeException; {:try_start_6 .. :try_end_6} :catch_0
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 71
    :goto_1
    :try_start_7
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 72
    .line 73
    invoke-virtual {p2, v1, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->failOperation(ILjava/lang/Exception;)V

    .line 74
    .line 75
    .line 76
    throw p1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 77
    :goto_2
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 78
    .line 79
    invoke-virtual {p2, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperationDeferLog(I)Z

    .line 80
    .line 81
    .line 82
    move-result p2

    .line 83
    if-eqz p2, :cond_1

    .line 84
    .line 85
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 86
    .line 87
    invoke-virtual {p0, v1, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->logOperation(ILjava/lang/String;)V

    .line 88
    .line 89
    .line 90
    :cond_1
    throw p1

    .line 91
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 92
    .line 93
    const-string p1, "sql must not be null."

    .line 94
    .line 95
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    throw p0
.end method

.method public finalize()V
    .locals 5

    .line 1
    :try_start_0
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPool:Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-wide v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 6
    .line 7
    const-wide/16 v3, 0x0

    .line 8
    .line 9
    cmp-long v1, v1, v3

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnectionPool;->onConnectionLeaked()V

    .line 14
    .line 15
    .line 16
    goto :goto_0

    .line 17
    :catchall_0
    move-exception v0

    .line 18
    goto :goto_1

    .line 19
    :cond_0
    :goto_0
    const/4 v0, 0x1

    .line 20
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->dispose(Z)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    .line 22
    .line 23
    invoke-super {p0}, Ljava/lang/Object;->finalize()V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :goto_1
    invoke-super {p0}, Ljava/lang/Object;->finalize()V

    .line 28
    .line 29
    .line 30
    throw v0
.end method

.method public getConnectionId()I
    .locals 0

    .line 1
    iget p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionId:I

    .line 2
    .line 3
    return p0
.end method

.method public isPreparedStatementInCache(Ljava/lang/String;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mPreparedStatementCache:Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatementCache;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/util/LruCache;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

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

.method public isPrimaryConnection()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mIsPrimaryConnection:Z

    .line 2
    .line 3
    return p0
.end method

.method public onCancel()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeCancel(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public prepare(Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;)V
    .locals 8

    .line 1
    if-eqz p1, :cond_2

    .line 2
    .line 3
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 4
    .line 5
    const-string v1, "prepare"

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-virtual {v0, v1, p1, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->beginOperation(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    :try_start_0
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->acquirePreparedStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;

    .line 13
    .line 14
    .line 15
    move-result-object p1
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 16
    if-eqz p2, :cond_1

    .line 17
    .line 18
    :try_start_1
    iget v1, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mNumParameters:I

    .line 19
    .line 20
    iput v1, p2, Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;->numParameters:I

    .line 21
    .line 22
    iget-boolean v1, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mReadOnly:Z

    .line 23
    .line 24
    iput-boolean v1, p2, Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;->readOnly:Z

    .line 25
    .line 26
    iget-wide v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 27
    .line 28
    iget-wide v3, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 29
    .line 30
    invoke-static {v1, v2, v3, v4}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeGetColumnCount(JJ)I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-nez v1, :cond_0

    .line 35
    .line 36
    sget-object v1, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->EMPTY_STRING_ARRAY:[Ljava/lang/String;

    .line 37
    .line 38
    iput-object v1, p2, Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;->columnNames:[Ljava/lang/String;

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :catchall_0
    move-exception p2

    .line 42
    goto :goto_1

    .line 43
    :cond_0
    new-array v2, v1, [Ljava/lang/String;

    .line 44
    .line 45
    iput-object v2, p2, Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;->columnNames:[Ljava/lang/String;

    .line 46
    .line 47
    const/4 v2, 0x0

    .line 48
    :goto_0
    if-ge v2, v1, :cond_1

    .line 49
    .line 50
    iget-object v3, p2, Lnet/zetetic/database/sqlcipher/SQLiteStatementInfo;->columnNames:[Ljava/lang/String;

    .line 51
    .line 52
    iget-wide v4, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 53
    .line 54
    iget-wide v6, p1, Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;->mStatementPtr:J

    .line 55
    .line 56
    invoke-static {v4, v5, v6, v7, v2}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeGetColumnName(JJI)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v4

    .line 60
    aput-object v4, v3, v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 61
    .line 62
    add-int/lit8 v2, v2, 0x1

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :goto_1
    :try_start_2
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V

    .line 66
    .line 67
    .line 68
    throw p2

    .line 69
    :catchall_1
    move-exception p1

    .line 70
    goto :goto_4

    .line 71
    :catch_0
    move-exception p1

    .line 72
    goto :goto_3

    .line 73
    :cond_1
    :goto_2
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->releasePreparedStatement(Lnet/zetetic/database/sqlcipher/SQLiteConnection$PreparedStatement;)V
    :try_end_2
    .catch Ljava/lang/RuntimeException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 74
    .line 75
    .line 76
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 77
    .line 78
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 79
    .line 80
    .line 81
    return-void

    .line 82
    :goto_3
    :try_start_3
    iget-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 83
    .line 84
    invoke-virtual {p2, v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->failOperation(ILjava/lang/Exception;)V

    .line 85
    .line 86
    .line 87
    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 88
    :goto_4
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mRecentOperations:Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;

    .line 89
    .line 90
    invoke-virtual {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection$OperationLog;->endOperation(I)V

    .line 91
    .line 92
    .line 93
    throw p1

    .line 94
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 95
    .line 96
    const-string p1, "sql must not be null."

    .line 97
    .line 98
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    throw p0
.end method

.method public reconfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mOnlyAllowReadOnlyOperations:Z

    .line 3
    .line 4
    iget-object v1, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->customFunctions:Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    move v2, v0

    .line 11
    :goto_0
    if-ge v2, v1, :cond_1

    .line 12
    .line 13
    iget-object v3, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->customFunctions:Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    check-cast v3, Lnet/zetetic/database/sqlcipher/SQLiteCustomFunction;

    .line 20
    .line 21
    iget-object v4, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 22
    .line 23
    iget-object v4, v4, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->customFunctions:Ljava/util/ArrayList;

    .line 24
    .line 25
    invoke-virtual {v4, v3}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v4

    .line 29
    if-nez v4, :cond_0

    .line 30
    .line 31
    iget-wide v4, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionPtr:J

    .line 32
    .line 33
    invoke-static {v4, v5, v3}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->nativeRegisterCustomFunction(JLnet/zetetic/database/sqlcipher/SQLiteCustomFunction;)V

    .line 34
    .line 35
    .line 36
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    iget-boolean v1, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->foreignKeyConstraintsEnabled:Z

    .line 40
    .line 41
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 42
    .line 43
    iget-boolean v3, v2, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->foreignKeyConstraintsEnabled:Z

    .line 44
    .line 45
    const/4 v4, 0x1

    .line 46
    if-eq v1, v3, :cond_2

    .line 47
    .line 48
    move v1, v4

    .line 49
    goto :goto_1

    .line 50
    :cond_2
    move v1, v0

    .line 51
    :goto_1
    iget v3, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 52
    .line 53
    iget v5, v2, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->openFlags:I

    .line 54
    .line 55
    xor-int/2addr v3, v5

    .line 56
    const/high16 v5, 0x20000000

    .line 57
    .line 58
    and-int/2addr v3, v5

    .line 59
    if-eqz v3, :cond_3

    .line 60
    .line 61
    move v0, v4

    .line 62
    :cond_3
    iget-object v3, p1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->locale:Ljava/util/Locale;

    .line 63
    .line 64
    iget-object v2, v2, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->locale:Ljava/util/Locale;

    .line 65
    .line 66
    invoke-virtual {v3, v2}, Ljava/util/Locale;->equals(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    iget-object v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 71
    .line 72
    invoke-virtual {v3, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->updateParametersFrom(Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;)V

    .line 73
    .line 74
    .line 75
    if-eqz v1, :cond_4

    .line 76
    .line 77
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setForeignKeyModeFromConfiguration()V

    .line 78
    .line 79
    .line 80
    :cond_4
    if-eqz v0, :cond_5

    .line 81
    .line 82
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setWalModeFromConfiguration()V

    .line 83
    .line 84
    .line 85
    :cond_5
    if-nez v2, :cond_6

    .line 86
    .line 87
    invoke-direct {p0}, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->setLocaleFromConfiguration()V

    .line 88
    .line 89
    .line 90
    :cond_6
    return-void
.end method

.method public setOnlyAllowReadOnlyOperations(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mOnlyAllowReadOnlyOperations:Z

    .line 2
    .line 3
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SQLiteConnection: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConfiguration:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;

    .line 9
    .line 10
    iget-object v1, v1, Lnet/zetetic/database/sqlcipher/SQLiteDatabaseConfiguration;->path:Ljava/lang/String;

    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v1, " ("

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    iget p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteConnection;->mConnectionId:I

    .line 21
    .line 22
    const-string v1, ")"

    .line 23
    .line 24
    invoke-static {p0, v1, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method
