.class public final Lnet/zetetic/database/sqlcipher/SQLiteGlobal;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final TAG:Ljava/lang/String; = "SQLiteGlobal"

.field private static sDefaultPageSize:I = 0x1000

.field private static final sLock:Ljava/lang/Object;

.field private static sWALConnectionPoolSize:I = 0xa


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->sLock:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static getDefaultJournalMode()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "delete"

    .line 2
    .line 3
    return-object v0
.end method

.method public static getDefaultPageSize()I
    .locals 3

    .line 1
    sget-object v0, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->sLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget v1, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->sDefaultPageSize:I

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    new-instance v1, Landroid/os/StatFs;

    .line 9
    .line 10
    const-string v2, "/data"

    .line 11
    .line 12
    invoke-direct {v1, v2}, Landroid/os/StatFs;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1}, Landroid/os/StatFs;->getBlockSize()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    sput v1, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->sDefaultPageSize:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception v1

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    :goto_0
    const/16 v1, 0x1000

    .line 25
    .line 26
    monitor-exit v0

    .line 27
    return v1

    .line 28
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 29
    throw v1
.end method

.method public static getDefaultSyncMode()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "normal"

    .line 2
    .line 3
    return-object v0
.end method

.method public static getJournalSizeLimit()I
    .locals 1

    .line 1
    const/16 v0, 0x2710

    .line 2
    .line 3
    return v0
.end method

.method public static getWALAutoCheckpoint()I
    .locals 2

    .line 1
    const/16 v0, 0x3e8

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    return v0
.end method

.method public static getWALConnectionPoolSize()I
    .locals 1

    .line 1
    sget v0, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->sWALConnectionPoolSize:I

    .line 2
    .line 3
    return v0
.end method

.method public static getWALSyncMode()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "normal"

    .line 2
    .line 3
    return-object v0
.end method

.method private static native nativeReleaseMemory()I
.end method

.method public static releaseMemory()I
    .locals 1

    .line 1
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->nativeReleaseMemory()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    return v0
.end method

.method public static setWALConnectionPoolSize(I)V
    .locals 0

    .line 1
    sput p0, Lnet/zetetic/database/sqlcipher/SQLiteGlobal;->sWALConnectionPoolSize:I

    .line 2
    .line 3
    return-void
.end method
