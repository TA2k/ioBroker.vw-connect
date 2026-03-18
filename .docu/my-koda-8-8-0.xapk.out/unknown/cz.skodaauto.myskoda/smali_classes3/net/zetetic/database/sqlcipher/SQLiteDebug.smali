.class public final Lnet/zetetic/database/sqlcipher/SQLiteDebug;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lnet/zetetic/database/sqlcipher/SQLiteDebug$PagerStats;,
        Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;
    }
.end annotation


# static fields
.field public static final DEBUG_LOG_SLOW_QUERIES:Z = false

.field public static final DEBUG_SQL_LOG:Z

.field public static final DEBUG_SQL_STATEMENTS:Z

.field public static final DEBUG_SQL_TIME:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "SQLiteLog"

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-static {v0, v1}, Lnet/zetetic/database/Logger;->isLoggable(Ljava/lang/String;I)Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    sput-boolean v0, Lnet/zetetic/database/sqlcipher/SQLiteDebug;->DEBUG_SQL_LOG:Z

    .line 9
    .line 10
    const-string v0, "SQLiteStatements"

    .line 11
    .line 12
    invoke-static {v0, v1}, Lnet/zetetic/database/Logger;->isLoggable(Ljava/lang/String;I)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    sput-boolean v0, Lnet/zetetic/database/sqlcipher/SQLiteDebug;->DEBUG_SQL_STATEMENTS:Z

    .line 17
    .line 18
    const-string v0, "SQLiteTime"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lnet/zetetic/database/Logger;->isLoggable(Ljava/lang/String;I)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    sput-boolean v0, Lnet/zetetic/database/sqlcipher/SQLiteDebug;->DEBUG_SQL_TIME:Z

    .line 25
    .line 26
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

.method public static dump(Landroid/util/Printer;[Ljava/lang/String;)V
    .locals 5

    .line 1
    array-length v0, p1

    .line 2
    const/4 v1, 0x0

    .line 3
    move v2, v1

    .line 4
    :goto_0
    if-ge v1, v0, :cond_1

    .line 5
    .line 6
    aget-object v3, p1, v1

    .line 7
    .line 8
    const-string v4, "-v"

    .line 9
    .line 10
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_1
    invoke-static {p0, v2}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->dumpAll(Landroid/util/Printer;Z)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public static getDatabaseInfo()Lnet/zetetic/database/sqlcipher/SQLiteDebug$PagerStats;
    .locals 2

    .line 1
    new-instance v0, Lnet/zetetic/database/sqlcipher/SQLiteDebug$PagerStats;

    .line 2
    .line 3
    invoke-direct {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDebug$PagerStats;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDebug;->nativeGetPagerStats(Lnet/zetetic/database/sqlcipher/SQLiteDebug$PagerStats;)V

    .line 7
    .line 8
    .line 9
    invoke-static {}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getDbStats()Ljava/util/ArrayList;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iput-object v1, v0, Lnet/zetetic/database/sqlcipher/SQLiteDebug$PagerStats;->dbStats:Ljava/util/ArrayList;

    .line 14
    .line 15
    return-object v0
.end method

.method private static native nativeGetPagerStats(Lnet/zetetic/database/sqlcipher/SQLiteDebug$PagerStats;)V
.end method

.method public static final shouldLogSlowQuery(J)Z
    .locals 2

    .line 1
    const-string v0, "db.log.slow_query_threshold"

    .line 2
    .line 3
    const-string v1, "10000"

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/lang/System;->getProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-ltz v0, :cond_0

    .line 14
    .line 15
    int-to-long v0, v0

    .line 16
    cmp-long p0, p0, v0

    .line 17
    .line 18
    if-ltz p0, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    return p0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return p0
.end method
