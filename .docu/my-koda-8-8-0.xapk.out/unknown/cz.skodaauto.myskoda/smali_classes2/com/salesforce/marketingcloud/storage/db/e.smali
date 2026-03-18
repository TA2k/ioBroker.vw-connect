.class public Lcom/salesforce/marketingcloud/storage/db/e;
.super Lcom/salesforce/marketingcloud/storage/db/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/storage/c;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "Range"
    }
.end annotation


# static fields
.field static final e:Ljava/lang/String; = "device_stats"

.field private static final f:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "DeviceStatsDbStorage"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/e;->f:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;-><init>(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static a(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/analytics/stats/b;
    .locals 6

    const/4 v0, 0x0

    .line 2
    :try_start_0
    const-string v1, "id"

    invoke-interface {p0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v1

    invoke-interface {p0, v1}, Landroid/database/Cursor;->getInt(I)I

    move-result v1

    .line 3
    const-string v2, "type"

    invoke-interface {p0, v2}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v2

    invoke-interface {p0, v2}, Landroid/database/Cursor;->getInt(I)I

    move-result v2

    .line 4
    new-instance v3, Ljava/util/Date;

    const-string v4, "date"

    invoke-interface {p0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-interface {p0, v4}, Landroid/database/Cursor;->getLong(I)J

    move-result-wide v4

    invoke-direct {v3, v4, v5}, Ljava/util/Date;-><init>(J)V

    .line 5
    const-string v4, "event_data"

    .line 6
    invoke-interface {p0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-interface {p0, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    invoke-interface {p1, v4}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Lcom/salesforce/marketingcloud/analytics/stats/d;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/analytics/stats/d;

    move-result-object p1

    .line 7
    const-string v4, "ready_to_send"

    invoke-interface {p0, v4}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v4

    invoke-interface {p0, v4}, Landroid/database/Cursor;->getInt(I)I

    move-result p0

    const/4 v4, 0x1

    if-ne p0, v4, :cond_0

    goto :goto_0

    :cond_0
    move v4, v0

    .line 8
    :goto_0
    invoke-static {v1, v2, v3, p1, v4}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a(IILjava/util/Date;Lcom/salesforce/marketingcloud/analytics/stats/d;Z)Lcom/salesforce/marketingcloud/analytics/stats/b;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p0

    .line 9
    sget-object p1, Lcom/salesforce/marketingcloud/storage/db/e;->f:Ljava/lang/String;

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Unable to read analytic item from cursor."

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p0, 0x0

    return-object p0
.end method

.method private a(Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;)Ljava/util/List;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            "Ljava/lang/String;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/stats/b;",
            ">;"
        }
    .end annotation

    .line 14
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 15
    iget-object v1, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {v1}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 16
    iget-object v1, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    const/4 v2, 0x0

    invoke-virtual {v1, p2, v2}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p2

    if-eqz p2, :cond_3

    .line 17
    invoke-interface {p2}, Landroid/database/Cursor;->moveToFirst()Z

    move-result v1

    if-eqz v1, :cond_2

    .line 18
    invoke-interface {p2}, Landroid/database/Cursor;->getCount()I

    move-result v0

    .line 19
    const-string v1, "id"

    invoke-interface {p2, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v1

    .line 20
    new-array v2, v0, [Ljava/lang/String;

    .line 21
    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3, v0}, Ljava/util/ArrayList;-><init>(I)V

    const/4 v4, 0x0

    .line 22
    :goto_0
    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/storage/db/e;->a(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/analytics/stats/b;

    move-result-object v5

    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 23
    invoke-interface {p2, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v5

    aput-object v5, v2, v4

    .line 24
    invoke-interface {p2}, Landroid/database/Cursor;->moveToNext()Z

    move-result v5

    if-eqz v5, :cond_1

    add-int/lit8 v5, v4, 0x1

    if-lt v4, v0, :cond_0

    goto :goto_1

    :cond_0
    move v4, v5

    goto :goto_0

    .line 25
    :cond_1
    :goto_1
    new-instance p1, Landroid/content/ContentValues;

    invoke-direct {p1}, Landroid/content/ContentValues;-><init>()V

    const/4 v0, 0x1

    .line 26
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    const-string v1, "in_transit"

    invoke-virtual {p1, v1, v0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 27
    :try_start_0
    invoke-static {v2}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-virtual {p0, p1, v0}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;Ljava/util/Collection;)V

    .line 28
    iget-object p1, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_2

    .line 29
    :catch_0
    sget-object p1, Lcom/salesforce/marketingcloud/storage/db/e;->f:Ljava/lang/String;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/e;->o()Ljava/lang/String;

    move-result-object v0

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "Unable to update %s table."

    invoke-static {p1, v1, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    :goto_2
    move-object v0, v3

    .line 30
    :cond_2
    invoke-interface {p2}, Landroid/database/Cursor;->close()V

    .line 31
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    :cond_3
    return-object v0
.end method

.method public static a(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "DROP TABLE IF EXISTS device_stats"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method private static b(Lcom/salesforce/marketingcloud/analytics/stats/b;Lcom/salesforce/marketingcloud/util/Crypto;)Landroid/content/ContentValues;
    .locals 3

    .line 2
    new-instance v0, Landroid/content/ContentValues;

    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/stats/b;->b()Ljava/lang/Integer;

    move-result-object v1

    if-eqz v1, :cond_0

    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/stats/b;->b()Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "id"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 5
    :cond_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/stats/b;->d()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "type"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 6
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/stats/b;->a()Ljava/util/Date;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/Date;->getTime()J

    move-result-wide v1

    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    const-string v2, "date"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/stats/b;->c()Lcom/salesforce/marketingcloud/analytics/stats/d;

    move-result-object v1

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/analytics/stats/d;->a()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    const-string v1, "event_data"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/stats/b;->e()Z

    move-result p0

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    const-string p1, "ready_to_send"

    invoke-virtual {v0, p1, p0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    return-object v0
.end method

.method public static b(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "CREATE TABLE device_stats(id INTEGER PRIMARY KEY, type INTEGER, date INTEGER, event_data TEXT, in_transit INTEGER DEFAULT 0, ready_to_send INTEGER DEFAULT 0);"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method private static c(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 3

    .line 1
    :try_start_0
    const-string v0, "SELECT id,type,date,event_data,in_transit,ready_to_send FROM device_stats"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    const/4 p0, 0x1

    return p0

    :catch_0
    move-exception p0

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/e;->f:Ljava/lang/String;

    const-string v1, "device_stats"

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "%s is invalid"

    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p0, 0x0

    return p0
.end method

.method public static d(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 4

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/e;->c(Landroid/database/sqlite/SQLiteDatabase;)Z

    move-result v0

    if-nez v0, :cond_0

    .line 2
    :try_start_0
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/e;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 3
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/e;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 4
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/e;->c(Landroid/database/sqlite/SQLiteDatabase;)Z

    move-result p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return p0

    :catch_0
    move-exception p0

    .line 5
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/e;->f:Ljava/lang/String;

    const-string v2, "device_stats"

    filled-new-array {v2}, [Ljava/lang/Object;

    move-result-object v2

    const-string v3, "Unable to recover %s"

    invoke-static {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    return v0
.end method


# virtual methods
.method public a()I
    .locals 7

    .line 32
    :try_start_0
    const-string v0, "(type = ? OR type = ?) AND in_transit = 0 AND date <= ?"

    const/16 v1, 0x6a

    .line 33
    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    const/16 v2, 0x6b

    .line 34
    invoke-static {v2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v2

    .line 35
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    const-wide/32 v5, 0x48190800

    sub-long/2addr v3, v5

    invoke-static {v3, v4}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    move-result-object v3

    filled-new-array {v1, v2, v3}, [Ljava/lang/String;

    move-result-object v1

    .line 36
    invoke-virtual {p0, v0, v1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;[Ljava/lang/String;)I

    move-result v0

    const-string v1, "type = ? AND ready_to_send = 0 AND date <= ?"

    const/16 v2, 0x64

    .line 37
    invoke-static {v2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v2

    .line 38
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    sub-long/2addr v3, v5

    invoke-static {v3, v4}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    move-result-object v3

    filled-new-array {v2, v3}, [Ljava/lang/String;

    move-result-object v2

    .line 39
    invoke-virtual {p0, v1, v2}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;[Ljava/lang/String;)I

    move-result p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    add-int/2addr v0, p0

    return v0

    :catch_0
    move-exception p0

    .line 40
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/e;->f:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/Object;

    const-string v3, "Unable to purge old debug/telemetry data."

    invoke-static {v0, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1
.end method

.method public a(Lcom/salesforce/marketingcloud/analytics/stats/b;Lcom/salesforce/marketingcloud/util/Crypto;)V
    .locals 1

    .line 10
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/storage/db/e;->b(Lcom/salesforce/marketingcloud/analytics/stats/b;Lcom/salesforce/marketingcloud/util/Crypto;)Landroid/content/ContentValues;

    move-result-object p2

    .line 11
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/analytics/stats/b;->b()Ljava/lang/Integer;

    move-result-object v0

    if-eqz v0, :cond_1

    .line 12
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/analytics/stats/b;->b()Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Integer;->toString()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    const-string v0, "id = ?"

    invoke-virtual {p0, p2, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    move-result p1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    return-void

    .line 13
    :cond_1
    :goto_0
    invoke-virtual {p0, p2}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;)J

    return-void
.end method

.method public c([Ljava/lang/String;)V
    .locals 3

    .line 3
    array-length v0, p1

    if-lez v0, :cond_0

    .line 4
    :try_start_0
    invoke-static {p1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/storage/db/b;->c(Ljava/util/Collection;)I

    move-result v0

    .line 5
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/e;->f:Ljava/lang/String;

    const-string v2, "Deleted %d items of %d items"

    array-length p1, p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    filled-new-array {p1, v0}, [Ljava/lang/Object;

    move-result-object p1

    invoke-static {v1, v2, p1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    .line 6
    :catch_0
    sget-object p1, Lcom/salesforce/marketingcloud/storage/db/e;->f:Ljava/lang/String;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/e;->o()Ljava/lang/String;

    move-result-object p0

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string v0, "Unable to clean up %s table."

    invoke-static {p1, v0, p0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public d([Ljava/lang/String;)V
    .locals 3

    .line 6
    array-length v0, p1

    if-lez v0, :cond_0

    .line 7
    new-instance v0, Landroid/content/ContentValues;

    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    const/4 v1, 0x0

    .line 8
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "in_transit"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 9
    :try_start_0
    invoke-static {p1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    invoke-virtual {p0, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;Ljava/util/Collection;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    .line 10
    :catch_0
    sget-object p1, Lcom/salesforce/marketingcloud/storage/db/e;->f:Ljava/lang/String;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/e;->o()Ljava/lang/String;

    move-result-object p0

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string v0, "Unable to update %s table."

    invoke-static {p1, v0, p0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public f()I
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/storage/db/b;->i(Ljava/lang/String;)I

    .line 3
    .line 4
    .line 5
    move-result p0

    .line 6
    return p0
.end method

.method public i(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/stats/b;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 4
    .line 5
    const-string v1, "SELECT * FROM device_stats WHERE ready_to_send=0"

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-virtual {p0, v1, v2}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    if-eqz p0, :cond_2

    .line 13
    .line 14
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v1, :cond_1

    .line 19
    .line 20
    new-instance v1, Ljava/util/ArrayList;

    .line 21
    .line 22
    invoke-interface {p0}, Landroid/database/Cursor;->getCount()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 27
    .line 28
    .line 29
    :cond_0
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/e;->a(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/analytics/stats/b;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    invoke-interface {p0}, Landroid/database/Cursor;->moveToNext()Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-nez v0, :cond_0

    .line 41
    .line 42
    move-object v0, v1

    .line 43
    :cond_1
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 44
    .line 45
    .line 46
    :cond_2
    return-object v0
.end method

.method public j(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/stats/b;",
            ">;"
        }
    .end annotation

    .line 1
    const-string v0, "SELECT * FROM device_stats WHERE ready_to_send=1 AND in_transit=0 AND type IN(100, 101, 102, 103, 104, 106, 107, 110, 111, 112)"

    .line 2
    .line 3
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/storage/db/e;->a(Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public n(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/stats/b;",
            ">;"
        }
    .end annotation

    .line 1
    const-string v0, "SELECT * FROM device_stats WHERE ready_to_send=1 AND in_transit=0 AND type IN(105)"

    .line 2
    .line 3
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/storage/db/e;->a(Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public o()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "device_stats"

    .line 2
    .line 3
    return-object p0
.end method
