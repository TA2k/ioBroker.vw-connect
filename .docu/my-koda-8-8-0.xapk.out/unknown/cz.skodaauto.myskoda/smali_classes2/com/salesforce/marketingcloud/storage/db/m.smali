.class public Lcom/salesforce/marketingcloud/storage/db/m;
.super Lcom/salesforce/marketingcloud/storage/db/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/storage/m;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness",
        "Range"
    }
.end annotation


# static fields
.field public static final g:Ljava/lang/String; = "triggers"

.field private static final h:Ljava/lang/String;


# instance fields
.field private final e:Landroid/database/sqlite/SQLiteStatement;

.field private final f:Landroid/database/sqlite/SQLiteStatement;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "TriggerDbStorage"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/m;->h:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;-><init>(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 2
    .line 3
    .line 4
    const-string v0, "UPDATE triggers SET app_open_count = app_open_count + 1 WHERE (start_date IS NULL OR start_date < ?)"

    .line 5
    .line 6
    invoke-virtual {p1, v0}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/m;->e:Landroid/database/sqlite/SQLiteStatement;

    .line 11
    .line 12
    const-string v0, "SELECT app_open_count FROM triggers WHERE id = ?"

    .line 13
    .line 14
    invoke-virtual {p1, v0}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iput-object p1, p0, Lcom/salesforce/marketingcloud/storage/db/m;->f:Landroid/database/sqlite/SQLiteStatement;

    .line 19
    .line 20
    return-void
.end method

.method private static a(Landroid/database/Cursor;)Lcom/salesforce/marketingcloud/events/h;
    .locals 3

    .line 2
    :try_start_0
    new-instance v0, Lcom/salesforce/marketingcloud/events/h;

    new-instance v1, Lorg/json/JSONObject;

    const-string v2, "_trigger"

    invoke-interface {p0, v2}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v2

    invoke-interface {p0, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v1, p0}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/events/h;-><init>(Lorg/json/JSONObject;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception p0

    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/m;->h:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "Unable to read trigger from DB"

    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p0, 0x0

    return-object p0
.end method

.method public static a(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "DROP TABLE IF EXISTS triggers"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method public static b(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "CREATE TABLE triggers(id TEXT PRIMARY KEY, _key TEXT, start_date INTEGER DEFAULT NULL, _trigger TEXT, app_open_count INTEGER DEFAULT 0);"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method private static c(Lcom/salesforce/marketingcloud/events/h;)Landroid/content/ContentValues;
    .locals 3

    .line 2
    new-instance v0, Landroid/content/ContentValues;

    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/events/h;->h()Ljava/lang/String;

    move-result-object v1

    const-string v2, "id"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/events/h;->i()Ljava/lang/String;

    move-result-object v1

    const-string v2, "_key"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/events/h;->l()Ljava/util/Date;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/events/h;->l()Ljava/util/Date;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/Date;->getTime()J

    move-result-wide v1

    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    const-string v2, "start_date"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 6
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/events/h;->m()Lorg/json/JSONObject;

    move-result-object p0

    invoke-virtual {p0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object p0

    const-string v1, "_trigger"

    invoke-virtual {v0, v1, p0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    return-object v0
.end method

.method private static c(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 1

    .line 1
    :try_start_0
    const-string v0, "SELECT id,_key,start_date,_trigger,app_open_count FROM triggers"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    const/4 p0, 0x1

    return p0

    :catch_0
    const/4 p0, 0x0

    return p0
.end method

.method public static d(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 4

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/m;->c(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    :try_start_0
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/m;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 8
    .line 9
    .line 10
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/m;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/m;->c(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 14
    .line 15
    .line 16
    move-result p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 17
    return p0

    .line 18
    :catch_0
    move-exception p0

    .line 19
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/m;->h:Ljava/lang/String;

    .line 20
    .line 21
    const-string v2, "triggers"

    .line 22
    .line 23
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    const-string v3, "Unable to recover %s"

    .line 28
    .line 29
    invoke-static {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :cond_0
    return v0
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/events/h;)V
    .locals 2

    .line 4
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/m;->c(Lcom/salesforce/marketingcloud/events/h;)Landroid/content/ContentValues;

    move-result-object v0

    .line 5
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/events/h;->h()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    const-string v1, "id = ?"

    invoke-virtual {p0, v0, v1, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    move-result p1

    if-nez p1, :cond_0

    .line 6
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;)J

    :cond_0
    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/events/h;)I
    .locals 2

    if-eqz p1, :cond_0

    .line 10
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/m;->f:Landroid/database/sqlite/SQLiteStatement;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/events/h;->h()Ljava/lang/String;

    move-result-object p1

    const/4 v1, 0x1

    invoke-virtual {v0, v1, p1}, Landroid/database/sqlite/SQLiteProgram;->bindString(ILjava/lang/String;)V

    .line 11
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/m;->f:Landroid/database/sqlite/SQLiteStatement;

    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteStatement;->simpleQueryForLong()J

    move-result-wide p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    long-to-int p0, p0

    return p0

    :catch_0
    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public b(Ljava/util/Collection;)I
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)I"
        }
    .end annotation

    .line 6
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v0

    if-nez v0, :cond_0

    const/4 p1, 0x0

    .line 7
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->i(Ljava/lang/String;)I

    move-result p0

    return p0

    .line 8
    :cond_0
    :try_start_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/m;->o()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;Ljava/util/Collection;)I

    move-result p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return p0

    .line 9
    :catch_0
    sget-object p1, Lcom/salesforce/marketingcloud/storage/db/m;->h:Ljava/lang/String;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/m;->o()Ljava/lang/String;

    move-result-object p0

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string v0, "Unable to clean up %s table."

    invoke-static {p1, v0, p0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p0, 0x0

    return p0
.end method

.method public b(Ljava/lang/String;)Lcom/salesforce/marketingcloud/events/h;
    .locals 2

    .line 2
    const-string v0, "_trigger"

    filled-new-array {v0}, [Ljava/lang/String;

    move-result-object v0

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    const-string v1, "id = ?"

    invoke-virtual {p0, v0, v1, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    const/4 p1, 0x0

    if-eqz p0, :cond_1

    .line 3
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 4
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/m;->a(Landroid/database/Cursor;)Lcom/salesforce/marketingcloud/events/h;

    move-result-object p1

    .line 5
    :cond_0
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    :cond_1
    return-object p1
.end method

.method public g(Ljava/lang/String;)Ljava/util/List;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/events/h;",
            ">;"
        }
    .end annotation

    .line 1
    const-string v0, "_trigger"

    .line 2
    .line 3
    filled-new-array {v0}, [Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    invoke-static {v1, v2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    filled-new-array {p1, v1}, [Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    const-string v1, "lower(_key) = lower(?) AND (start_date IS NULL OR start_date < ?)"

    .line 20
    .line 21
    invoke-virtual {p0, v0, v1, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    :try_start_0
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    if-eqz p1, :cond_1

    .line 30
    .line 31
    new-instance p1, Ljava/util/ArrayList;

    .line 32
    .line 33
    invoke-interface {p0}, Landroid/database/Cursor;->getCount()I

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 38
    .line 39
    .line 40
    :cond_0
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/m;->a(Landroid/database/Cursor;)Lcom/salesforce/marketingcloud/events/h;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    invoke-interface {p0}, Landroid/database/Cursor;->moveToNext()Z

    .line 48
    .line 49
    .line 50
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 51
    if-nez v0, :cond_0

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :catchall_0
    move-exception p1

    .line 55
    goto :goto_1

    .line 56
    :cond_1
    const/4 p1, 0x0

    .line 57
    :goto_0
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 58
    .line 59
    .line 60
    if-eqz p1, :cond_2

    .line 61
    .line 62
    return-object p1

    .line 63
    :cond_2
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 64
    .line 65
    return-object p0

    .line 66
    :goto_1
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 67
    .line 68
    .line 69
    throw p1
.end method

.method public k()V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/m;->e:Landroid/database/sqlite/SQLiteStatement;

    .line 2
    .line 3
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    const/4 v2, 0x1

    .line 12
    invoke-virtual {v0, v2, v1}, Landroid/database/sqlite/SQLiteProgram;->bindString(ILjava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/m;->e:Landroid/database/sqlite/SQLiteStatement;

    .line 16
    .line 17
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteStatement;->execute()V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public m()Lorg/json/JSONArray;
    .locals 7

    .line 1
    new-instance v0, Lorg/json/JSONArray;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONArray;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "_trigger"

    .line 7
    .line 8
    const-string v2, "app_open_count"

    .line 9
    .line 10
    filled-new-array {v1, v2}, [Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    const/4 v4, 0x0

    .line 15
    invoke-virtual {p0, v3, v4}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    if-eqz p0, :cond_2

    .line 20
    .line 21
    :try_start_0
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-eqz v3, :cond_1

    .line 26
    .line 27
    invoke-interface {p0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    invoke-interface {p0, v2}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 32
    .line 33
    .line 34
    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    :cond_0
    :try_start_1
    new-instance v3, Lorg/json/JSONObject;

    .line 36
    .line 37
    invoke-interface {p0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    invoke-direct {v3, v4}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    const-string v4, "appOpenCount"

    .line 45
    .line 46
    invoke-interface {p0, v2}, Landroid/database/Cursor;->getInt(I)I

    .line 47
    .line 48
    .line 49
    move-result v5

    .line 50
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v0, v3}, Lorg/json/JSONArray;->put(Ljava/lang/Object;)Lorg/json/JSONArray;
    :try_end_1
    .catch Lorg/json/JSONException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :catchall_0
    move-exception v0

    .line 58
    goto :goto_1

    .line 59
    :catch_0
    move-exception v3

    .line 60
    :try_start_2
    sget-object v4, Lcom/salesforce/marketingcloud/storage/db/m;->h:Ljava/lang/String;

    .line 61
    .line 62
    const-string v5, "Unable to read trigger information from cursor."

    .line 63
    .line 64
    const/4 v6, 0x0

    .line 65
    new-array v6, v6, [Ljava/lang/Object;

    .line 66
    .line 67
    invoke-static {v4, v3, v5, v6}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    :goto_0
    invoke-interface {p0}, Landroid/database/Cursor;->moveToNext()Z

    .line 71
    .line 72
    .line 73
    move-result v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 74
    if-nez v3, :cond_0

    .line 75
    .line 76
    :cond_1
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 77
    .line 78
    .line 79
    return-object v0

    .line 80
    :goto_1
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 81
    .line 82
    .line 83
    throw v0

    .line 84
    :cond_2
    return-object v0
.end method

.method public o()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "triggers"

    .line 2
    .line 3
    return-object p0
.end method
