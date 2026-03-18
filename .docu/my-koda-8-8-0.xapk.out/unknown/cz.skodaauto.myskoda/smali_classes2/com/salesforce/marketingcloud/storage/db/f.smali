.class public Lcom/salesforce/marketingcloud/storage/db/f;
.super Lcom/salesforce/marketingcloud/storage/db/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/storage/e;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness",
        "Range"
    }
.end annotation


# static fields
.field public static final e:Ljava/lang/String; = "in_app_messages"

.field public static final f:Ljava/lang/String; = "iam_state"

.field public static final g:Ljava/lang/String; = "iam_view"

.field public static final h:Ljava/lang/String; = "iam_state_init"

.field private static final i:Ljava/lang/String;

.field private static final j:Ljava/lang/String; = "id IN (%s) AND (display_count < display_limit) AND (start_date IS NULL OR start_date < ?) AND (end_date IS NULL OR end_date > ?) ORDER BY   priority ASC,  modified_date DESC LIMIT 1"


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "InAppMessageDbStorage"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/f;->i:Ljava/lang/String;

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

.method private static a(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/lang/String;
    .locals 2

    .line 2
    :try_start_0
    const-string v0, "media_url"

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v0

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object p0

    invoke-interface {p1, p0}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p0

    .line 3
    sget-object p1, Lcom/salesforce/marketingcloud/storage/db/f;->i:Ljava/lang/String;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Unable to retrieve media_url from db cursor"

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p0, 0x0

    return-object p0
.end method

.method private static a(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "CREATE TABLE iam_state(id TEXT PRIMARY KEY, display_count integer default 0, FOREIGN KEY (id) REFERENCES in_app_messages(id) ON DELETE CASCADE);"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method private static b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/util/Crypto;)Landroid/content/ContentValues;
    .locals 5

    .line 2
    new-instance v0, Landroid/content/ContentValues;

    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object v1

    const-string v2, "id"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->priority()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "priority"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->startDateUtc()Ljava/util/Date;

    move-result-object v1

    const/4 v2, 0x0

    if-eqz v1, :cond_0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->startDateUtc()Ljava/util/Date;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/Date;->getTime()J

    move-result-wide v3

    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    goto :goto_0

    :cond_0
    move-object v1, v2

    :goto_0
    const-string v3, "start_date"

    invoke-virtual {v0, v3, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 6
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->endDateUtc()Ljava/util/Date;

    move-result-object v1

    if-eqz v1, :cond_1

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->endDateUtc()Ljava/util/Date;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/Date;->getTime()J

    move-result-wide v1

    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v2

    :cond_1
    const-string v1, "end_date"

    invoke-virtual {v0, v1, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->modifiedDateUtc()Ljava/util/Date;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/Date;->getTime()J

    move-result-wide v1

    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    const-string v2, "modified_date"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Long;)V

    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimit()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "display_limit"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 9
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->media()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;

    move-result-object v1

    if-eqz v1, :cond_2

    .line 10
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->url()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_2

    .line 11
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Media;->url()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "media_url"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 12
    :cond_2
    invoke-static {p0}, Lcom/salesforce/marketingcloud/internal/c;->b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Lorg/json/JSONObject;

    move-result-object p0

    invoke-virtual {p0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-interface {p1, p0}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    const-string p1, "message_json"

    invoke-virtual {v0, p1, p0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    return-object v0
.end method

.method private static b(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;
    .locals 3

    .line 13
    :try_start_0
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    new-instance v1, Lorg/json/JSONObject;

    const-string v2, "message_json"

    .line 14
    invoke-interface {p0, v2}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v2

    invoke-interface {p0, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object p0

    invoke-interface {p1, p0}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-direct {v1, p0}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;-><init>(Lorg/json/JSONObject;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception p0

    .line 15
    sget-object p1, Lcom/salesforce/marketingcloud/storage/db/f;->i:Ljava/lang/String;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Unable to retrieve InAppMessage from db cursor"

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p0, 0x0

    return-object p0
.end method

.method private static b(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "CREATE TRIGGER iam_state_init AFTER INSERT ON in_app_messages BEGIN INSERT INTO iam_state (id) VALUES (NEW.id); END;"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method private static c(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "CREATE VIEW iam_view AS SELECT in_app_messages.id,in_app_messages.priority,in_app_messages.start_date,in_app_messages.end_date,in_app_messages.modified_date,in_app_messages.display_limit,in_app_messages.message_json,iam_state.display_count FROM in_app_messages INNER JOIN iam_state ON iam_state.id = in_app_messages.id;"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method private static d(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "CREATE TABLE in_app_messages(id TEXT PRIMARY KEY, priority INTEGER DEFAULT 999, start_date INTEGER DEFAULT NULL, end_date INTEGER DEFAULT NULL, modified_date INTEGER DEFAULT NULL, display_limit INTEGER DEFAULT 1, media_url TEXT DEFAULT NULL, message_json TEXT);"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method public static e(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->h(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->f(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 5
    .line 6
    .line 7
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->g(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 8
    .line 9
    .line 10
    const-string v0, "DROP TRIGGER IF EXISTS iam_state_init"

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method private static f(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "DROP TABLE IF EXISTS iam_state"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private static g(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "DROP VIEW IF EXISTS iam_view"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private static h(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "DROP TABLE IF EXISTS in_app_messages"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static i(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->d(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 5
    .line 6
    .line 7
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 8
    .line 9
    .line 10
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->c(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method private static j(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 3

    .line 1
    :try_start_0
    const-string v0, "SELECT id,display_count FROM iam_state"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return p0

    .line 8
    :catch_0
    move-exception p0

    .line 9
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/f;->i:Ljava/lang/String;

    .line 10
    .line 11
    const-string v1, "iam_state"

    .line 12
    .line 13
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const-string v2, "%s is invalid"

    .line 18
    .line 19
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    return p0
.end method

.method private static k(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 3

    .line 1
    :try_start_0
    const-string v0, "SELECT id,priority,start_date,end_date,modified_date,display_limit,media_url,message_json FROM in_app_messages"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return p0

    .line 8
    :catch_0
    move-exception p0

    .line 9
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/f;->i:Ljava/lang/String;

    .line 10
    .line 11
    const-string v1, "in_app_messages"

    .line 12
    .line 13
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const-string v2, "%s is invalid"

    .line 18
    .line 19
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    return p0
.end method

.method private static l(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 3

    .line 1
    :try_start_0
    const-string v0, "SELECT id,priority,start_date,end_date,modified_date,display_limit,message_json,display_count FROM iam_view"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return p0

    .line 8
    :catch_0
    move-exception p0

    .line 9
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/f;->i:Ljava/lang/String;

    .line 10
    .line 11
    const-string v1, "iam_view"

    .line 12
    .line 13
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    const-string v2, "%s is invalid"

    .line 18
    .line 19
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    return p0
.end method

.method public static m(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 8

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->k(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const-string v1, "Unable to recover %s"

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 11
    .line 12
    .line 13
    :try_start_0
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->h(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 14
    .line 15
    .line 16
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->d(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    .line 21
    .line 22
    goto :goto_0

    .line 23
    :catchall_0
    move-exception v0

    .line 24
    goto :goto_1

    .line 25
    :catch_0
    move-exception v0

    .line 26
    :try_start_1
    sget-object v3, Lcom/salesforce/marketingcloud/storage/db/f;->i:Ljava/lang/String;

    .line 27
    .line 28
    const-string v4, "in_app_messages"

    .line 29
    .line 30
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    invoke-static {v3, v0, v1, v4}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 35
    .line 36
    .line 37
    :goto_0
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 38
    .line 39
    .line 40
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->k(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-eqz v0, :cond_0

    .line 45
    .line 46
    return v2

    .line 47
    :goto_1
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 48
    .line 49
    .line 50
    throw v0

    .line 51
    :cond_0
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->j(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    const/4 v3, 0x1

    .line 56
    if-eqz v0, :cond_2

    .line 57
    .line 58
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 59
    .line 60
    .line 61
    :try_start_2
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->f(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 62
    .line 63
    .line 64
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 68
    .line 69
    .line 70
    goto :goto_2

    .line 71
    :catchall_1
    move-exception v0

    .line 72
    goto :goto_3

    .line 73
    :catch_1
    move-exception v0

    .line 74
    :try_start_3
    sget-object v4, Lcom/salesforce/marketingcloud/storage/db/f;->i:Ljava/lang/String;

    .line 75
    .line 76
    const-string v5, "iam_state"

    .line 77
    .line 78
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v5

    .line 82
    invoke-static {v4, v0, v1, v5}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 83
    .line 84
    .line 85
    :goto_2
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 86
    .line 87
    .line 88
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->j(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-eqz v0, :cond_1

    .line 93
    .line 94
    return v2

    .line 95
    :cond_1
    move v0, v3

    .line 96
    goto :goto_4

    .line 97
    :goto_3
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 98
    .line 99
    .line 100
    throw v0

    .line 101
    :cond_2
    move v0, v2

    .line 102
    :goto_4
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->l(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 103
    .line 104
    .line 105
    move-result v4

    .line 106
    if-eqz v4, :cond_3

    .line 107
    .line 108
    :try_start_4
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->g(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 109
    .line 110
    .line 111
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->c(Landroid/database/sqlite/SQLiteDatabase;)V
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_2

    .line 112
    .line 113
    .line 114
    goto :goto_5

    .line 115
    :catch_2
    move-exception v4

    .line 116
    sget-object v5, Lcom/salesforce/marketingcloud/storage/db/f;->i:Ljava/lang/String;

    .line 117
    .line 118
    const-string v6, "iam_view"

    .line 119
    .line 120
    filled-new-array {v6}, [Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v6

    .line 124
    invoke-static {v5, v4, v1, v6}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    :goto_5
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->l(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 128
    .line 129
    .line 130
    move-result v4

    .line 131
    if-eqz v4, :cond_3

    .line 132
    .line 133
    return v2

    .line 134
    :cond_3
    const-string v4, "trigger"

    .line 135
    .line 136
    const-string v5, "iam_state_init"

    .line 137
    .line 138
    invoke-static {p0, v4, v5}, Lcom/salesforce/marketingcloud/storage/db/c;->a(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;)Z

    .line 139
    .line 140
    .line 141
    move-result v6

    .line 142
    if-eqz v6, :cond_5

    .line 143
    .line 144
    :try_start_5
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/f;->b(Landroid/database/sqlite/SQLiteDatabase;)V
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_3

    .line 145
    .line 146
    .line 147
    goto :goto_6

    .line 148
    :catch_3
    move-exception v0

    .line 149
    sget-object v6, Lcom/salesforce/marketingcloud/storage/db/f;->i:Ljava/lang/String;

    .line 150
    .line 151
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v7

    .line 155
    invoke-static {v6, v0, v1, v7}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    :goto_6
    invoke-static {p0, v4, v5}, Lcom/salesforce/marketingcloud/storage/db/c;->a(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;)Z

    .line 159
    .line 160
    .line 161
    move-result v0

    .line 162
    if-eqz v0, :cond_4

    .line 163
    .line 164
    return v2

    .line 165
    :cond_4
    move v0, v3

    .line 166
    :cond_5
    if-eqz v0, :cond_6

    .line 167
    .line 168
    :try_start_6
    const-string v0, "INSERT OR IGNORE INTO iam_state(id) SELECT id FROM in_app_messages;"

    .line 169
    .line 170
    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_4

    .line 171
    .line 172
    .line 173
    goto :goto_7

    .line 174
    :catch_4
    move-exception p0

    .line 175
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/f;->i:Ljava/lang/String;

    .line 176
    .line 177
    new-array v1, v2, [Ljava/lang/Object;

    .line 178
    .line 179
    const-string v2, "Unable to correct relationship between iam data and iam state."

    .line 180
    .line 181
    invoke-static {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    :cond_6
    :goto_7
    return v3
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/util/Crypto;)I
    .locals 3

    .line 4
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/storage/db/f;->b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/util/Crypto;)Landroid/content/ContentValues;

    move-result-object p2

    .line 5
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    const-string v1, "id = ?"

    const-string v2, "in_app_messages"

    invoke-virtual {v0, v2, p2, v1, p1}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    move-result p1

    if-eqz p1, :cond_0

    const/4 p0, 0x2

    return p0

    .line 6
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    const/4 p1, 0x0

    invoke-virtual {p0, v2, p1, p2}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J

    const/4 p0, 0x1

    return p0
.end method

.method public a(Ljava/util/Collection;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)I"
        }
    .end annotation

    .line 11
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v0

    const-string v1, "in_app_messages"

    if-nez v0, :cond_0

    .line 12
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    const/4 p1, 0x0

    invoke-virtual {p0, v1, p1, p1}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I

    move-result p0

    return p0

    .line 13
    :cond_0
    :try_start_0
    invoke-virtual {p0, v1, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;Ljava/util/Collection;)I

    move-result p0
    :try_end_0
    .catch Landroid/database/SQLException; {:try_start_0 .. :try_end_0} :catch_0

    return p0

    .line 14
    :catch_0
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/f;->i:Ljava/lang/String;

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v0, "Unable to clean up %s table."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p0, 0x0

    return p0
.end method

.method public a(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;
    .locals 3

    .line 7
    const-string v0, "message_json"

    filled-new-array {v0}, [Ljava/lang/String;

    move-result-object v0

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    const-string v1, "in_app_messages"

    const-string v2, "id = ?"

    invoke-virtual {p0, v1, v0, v2, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    const/4 p1, 0x0

    if-eqz p0, :cond_1

    .line 8
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 9
    invoke-static {p0, p2}, Lcom/salesforce/marketingcloud/storage/db/f;->b(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    move-result-object p1

    .line 10
    :cond_0
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    :cond_1
    return-object p1
.end method

.method public a(Ljava/util/Collection;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;"
        }
    .end annotation

    .line 15
    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v0

    const/4 v1, 0x0

    if-lez v0, :cond_2

    .line 16
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 17
    const-string v0, "iam_view"

    invoke-virtual {p0, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->b(Ljava/lang/String;Ljava/util/Collection;)V

    .line 18
    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object p1

    const-string v2, "SELECT %1$s.id FROM %1$s LEFT JOIN tmp_%1$s ON %1$s.id = tmp_%1$s.id WHERE tmp_%1$s.id IS NOT NULL"

    invoke-static {v2, p1}, Lcom/salesforce/marketingcloud/storage/db/c;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v2, "id IN (%s) AND (display_count < display_limit) AND (start_date IS NULL OR start_date < ?) AND (end_date IS NULL OR end_date > ?) ORDER BY   priority ASC,  modified_date DESC LIMIT 1"

    invoke-static {v2, p1}, Lcom/salesforce/marketingcloud/storage/db/c;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    .line 19
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v2

    invoke-static {v2, v3}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    move-result-object v2

    .line 20
    const-string v3, "message_json"

    filled-new-array {v3}, [Ljava/lang/String;

    move-result-object v3

    filled-new-array {v2, v2}, [Ljava/lang/String;

    move-result-object v2

    .line 21
    invoke-virtual {p0, v0, v3, p1, v2}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p1

    if-eqz p1, :cond_1

    .line 22
    invoke-interface {p1}, Landroid/database/Cursor;->moveToFirst()Z

    move-result v2

    if-eqz v2, :cond_0

    .line 23
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/storage/db/f;->b(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    move-result-object v1

    .line 24
    :cond_0
    invoke-interface {p1}, Landroid/database/Cursor;->close()V

    .line 25
    :cond_1
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/storage/db/b;->h(Ljava/lang/String;)V

    .line 26
    iget-object p1, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V

    .line 27
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    :cond_2
    return-object v1
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
    .locals 1

    if-eqz p1, :cond_0

    .line 28
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 29
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    .line 30
    const-string v0, "UPDATE iam_state SET display_count = display_count + 1 WHERE id = ?"

    invoke-virtual {p0, v0, p1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public b(Ljava/lang/String;I)V
    .locals 0

    if-eqz p1, :cond_0

    if-ltz p2, :cond_0

    .line 16
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 17
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p2

    filled-new-array {p2, p1}, [Ljava/lang/Object;

    move-result-object p1

    .line 18
    const-string p2, "UPDATE iam_state SET display_count = MAX(display_count, ?) WHERE id = ?"

    invoke-virtual {p0, p2, p1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public c(Lcom/salesforce/marketingcloud/util/Crypto;)Lorg/json/JSONArray;
    .locals 7

    .line 2
    new-instance v0, Lorg/json/JSONArray;

    invoke-direct {v0}, Lorg/json/JSONArray;-><init>()V

    .line 3
    const-string v1, "message_json"

    const-string v2, "display_count"

    filled-new-array {v1, v2}, [Ljava/lang/String;

    move-result-object v3

    const-string v4, "iam_view"

    const/4 v5, 0x0

    invoke-virtual {p0, v4, v3, v5, v5}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    if-eqz p0, :cond_2

    .line 4
    :try_start_0
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    move-result v3

    if-eqz v3, :cond_1

    .line 5
    invoke-interface {p0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v1

    .line 6
    invoke-interface {p0, v2}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    :cond_0
    :try_start_1
    new-instance v3, Lorg/json/JSONObject;

    invoke-interface {p0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    invoke-interface {p1, v4}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    invoke-direct {v3, v4}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 8
    const-string v4, "displayCount"

    invoke-interface {p0, v2}, Landroid/database/Cursor;->getInt(I)I

    move-result v5

    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 9
    invoke-virtual {v0, v3}, Lorg/json/JSONArray;->put(Ljava/lang/Object;)Lorg/json/JSONArray;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :catch_0
    move-exception v3

    .line 10
    :try_start_2
    sget-object v4, Lcom/salesforce/marketingcloud/storage/db/f;->i:Ljava/lang/String;

    const-string v5, "Unable to read message information from cursor."

    const/4 v6, 0x0

    new-array v6, v6, [Ljava/lang/Object;

    invoke-static {v4, v3, v5, v6}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    :goto_0
    invoke-interface {p0}, Landroid/database/Cursor;->moveToNext()Z

    move-result v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    if-nez v3, :cond_0

    .line 12
    :cond_1
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    return-object v0

    .line 13
    :goto_1
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 14
    throw p1

    :cond_2
    return-object v0
.end method

.method public d(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 2
    const-string v0, "media_url"

    filled-new-array {v0}, [Ljava/lang/String;

    move-result-object v0

    const-string v1, "in_app_messages"

    const-string v2, "media_url IS NOT NULL"

    const/4 v3, 0x0

    invoke-virtual {p0, v1, v0, v2, v3}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    .line 3
    :try_start_0
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    move-result v0

    if-eqz v0, :cond_2

    .line 4
    new-instance v3, Ljava/util/ArrayList;

    invoke-interface {p0}, Landroid/database/Cursor;->getCount()I

    move-result v0

    invoke-direct {v3, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 5
    :cond_0
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/f;->a(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_1

    .line 6
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    .line 7
    :cond_1
    :goto_0
    invoke-interface {p0}, Landroid/database/Cursor;->moveToNext()Z

    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-nez v0, :cond_0

    .line 8
    :cond_2
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    if-eqz v3, :cond_3

    return-object v3

    .line 9
    :cond_3
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    return-object p0

    .line 10
    :goto_1
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 11
    throw p1
.end method

.method public o()Ljava/lang/String;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method
