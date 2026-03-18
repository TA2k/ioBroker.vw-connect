.class public final Lcom/salesforce/marketingcloud/storage/db/upgrades/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "Range"
    }
.end annotation


# static fields
.field public static final a:Lcom/salesforce/marketingcloud/storage/db/upgrades/b;

.field private static final b:Ljava/lang/String;

.field private static c:Landroid/database/sqlite/SQLiteDatabase;

.field private static d:Lcom/salesforce/marketingcloud/util/Crypto;

.field private static e:Lcom/salesforce/marketingcloud/util/Crypto;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a:Lcom/salesforce/marketingcloud/storage/db/upgrades/b;

    .line 7
    .line 8
    const-string v0, "Version11ToVersion12"

    .line 9
    .line 10
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->b:Ljava/lang/String;

    .line 15
    .line 16
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

.method private final a(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 121
    :try_start_0
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->e:Lcom/salesforce/marketingcloud/util/Crypto;

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    .line 122
    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/lang/String;

    move-result-object p0

    if-eqz p0, :cond_1

    .line 123
    sget-object p1, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a:Lcom/salesforce/marketingcloud/storage/db/upgrades/b;

    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->d:Lcom/salesforce/marketingcloud/util/Crypto;

    if-eqz v0, :cond_0

    .line 124
    invoke-direct {p1, p0, v0}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->b(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    .line 125
    :cond_0
    const-string p0, "crypto"

    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v1

    :cond_1
    return-object v1

    .line 126
    :cond_2
    const-string p0, "legacyCrypto"

    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 127
    :catch_0
    new-instance p0, Ljava/security/GeneralSecurityException;

    const-string p1, "Failed to migrate data."

    invoke-direct {p0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method private final a(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/lang/String;
    .locals 0

    .line 128
    invoke-interface {p2, p1}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method private final a()V
    .locals 3

    .line 55
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    const/4 v0, 0x0

    const-string v1, "database"

    if-eqz p0, :cond_b

    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 56
    :try_start_0
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz p0, :cond_9

    .line 57
    const-string v2, "DELETE FROM inbox_messages;"

    invoke-virtual {p0, v2}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 58
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz p0, :cond_8

    .line 59
    const-string v2, "DELETE FROM messages;"

    invoke-virtual {p0, v2}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 60
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz p0, :cond_7

    .line 61
    const-string v2, "DELETE FROM registration;"

    invoke-virtual {p0, v2}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 62
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz p0, :cond_6

    .line 63
    const-string v2, "DELETE FROM device_stats;"

    invoke-virtual {p0, v2}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 64
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz p0, :cond_5

    .line 65
    const-string v2, "DELETE FROM in_app_messages;"

    invoke-virtual {p0, v2}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 66
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz p0, :cond_4

    .line 67
    const-string v2, "DELETE FROM analytic_item;"

    invoke-virtual {p0, v2}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 68
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz p0, :cond_3

    .line 69
    const-string v2, "DELETE FROM regions;"

    invoke-virtual {p0, v2}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 70
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz p0, :cond_2

    .line 71
    const-string v2, "DELETE FROM location_table;"

    invoke-virtual {p0, v2}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 72
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz p0, :cond_1

    .line 73
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 74
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz p0, :cond_0

    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    return-void

    :cond_0
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v0

    :catchall_0
    move-exception p0

    goto :goto_0

    .line 75
    :cond_1
    :try_start_1
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v0

    .line 76
    :cond_2
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v0

    .line 77
    :cond_3
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v0

    .line 78
    :cond_4
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v0

    .line 79
    :cond_5
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v0

    .line 80
    :cond_6
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v0

    .line 81
    :cond_7
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v0

    .line 82
    :cond_8
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v0

    .line 83
    :cond_9
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 84
    :goto_0
    sget-object v2, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-nez v2, :cond_a

    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v0

    :cond_a
    invoke-virtual {v2}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    throw p0

    .line 85
    :cond_b
    invoke-static {v1}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v0
.end method

.method public static final a(Landroid/database/sqlite/SQLiteDatabase;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/util/Crypto;)V
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    const-string v2, "longitude"

    const-string v3, "latitude"

    const-string v4, "message_json"

    const-string v5, "database"

    const-string v6, "db"

    invoke-static {v0, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v6, "crypto"

    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    sget-object v7, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v8, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->b:Ljava/lang/String;

    sget-object v10, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$h;->b:Lcom/salesforce/marketingcloud/storage/db/upgrades/b$h;

    const/4 v11, 0x2

    const/4 v12, 0x0

    const/4 v9, 0x0

    invoke-static/range {v7 .. v12}, Lcom/salesforce/marketingcloud/g;->c(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 2
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-nez p2, :cond_0

    .line 3
    sget-object v10, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$i;->b:Lcom/salesforce/marketingcloud/storage/db/upgrades/b$i;

    const/4 v11, 0x2

    const/4 v12, 0x0

    const/4 v9, 0x0

    invoke-static/range {v7 .. v12}, Lcom/salesforce/marketingcloud/g;->b(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 4
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a:Lcom/salesforce/marketingcloud/storage/db/upgrades/b;

    invoke-direct {v0}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a()V

    return-void

    .line 5
    :cond_0
    sput-object v1, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->d:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 6
    sput-object p2, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->e:Lcom/salesforce/marketingcloud/util/Crypto;

    const/4 v1, 0x0

    .line 7
    :try_start_0
    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 8
    sget-object v6, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a:Lcom/salesforce/marketingcloud/storage/db/upgrades/b;

    .line 9
    const-string v7, "inbox_messages"

    .line 10
    const-string v8, "SELECT * FROM inbox_messages;"

    .line 11
    invoke-static {v4}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v10

    const/4 v11, 0x4

    const/4 v12, 0x0

    const/4 v9, 0x0

    .line 12
    invoke-static/range {v6 .. v12}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a(Lcom/salesforce/marketingcloud/storage/db/upgrades/b;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/util/Set;ILjava/lang/Object;)V

    .line 13
    const-string v7, "messages"

    .line 14
    const-string v8, "SELECT * FROM messages;"

    .line 15
    const-string v9, "title"

    const-string v10, "alert"

    const-string v11, "mediaUrl"

    const-string v12, "mediaAlt"

    const-string v13, "url"

    const-string v14, "custom"

    const-string v15, "open_direct"

    const-string v16, "keys"

    filled-new-array/range {v9 .. v16}, [Ljava/lang/String;

    move-result-object v0

    .line 16
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v10

    const/4 v11, 0x4

    const/4 v12, 0x0

    const/4 v9, 0x0

    .line 17
    invoke-static/range {v6 .. v12}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a(Lcom/salesforce/marketingcloud/storage/db/upgrades/b;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/util/Set;ILjava/lang/Object;)V

    .line 18
    const-string v7, "registration"

    .line 19
    const-string v8, "SELECT * FROM registration;"

    .line 20
    const-string v9, "subscriber_key"

    const-string v10, "signed_string"

    const-string v11, "et_app_id"

    const-string v12, "system_token"

    const-string v13, "tags"

    const-string v14, "attributes"

    filled-new-array/range {v9 .. v14}, [Ljava/lang/String;

    move-result-object v0

    .line 21
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v10

    const/4 v11, 0x4

    const/4 v12, 0x0

    const/4 v9, 0x0

    .line 22
    invoke-static/range {v6 .. v12}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a(Lcom/salesforce/marketingcloud/storage/db/upgrades/b;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/util/Set;ILjava/lang/Object;)V

    .line 23
    const-string v7, "device_stats"

    .line 24
    const-string v8, "SELECT * FROM device_stats;"

    .line 25
    const-string v0, "event_data"

    invoke-static {v0}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v10

    const/4 v11, 0x4

    const/4 v12, 0x0

    const/4 v9, 0x0

    .line 26
    invoke-static/range {v6 .. v12}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a(Lcom/salesforce/marketingcloud/storage/db/upgrades/b;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/util/Set;ILjava/lang/Object;)V

    .line 27
    const-string v7, "in_app_messages"

    .line 28
    const-string v8, "SELECT * FROM in_app_messages;"

    .line 29
    const-string v0, "media_url"

    filled-new-array {v0, v4}, [Ljava/lang/String;

    move-result-object v0

    .line 30
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v10

    const/4 v11, 0x4

    const/4 v12, 0x0

    const/4 v9, 0x0

    .line 31
    invoke-static/range {v6 .. v12}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a(Lcom/salesforce/marketingcloud/storage/db/upgrades/b;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/util/Set;ILjava/lang/Object;)V

    .line 32
    const-string v7, "analytic_item"

    .line 33
    const-string v8, "SELECT * FROM analytic_item;"

    .line 34
    const-string v0, "enc_json_et_payload"

    const-string v4, "predictive_intelligence_identifier"

    const-string v9, "enc_json_pi_payload"

    filled-new-array {v0, v4, v9}, [Ljava/lang/String;

    move-result-object v0

    .line 35
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v10

    const/4 v11, 0x4

    const/4 v12, 0x0

    const/4 v9, 0x0

    .line 36
    invoke-static/range {v6 .. v12}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a(Lcom/salesforce/marketingcloud/storage/db/upgrades/b;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/util/Set;ILjava/lang/Object;)V

    .line 37
    const-string v7, "regions"

    .line 38
    const-string v8, "SELECT * FROM regions;"

    .line 39
    const-string v0, "beacon_guid"

    const-string v4, "description"

    const-string v9, "name"

    filled-new-array {v3, v2, v0, v4, v9}, [Ljava/lang/String;

    move-result-object v0

    .line 40
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v10

    const/4 v11, 0x4

    const/4 v12, 0x0

    const/4 v9, 0x0

    .line 41
    invoke-static/range {v6 .. v12}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a(Lcom/salesforce/marketingcloud/storage/db/upgrades/b;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/util/Set;ILjava/lang/Object;)V

    .line 42
    const-string v7, "location_table"

    .line 43
    const-string v8, "SELECT * FROM location_table;"

    .line 44
    filled-new-array {v3, v2}, [Ljava/lang/String;

    move-result-object v0

    .line 45
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    move-result-object v10

    const/4 v11, 0x4

    const/4 v12, 0x0

    const/4 v9, 0x0

    .line 46
    invoke-static/range {v6 .. v12}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a(Lcom/salesforce/marketingcloud/storage/db/upgrades/b;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/util/Set;ILjava/lang/Object;)V

    .line 47
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz v0, :cond_1

    .line 48
    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 49
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz v0, :cond_2

    goto :goto_1

    :catchall_0
    move-exception v0

    goto :goto_2

    :catch_0
    move-exception v0

    goto :goto_0

    .line 50
    :cond_1
    :try_start_1
    invoke-static {v5}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v1
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 51
    :goto_0
    :try_start_2
    sget-object v2, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v3, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->b:Ljava/lang/String;

    new-instance v4, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$j;

    invoke-direct {v4, v0}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$j;-><init>(Ljava/lang/Exception;)V

    invoke-virtual {v2, v3, v0, v4}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 52
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz v0, :cond_2

    .line 53
    :goto_1
    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    return-void

    :cond_2
    invoke-static {v5}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v1

    .line 54
    :goto_2
    sget-object v2, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-nez v2, :cond_3

    invoke-static {v5}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v1

    :cond_3
    invoke-virtual {v2}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    throw v0
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/storage/db/upgrades/b;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/util/Set;ILjava/lang/Object;)V
    .locals 0

    and-int/lit8 p5, p5, 0x4

    if-eqz p5, :cond_0

    const/4 p3, 0x0

    .line 86
    :cond_0
    invoke-direct {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/util/Set;)V

    return-void
.end method

.method private final a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/util/Set;)V
    .locals 10
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "[",
            "Ljava/lang/String;",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    const-string p0, "id"

    const-string v1, "id=?"

    const-string v2, "database"

    const/4 v3, 0x0

    .line 87
    :try_start_0
    sget-object v4, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v5, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->b:Ljava/lang/String;

    new-instance v7, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$a;

    invoke-direct {v7, p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$a;-><init>(Ljava/lang/String;)V

    const/4 v8, 0x2

    const/4 v9, 0x0

    const/4 v6, 0x0

    invoke-static/range {v4 .. v9}, Lcom/salesforce/marketingcloud/g;->d(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 88
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz v0, :cond_8

    .line 89
    invoke-virtual {v0, p2, p3}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p2
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    move-object p3, v3

    .line 90
    :goto_0
    :try_start_1
    invoke-interface {p2}, Landroid/database/Cursor;->moveToNext()Z

    move-result v0

    if-eqz v0, :cond_7

    if-nez p3, :cond_0

    .line 91
    sget-object p3, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a:Lcom/salesforce/marketingcloud/storage/db/upgrades/b;

    invoke-direct {p3, p4}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a(Ljava/util/Set;)Z

    move-result p3

    invoke-static {p3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p3

    goto :goto_1

    :catchall_0
    move-exception v0

    move-object p0, v0

    goto/16 :goto_6

    .line 92
    :cond_0
    :goto_1
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_6

    .line 93
    sget-object v4, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v5, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->b:Ljava/lang/String;

    new-instance v7, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$b;

    invoke-direct {v7, p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$b;-><init>(Ljava/lang/String;)V

    const/4 v8, 0x2

    const/4 v9, 0x0

    const/4 v6, 0x0

    invoke-static/range {v4 .. v9}, Lcom/salesforce/marketingcloud/g;->d(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 94
    :try_start_2
    new-instance v0, Landroid/content/ContentValues;

    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    .line 95
    invoke-interface {p4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/String;

    .line 96
    invoke-static {p2, v5}, Lcom/salesforce/marketingcloud/storage/db/d;->b(Landroid/database/Cursor;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    if-eqz v6, :cond_2

    const/4 v7, 0x0

    .line 97
    :goto_3
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    move-result v8

    if-ge v7, v8, :cond_2

    invoke-virtual {v6, v7}, Ljava/lang/String;->charAt(I)C

    move-result v8

    .line 98
    invoke-static {v8}, Ljava/lang/Character;->isWhitespace(C)Z

    move-result v9

    if-nez v9, :cond_1

    const/16 v9, 0xa0

    if-eq v8, v9, :cond_1

    const/16 v9, 0x2007

    if-eq v8, v9, :cond_1

    const/16 v9, 0x202f

    if-eq v8, v9, :cond_1

    .line 99
    sget-object v7, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a:Lcom/salesforce/marketingcloud/storage/db/upgrades/b;

    invoke-direct {v7, v6}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v6

    goto :goto_4

    :catch_0
    move-exception v0

    goto :goto_5

    :cond_1
    add-int/lit8 v7, v7, 0x1

    goto :goto_3

    :cond_2
    move-object v6, v3

    .line 100
    :goto_4
    invoke-virtual {v0, v5, v6}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_2

    .line 101
    :cond_3
    sget-object v4, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz v4, :cond_4

    .line 102
    invoke-static {p2, p0}, Lcom/salesforce/marketingcloud/storage/db/d;->b(Landroid/database/Cursor;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    filled-new-array {v5}, [Ljava/lang/String;

    move-result-object v5

    .line 103
    invoke-virtual {v4, p1, v0, v1, v5}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    goto/16 :goto_0

    .line 104
    :cond_4
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v3
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 105
    :goto_5
    :try_start_3
    sget-object v4, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v5, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->b:Ljava/lang/String;

    new-instance v6, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$c;

    invoke-direct {v6, p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$c;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v5, v0, v6}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 106
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz v0, :cond_5

    .line 107
    invoke-static {p2, p0}, Lcom/salesforce/marketingcloud/storage/db/d;->b(Landroid/database/Cursor;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    filled-new-array {v4}, [Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v0, p1, v1, v4}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I

    goto/16 :goto_0

    .line 108
    :cond_5
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v3

    .line 109
    :cond_6
    sget-object v4, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v5, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->b:Ljava/lang/String;

    new-instance v7, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$d;

    invoke-direct {v7, p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$d;-><init>(Ljava/lang/String;)V

    const/4 v8, 0x2

    const/4 v9, 0x0

    const/4 v6, 0x0

    invoke-static/range {v4 .. v9}, Lcom/salesforce/marketingcloud/g;->d(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    goto/16 :goto_0

    .line 110
    :cond_7
    :try_start_4
    invoke-interface {p2}, Ljava/io/Closeable;->close()V

    .line 111
    sget-object v4, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v5, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->b:Ljava/lang/String;

    new-instance v7, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$e;

    invoke-direct {v7, p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$e;-><init>(Ljava/lang/String;)V

    const/4 v8, 0x2

    const/4 v9, 0x0

    const/4 v6, 0x0

    invoke-static/range {v4 .. v9}, Lcom/salesforce/marketingcloud/g;->d(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_1

    goto :goto_8

    :catch_1
    move-exception v0

    move-object p0, v0

    goto :goto_7

    .line 112
    :goto_6
    :try_start_5
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    :catchall_1
    move-exception v0

    move-object p3, v0

    :try_start_6
    invoke-static {p2, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw p3

    .line 113
    :cond_8
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v3
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_1

    .line 114
    :goto_7
    sget-object v4, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    sget-object v5, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->b:Ljava/lang/String;

    new-instance p2, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$f;

    invoke-direct {p2, p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$f;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v5, p0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 115
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    if-eqz p0, :cond_9

    new-instance p2, Ljava/lang/StringBuilder;

    const-string p3, "DELETE FROM "

    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p3, ";"

    invoke-virtual {p2, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p0, p2}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 116
    new-instance v7, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$g;

    invoke-direct {v7, p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b$g;-><init>(Ljava/lang/String;)V

    const/4 v8, 0x2

    const/4 v9, 0x0

    const/4 v6, 0x0

    invoke-static/range {v4 .. v9}, Lcom/salesforce/marketingcloud/g;->d(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    :goto_8
    return-void

    .line 117
    :cond_9
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    throw v3
.end method

.method private final a(Ljava/util/Set;)Z
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;)Z"
        }
    .end annotation

    .line 118
    :try_start_0
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->d:Lcom/salesforce/marketingcloud/util/Crypto;

    if-eqz p0, :cond_1

    .line 119
    invoke-static {p1}, Lmx0/q;->I(Ljava/lang/Iterable;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/String;

    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-nez p0, :cond_0

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    return p0

    .line 120
    :cond_1
    const-string p0, "crypto"

    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    const/4 p0, 0x0

    throw p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :catch_0
    :goto_0
    const/4 p0, 0x1

    return p0
.end method

.method private final b(Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-interface {p2, p1}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
