.class public final Lcom/salesforce/marketingcloud/storage/db/a;
.super Lcom/salesforce/marketingcloud/storage/db/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/storage/a;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness",
        "Range"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/storage/db/a$a;
    }
.end annotation


# static fields
.field public static final e:Ljava/lang/String; = "analytic_item"

.field static final f:I = 0x3e7

.field private static final g:[Ljava/lang/String;

.field private static final h:Ljava/lang/String; = "CREATE TABLE analytic_item (id INTEGER PRIMARY KEY AUTOINCREMENT, event_date VARCHAR, analytic_product_type INTEGER, analytic_type INTEGER, value INTEGER, ready_to_send SMALLINT, object_ids VARCHAR, enc_json_pi_payload VARCHAR, enc_json_et_payload VARCHAR, predictive_intelligence_identifier VARCHAR DEFAULT NULL);"

.field private static final i:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    const-string v8, "enc_json_et_payload"

    .line 2
    .line 3
    const-string v9, "predictive_intelligence_identifier"

    .line 4
    .line 5
    const-string v0, "id"

    .line 6
    .line 7
    const-string v1, "event_date"

    .line 8
    .line 9
    const-string v2, "analytic_product_type"

    .line 10
    .line 11
    const-string v3, "analytic_type"

    .line 12
    .line 13
    const-string v4, "value"

    .line 14
    .line 15
    const-string v5, "ready_to_send"

    .line 16
    .line 17
    const-string v6, "object_ids"

    .line 18
    .line 19
    const-string v7, "enc_json_pi_payload"

    .line 20
    .line 21
    filled-new-array/range {v0 .. v9}, [Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/a;->g:[Ljava/lang/String;

    .line 26
    .line 27
    const-string v0, "AnalyticItemDbStorage"

    .line 28
    .line 29
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/a;->i:Ljava/lang/String;

    .line 34
    .line 35
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

.method private static a(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/analytics/b;
    .locals 11

    const/4 v1, 0x0

    const/4 v2, 0x0

    .line 3
    :try_start_0
    const-string v0, "analytic_type"

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v0

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getInt(I)I

    move-result v5

    .line 4
    const-string v0, "analytic_product_type"

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v0

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getInt(I)I

    move-result v0

    const/4 v9, 0x1

    if-nez v0, :cond_0

    move v4, v2

    goto :goto_0

    :cond_0
    move v4, v9

    .line 5
    :goto_0
    const-string v0, "event_date"

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v0

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/j;->d(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v3

    .line 6
    const-string v0, "ready_to_send"

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v0

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getInt(I)I

    move-result v0

    if-ne v0, v9, :cond_1

    move v8, v9

    goto :goto_1

    :cond_1
    move v8, v2

    .line 7
    :goto_1
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 8
    new-instance v6, Lorg/json/JSONArray;

    const-string v7, "object_ids"

    invoke-interface {p0, v7}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v7

    invoke-interface {p0, v7}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v7

    invoke-direct {v6, v7}, Lorg/json/JSONArray;-><init>(Ljava/lang/String;)V

    .line 9
    invoke-virtual {v6}, Lorg/json/JSONArray;->length()I

    move-result v7

    if-lez v7, :cond_2

    .line 10
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    move v7, v2

    .line 11
    :goto_2
    invoke-virtual {v6}, Lorg/json/JSONArray;->length()I

    move-result v10

    if-ge v7, v10, :cond_2

    .line 12
    invoke-virtual {v6, v7}, Lorg/json/JSONArray;->getString(I)Ljava/lang/String;

    move-result-object v10

    invoke-virtual {v0, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v7, v7, 0x1

    goto :goto_2

    :catch_0
    move-exception v0

    move-object p0, v0

    goto/16 :goto_5

    :cond_2
    move-object v6, v0

    if-eqz p1, :cond_4

    .line 13
    const-string v0, "enc_json_et_payload"

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v0

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v0

    invoke-interface {p1, v0}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 14
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v7

    if-nez v7, :cond_3

    .line 15
    new-instance v7, Lorg/json/JSONObject;

    invoke-direct {v7, v0}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 16
    const-string v10, "requestId"

    invoke-virtual {v7, v10}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v7

    goto :goto_3

    :cond_3
    move-object v7, v1

    goto :goto_3

    :cond_4
    move-object v0, v1

    move-object v7, v0

    .line 17
    :goto_3
    invoke-static {v7}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v10

    if-nez v10, :cond_5

    .line 18
    invoke-static/range {v3 .. v8}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;IILjava/util/List;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object v3

    goto :goto_4

    .line 19
    :cond_5
    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v7

    if-lez v7, :cond_6

    .line 20
    invoke-static {v3, v4, v5, v6, v8}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;IILjava/util/List;Z)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object v3

    goto :goto_4

    .line 21
    :cond_6
    invoke-static {v3, v4, v5}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;II)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object v3

    .line 22
    invoke-virtual {v3, v8}, Lcom/salesforce/marketingcloud/analytics/b;->a(Z)V

    .line 23
    :goto_4
    const-string v5, "id"

    invoke-interface {p0, v5}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v5

    invoke-interface {p0, v5}, Landroid/database/Cursor;->getInt(I)I

    move-result v5

    invoke-virtual {v3, v5}, Lcom/salesforce/marketingcloud/analytics/b;->a(I)V

    .line 24
    const-string v5, "value"

    invoke-interface {p0, v5}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v5

    invoke-interface {p0, v5}, Landroid/database/Cursor;->getInt(I)I

    move-result v5

    invoke-virtual {v3, v5}, Lcom/salesforce/marketingcloud/analytics/b;->b(I)V

    .line 25
    invoke-virtual {v3, v0}, Lcom/salesforce/marketingcloud/analytics/b;->b(Ljava/lang/String;)V

    if-ne v4, v9, :cond_7

    if-eqz p1, :cond_7

    .line 26
    const-string v0, "predictive_intelligence_identifier"

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v0

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v0

    invoke-interface {p1, v0}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v3, v0}, Lcom/salesforce/marketingcloud/analytics/b;->d(Ljava/lang/String;)V

    .line 27
    const-string v0, "enc_json_pi_payload"

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v0

    invoke-interface {p0, v0}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object p0

    .line 28
    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-nez v0, :cond_7

    .line 29
    invoke-interface {p1, p0}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v3, p0}, Lcom/salesforce/marketingcloud/analytics/b;->c(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :cond_7
    return-object v3

    .line 30
    :goto_5
    sget-object p1, Lcom/salesforce/marketingcloud/storage/db/a;->i:Ljava/lang/String;

    new-array v0, v2, [Ljava/lang/Object;

    const-string v2, "Failed to create our analytic item from storage."

    invoke-static {p1, p0, v2, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-object v1
.end method

.method public static varargs a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;
    .locals 1

    .line 2
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    invoke-static {v0, p0, p1}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method private a(III)V
    .locals 7

    add-int/lit8 p1, p1, 0x1

    sub-int/2addr p1, p2

    .line 35
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    .line 36
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    const-string v3, "analytic_product_type"

    const-string v5, "id"

    const-string v0, "id"

    const-string v1, "id"

    const-string v2, "analytic_item"

    filled-new-array/range {v0 .. v6}, [Ljava/lang/Object;

    move-result-object p1

    .line 37
    const-string p2, "%s IN ( SELECT %s FROM %s WHERE %s=%d ORDER BY %s ASC LIMIT %d )"

    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->i(Ljava/lang/String;)I

    return-void
.end method

.method public static a(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "DROP TABLE IF EXISTS analytic_item"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method private b(ILcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;"
        }
    .end annotation

    .line 20
    const-string v0, "value"

    const-string v1, "ready_to_send"

    const-string v2, "analytic_type"

    const-string v3, "analytic_product_type"

    filled-new-array {v2, v3, v0, v1}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "(%1$s=? OR %1$s=?) AND %2$s=? AND %3$s=? AND %4$s=?"

    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v4

    const/4 v0, 0x4

    .line 21
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x5

    .line 22
    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    .line 23
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    const/4 v2, 0x0

    .line 24
    invoke-static {v2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v3

    .line 25
    invoke-static {v2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v2

    filled-new-array {v0, v1, p1, v3, v2}, [Ljava/lang/String;

    move-result-object v5

    .line 26
    sget-object v3, Lcom/salesforce/marketingcloud/storage/db/a;->g:[Ljava/lang/String;

    const-string p1, "id"

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    .line 27
    const-string v0, "%s ASC"

    invoke-static {v0, p1}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v8

    const/4 v6, 0x0

    const/4 v7, 0x0

    move-object v2, p0

    invoke-virtual/range {v2 .. v8}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    .line 28
    invoke-virtual {v2, p0, p2}, Lcom/salesforce/marketingcloud/storage/db/a;->b(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public static b(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "CREATE TABLE analytic_item (id INTEGER PRIMARY KEY AUTOINCREMENT, event_date VARCHAR, analytic_product_type INTEGER, analytic_type INTEGER, value INTEGER, ready_to_send SMALLINT, object_ids VARCHAR, enc_json_pi_payload VARCHAR, enc_json_et_payload VARCHAR, predictive_intelligence_identifier VARCHAR DEFAULT NULL);"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method private static c(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/util/Crypto;)Landroid/content/ContentValues;
    .locals 7

    .line 3
    new-instance v0, Landroid/content/ContentValues;

    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->b()Ljava/util/Date;

    move-result-object v1

    invoke-static {v1}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Date;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "event_date"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->j()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "analytic_product_type"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 6
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->a()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "analytic_type"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->g()I

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "value"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->h()Z

    move-result v1

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "ready_to_send"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 9
    new-instance v1, Lorg/json/JSONArray;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->i()Ljava/util/List;

    move-result-object v2

    invoke-direct {v1, v2}, Lorg/json/JSONArray;-><init>(Ljava/util/Collection;)V

    invoke-virtual {v1}, Lorg/json/JSONArray;->toString()Ljava/lang/String;

    move-result-object v1

    const-string v2, "object_ids"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->j()I

    move-result v1

    const-string v2, "enc_json_pi_payload"

    const-string v3, "predictive_intelligence_identifier"

    const-string v4, "enc_json_et_payload"

    const/4 v5, 0x0

    if-nez v1, :cond_1

    .line 11
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->c()Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_0

    .line 12
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->c()Ljava/lang/String;

    move-result-object p0

    invoke-interface {p1, p0}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, v4, p0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 13
    :cond_0
    invoke-virtual {v0, v3, v5}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 14
    invoke-virtual {v0, v2, v5}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    return-object v0

    .line 15
    :cond_1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->j()I

    move-result v1

    const/4 v6, 0x1

    if-ne v1, v6, :cond_2

    .line 16
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->f()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v3, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 17
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->e()Ljava/lang/String;

    move-result-object p0

    invoke-interface {p1, p0}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, v2, p0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 18
    invoke-virtual {v0, v4, v5}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    :cond_2
    return-object v0
.end method

.method private static c(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 4

    const-string v0, "analytic_item"

    .line 1
    :try_start_0
    const-string v1, "SELECT %s FROM %s"

    const-string v2, ","

    sget-object v3, Lcom/salesforce/marketingcloud/storage/db/a;->g:[Ljava/lang/String;

    invoke-static {v2, v3}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    filled-new-array {v2, v0}, [Ljava/lang/Object;

    move-result-object v2

    invoke-static {v1, v2}, Lcom/salesforce/marketingcloud/storage/db/c;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, v1}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    const/4 p0, 0x1

    return p0

    :catch_0
    move-exception p0

    .line 2
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/a;->i:Ljava/lang/String;

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v2, "%s is invalid"

    invoke-static {v1, p0, v2, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p0, 0x0

    return p0
.end method

.method public static d(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 4

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/a;->c(Landroid/database/sqlite/SQLiteDatabase;)Z

    move-result v0

    if-nez v0, :cond_0

    .line 2
    :try_start_0
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 3
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/a;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 4
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/a;->c(Landroid/database/sqlite/SQLiteDatabase;)Z

    move-result p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return p0

    :catch_0
    move-exception p0

    .line 5
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/a;->i:Ljava/lang/String;

    const-string v2, "analytic_item"

    filled-new-array {v2}, [Ljava/lang/Object;

    move-result-object v2

    const-string v3, "Unable to recover %s"

    invoke-static {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    return v0
.end method

.method private h(I)I
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    const-string v0, "analytic_product_type"

    filled-new-array {v0, p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v0, "%s=%s"

    invoke-static {v0, p1}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    .line 3
    const-string v0, "analytic_item"

    invoke-static {p0, v0, p1}, Landroid/database/DatabaseUtils;->queryNumEntries(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;)J

    move-result-wide p0

    long-to-int p0, p0

    return p0
.end method


# virtual methods
.method public a()I
    .locals 8

    .line 47
    :try_start_0
    const-string v0, "analytic_product_type =? AND event_date <= ?"

    const/4 v1, 0x1

    .line 48
    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/util/Date;

    .line 49
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    sget-object v5, Ljava/util/concurrent/TimeUnit;->DAYS:Ljava/util/concurrent/TimeUnit;

    const-wide/16 v6, 0xe

    invoke-virtual {v5, v6, v7}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    move-result-wide v5

    sub-long/2addr v3, v5

    invoke-direct {v2, v3, v4}, Ljava/util/Date;-><init>(J)V

    invoke-static {v2}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Date;)Ljava/lang/String;

    move-result-object v2

    filled-new-array {v1, v2}, [Ljava/lang/String;

    move-result-object v1

    .line 50
    invoke-virtual {p0, v0, v1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;[Ljava/lang/String;)I

    move-result p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return p0

    :catch_0
    move-exception p0

    .line 51
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/a;->i:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/Object;

    const-string v3, "Unable to purge old analytic data."

    invoke-static {v0, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1
.end method

.method public a(I)I
    .locals 3

    .line 52
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/b;->C:Ljava/util/List;

    .line 53
    const-string v1, ","

    invoke-static {v1, v0}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "analytic_product_type"

    const-string v2, "analytic_type"

    filled-new-array {v1, v2, v0}, [Ljava/lang/Object;

    move-result-object v0

    .line 54
    const-string v1, "%s = ? AND %s NOT IN (%s)"

    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    .line 55
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    .line 56
    invoke-virtual {p0, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;[Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public a([Ljava/lang/String;)I
    .locals 1

    .line 46
    const-string v0, ","

    invoke-static {v0, p1}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    const-string v0, "id"

    filled-new-array {v0, p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v0, "%s IN (%s)"

    invoke-static {v0, p1}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->i(Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public a(Lcom/salesforce/marketingcloud/util/Crypto;I)Ljava/util/List;
    .locals 10
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            "I)",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;"
        }
    .end annotation

    .line 38
    const-string v0, "analytic_product_type"

    const-string v1, "ready_to_send"

    filled-new-array {v0, v1}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "%s=? AND %s=?"

    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v4

    const/4 v0, 0x1

    .line 39
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    .line 40
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v0

    filled-new-array {v1, v0}, [Ljava/lang/String;

    move-result-object v5

    .line 41
    sget-object v3, Lcom/salesforce/marketingcloud/storage/db/a;->g:[Ljava/lang/String;

    const-string v0, "event_date"

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    .line 42
    const-string v1, "%s ASC"

    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v8

    .line 43
    invoke-static {p2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v9

    const/4 v6, 0x0

    const/4 v7, 0x0

    move-object v2, p0

    .line 44
    invoke-virtual/range {v2 .. v9}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    .line 45
    invoke-virtual {v2, p0, p1}, Lcom/salesforce/marketingcloud/storage/db/a;->b(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public a(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/util/Crypto;)V
    .locals 4

    .line 31
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/analytics/b;->j()I

    move-result v0

    if-nez v0, :cond_0

    const/4 v0, 0x0

    goto :goto_0

    :cond_0
    const/4 v0, 0x1

    .line 32
    :goto_0
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->h(I)I

    move-result v1

    add-int/lit8 v2, v1, 0x1

    const/16 v3, 0x3e7

    if-le v2, v3, :cond_1

    .line 33
    invoke-direct {p0, v1, v3, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(III)V

    .line 34
    :cond_1
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/storage/db/a;->c(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/util/Crypto;)Landroid/content/ContentValues;

    move-result-object p2

    invoke-virtual {p0, p2}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;)J

    move-result-wide v0

    long-to-int p0, v0

    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/analytics/b;->a(I)V

    return-void
.end method

.method public b(I)I
    .locals 3

    .line 35
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/b;->C:Ljava/util/List;

    .line 36
    const-string v1, ","

    invoke-static {v1, v0}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "analytic_product_type"

    const-string v2, "analytic_type"

    filled-new-array {v1, v2, v0}, [Ljava/lang/Object;

    move-result-object v0

    .line 37
    const-string v1, "%s = ? AND %s IN (%s)"

    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    .line 38
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    .line 39
    invoke-virtual {p0, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;[Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public b(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/util/Crypto;)I
    .locals 2

    .line 11
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/storage/db/a;->c(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/util/Crypto;)Landroid/content/ContentValues;

    move-result-object p2

    const-string v0, "id"

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "%s = ?"

    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    .line 12
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/analytics/b;->d()I

    move-result p1

    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    .line 13
    invoke-virtual {p0, p2, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public b(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/database/Cursor;",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;"
        }
    .end annotation

    .line 2
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    if-eqz p1, :cond_4

    .line 3
    invoke-interface {p1}, Landroid/database/Cursor;->moveToFirst()Z

    move-result v1

    if-eqz v1, :cond_3

    .line 4
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 5
    :cond_0
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object v0

    if-eqz v0, :cond_1

    .line 6
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 7
    :cond_1
    const-string v0, "id"

    invoke-interface {p1, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    move-result v2

    invoke-interface {p1, v2}, Landroid/database/Cursor;->getInt(I)I

    move-result v2

    if-ltz v2, :cond_2

    .line 8
    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v3, "%s = ?"

    invoke-static {v3, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v2

    filled-new-array {v2}, [Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p0, v0, v2}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;[Ljava/lang/String;)I

    .line 9
    :cond_2
    :goto_0
    invoke-interface {p1}, Landroid/database/Cursor;->moveToNext()Z

    move-result v0

    if-nez v0, :cond_0

    move-object v0, v1

    .line 10
    :cond_3
    invoke-interface {p1}, Landroid/database/Cursor;->close()V

    :cond_4
    return-object v0
.end method

.method public b(Lcom/salesforce/marketingcloud/messages/Region;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/messages/Region;",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;"
        }
    .end annotation

    .line 29
    const-string v0, "object_ids"

    const-string v1, "ready_to_send"

    const-string v2, "analytic_type"

    filled-new-array {v2, v0, v1}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "(%1$s=? OR %1$s=?) AND %2$s LIKE ? AND %3$s=?"

    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    const/16 v1, 0xd

    .line 30
    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    const/16 v2, 0xb

    .line 31
    invoke-static {v2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v2

    .line 32
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v3, "%%%s%%"

    invoke-static {v3, p1}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    const/4 v3, 0x0

    .line 33
    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v3

    filled-new-array {v1, v2, p1, v3}, [Ljava/lang/String;

    move-result-object p1

    .line 34
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/a;->g:[Ljava/lang/String;

    invoke-virtual {p0, v1, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p1

    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/storage/db/a;->b(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public b(Lcom/salesforce/marketingcloud/util/Crypto;I)Ljava/util/List;
    .locals 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            "I)",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;"
        }
    .end annotation

    .line 14
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/a;->g:[Ljava/lang/String;

    const-string v0, "analytic_product_type"

    const-string v2, "ready_to_send"

    filled-new-array {v0, v2}, [Ljava/lang/Object;

    move-result-object v0

    .line 15
    const-string v2, "%s=? AND %s=?"

    invoke-static {v2, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    const/4 v0, 0x0

    .line 16
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v0

    const-string v3, "1"

    filled-new-array {v0, v3}, [Ljava/lang/String;

    move-result-object v3

    const-string v0, "id"

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    .line 17
    const-string v4, "%s ASC"

    invoke-static {v4, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v6

    invoke-static {p2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v7

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    .line 18
    invoke-virtual/range {v0 .. v7}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object p0

    .line 19
    invoke-virtual {v0, p0, p1}, Lcom/salesforce/marketingcloud/storage/db/a;->b(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public c(I)Z
    .locals 6

    .line 19
    const-string v0, "value"

    const-string v1, "ready_to_send"

    const-string v2, "analytic_type"

    const-string v3, "analytic_product_type"

    filled-new-array {v2, v3, v0, v1}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "(%1$s=? OR %1$s=?) AND %2$s=? AND %3$s=? AND %4$s=?"

    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x4

    .line 20
    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    const/4 v2, 0x5

    .line 21
    invoke-static {v2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v2

    .line 22
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    const/4 v3, 0x0

    .line 23
    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v4

    .line 24
    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v5

    filled-new-array {v1, v2, p1, v4, v5}, [Ljava/lang/String;

    move-result-object p1

    .line 25
    iget-object v1, p0, Lcom/salesforce/marketingcloud/storage/db/b;->c:Landroid/database/sqlite/SQLiteDatabase;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/a;->o()Ljava/lang/String;

    move-result-object p0

    invoke-static {v1, p0, v0, p1}, Landroid/database/DatabaseUtils;->queryNumEntries(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)J

    move-result-wide p0

    const-wide/16 v0, 0x0

    cmp-long p0, p0, v0

    if-lez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    return v3
.end method

.method public d()I
    .locals 1

    const/4 v0, 0x0

    .line 6
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->h(I)I

    move-result p0

    return p0
.end method

.method public e()I
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->h(I)I

    .line 3
    .line 4
    .line 5
    move-result p0

    .line 6
    return p0
.end method

.method public f(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;"
        }
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/a;->b(ILcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method

.method public g(I)I
    .locals 2

    .line 1
    const-string v0, "analytic_product_type"

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "%s = ?"

    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    .line 2
    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    .line 3
    invoke-virtual {p0, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Ljava/lang/String;[Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public g(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;"
        }
    .end annotation

    .line 4
    const-string v0, "analytic_type"

    const-string v1, "ready_to_send"

    filled-new-array {v0, v1}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "(%1$s=? OR %1$s=?) AND %2$s=?"

    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    const/16 v1, 0xd

    .line 5
    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    const/16 v2, 0xb

    .line 6
    invoke-static {v2}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v2

    const/4 v3, 0x0

    .line 7
    invoke-static {v3}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v3

    filled-new-array {v1, v2, v3}, [Ljava/lang/String;

    move-result-object v1

    .line 8
    sget-object v2, Lcom/salesforce/marketingcloud/storage/db/a;->g:[Ljava/lang/String;

    invoke-virtual {p0, v2, v0, v1}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    move-result-object v0

    invoke-virtual {p0, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/a;->b(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public h(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/util/Crypto;",
            ")",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;"
        }
    .end annotation

    const/4 v0, 0x1

    .line 4
    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/a;->b(ILcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    move-result-object p0

    return-object p0
.end method

.method public o()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "analytic_item"

    .line 2
    .line 3
    return-object p0
.end method
