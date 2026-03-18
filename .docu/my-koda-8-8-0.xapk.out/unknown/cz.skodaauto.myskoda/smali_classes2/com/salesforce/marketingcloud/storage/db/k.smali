.class public final Lcom/salesforce/marketingcloud/storage/db/k;
.super Lcom/salesforce/marketingcloud/storage/db/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/storage/k;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/storage/db/k$a;
    }
.end annotation


# static fields
.field public static final e:Ljava/lang/String; = "registration"

.field private static final f:[Ljava/lang/String;

.field private static final g:Ljava/lang/String; = "CREATE TABLE registration (id INTEGER PRIMARY KEY AUTOINCREMENT, platform VARCHAR, subscriber_key VARCHAR, et_app_id VARCHAR, timezone INTEGER, dst SMALLINT, tags VARCHAR, attributes VARCHAR, platform_version VARCHAR, push_enabled SMALLINT, location_enabled SMALLINT, proximity_enabled SMALLINT, hwid VARCHAR, system_token VARCHAR, device_id VARCHAR, app_version VARCHAR, sdk_version VARCHAR, signed_string VARCHAR, locale VARCHAR, uuid VARCHAR );"


# direct methods
.method static constructor <clinit>()V
    .locals 21

    .line 1
    const-string v19, "locale"

    .line 2
    .line 3
    const-string v20, "uuid"

    .line 4
    .line 5
    const-string v1, "id"

    .line 6
    .line 7
    const-string v2, "platform"

    .line 8
    .line 9
    const-string v3, "subscriber_key"

    .line 10
    .line 11
    const-string v4, "et_app_id"

    .line 12
    .line 13
    const-string v5, "timezone"

    .line 14
    .line 15
    const-string v6, "dst"

    .line 16
    .line 17
    const-string v7, "tags"

    .line 18
    .line 19
    const-string v8, "attributes"

    .line 20
    .line 21
    const-string v9, "platform_version"

    .line 22
    .line 23
    const-string v10, "push_enabled"

    .line 24
    .line 25
    const-string v11, "location_enabled"

    .line 26
    .line 27
    const-string v12, "proximity_enabled"

    .line 28
    .line 29
    const-string v13, "hwid"

    .line 30
    .line 31
    const-string v14, "system_token"

    .line 32
    .line 33
    const-string v15, "device_id"

    .line 34
    .line 35
    const-string v16, "app_version"

    .line 36
    .line 37
    const-string v17, "sdk_version"

    .line 38
    .line 39
    const-string v18, "signed_string"

    .line 40
    .line 41
    filled-new-array/range {v1 .. v20}, [Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/k;->f:[Ljava/lang/String;

    .line 46
    .line 47
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

.method private static varargs a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;
    .locals 1

    .line 2
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    invoke-static {v0, p0, p1}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static a(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "DROP TABLE IF EXISTS registration"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method public static b(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "CREATE TABLE registration (id INTEGER PRIMARY KEY AUTOINCREMENT, platform VARCHAR, subscriber_key VARCHAR, et_app_id VARCHAR, timezone INTEGER, dst SMALLINT, tags VARCHAR, attributes VARCHAR, platform_version VARCHAR, push_enabled SMALLINT, location_enabled SMALLINT, proximity_enabled SMALLINT, hwid VARCHAR, system_token VARCHAR, device_id VARCHAR, app_version VARCHAR, sdk_version VARCHAR, signed_string VARCHAR, locale VARCHAR, uuid VARCHAR );"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method private static c(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/util/Crypto;)Landroid/content/ContentValues;
    .locals 3

    .line 2
    new-instance v0, Landroid/content/ContentValues;

    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->contactKey()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "subscriber_key"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->signedString()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "signed_string"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->appId()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "et_app_id"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 6
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->systemToken()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "system_token"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->tags()Ljava/util/Set;

    move-result-object v1

    invoke-static {v1}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Set;)Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "tags"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->attributes()Ljava/util/Map;

    move-result-object v1

    invoke-static {v1}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Map;)Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    const-string v1, "attributes"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 9
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->deviceId()Ljava/lang/String;

    move-result-object p1

    const-string v1, "device_id"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->platform()Ljava/lang/String;

    move-result-object p1

    const-string v1, "platform"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 11
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->timeZone()I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    const-string v1, "timezone"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 12
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->dst()Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    const-string v1, "dst"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 13
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->platformVersion()Ljava/lang/String;

    move-result-object p1

    const-string v1, "platform_version"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 14
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->pushEnabled()Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    const-string v1, "push_enabled"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 15
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->locationEnabled()Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    const-string v1, "location_enabled"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 16
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->proximityEnabled()Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    const-string v1, "proximity_enabled"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 17
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->hwid()Ljava/lang/String;

    move-result-object p1

    const-string v1, "hwid"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 18
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->locale()Ljava/lang/String;

    move-result-object p1

    const-string v1, "locale"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 19
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->appVersion()Ljava/lang/String;

    move-result-object p1

    const-string v1, "app_version"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 20
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->sdkVersion()Ljava/lang/String;

    move-result-object p1

    const-string v1, "sdk_version"

    invoke-virtual {v0, v1, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 21
    invoke-static {p0}, Lcom/salesforce/marketingcloud/internal/m;->d(Lcom/salesforce/marketingcloud/registration/Registration;)Ljava/lang/String;

    move-result-object p0

    const-string p1, "uuid"

    invoke-virtual {v0, p1, p0}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    return-object v0
.end method

.method public static c(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 3

    .line 1
    :try_start_0
    const-string v0, "SELECT %s FROM %s"

    const-string v1, ","

    sget-object v2, Lcom/salesforce/marketingcloud/storage/db/k;->f:[Ljava/lang/String;

    invoke-static {v1, v2}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "registration"

    filled-new-array {v1, v2}, [Ljava/lang/Object;

    move-result-object v1

    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/storage/db/k;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    const/4 p0, 0x1

    return p0

    :catch_0
    const/4 p0, 0x0

    return p0
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/util/Crypto;)V
    .locals 2

    .line 3
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/storage/db/k;->c(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/util/Crypto;)Landroid/content/ContentValues;

    move-result-object p2

    invoke-virtual {p0, p2}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;)J

    move-result-wide v0

    long-to-int p2, v0

    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/internal/m;->a(Lcom/salesforce/marketingcloud/registration/Registration;I)V

    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/k;->c()I

    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/util/Crypto;)I
    .locals 2

    .line 2
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/storage/db/k;->c(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/util/Crypto;)Landroid/content/ContentValues;

    move-result-object p2

    const-string v0, "id"

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "%s = ?"

    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/storage/db/k;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    .line 3
    invoke-static {p1}, Lcom/salesforce/marketingcloud/internal/m;->b(Lcom/salesforce/marketingcloud/registration/Registration;)I

    move-result p1

    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    .line 4
    invoke-virtual {p0, p2, v0, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public c()I
    .locals 2

    .line 22
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/k;->o()Ljava/lang/String;

    move-result-object v0

    const-string v1, "id"

    filled-new-array {v1, v0}, [Ljava/lang/Object;

    move-result-object v0

    .line 23
    const-string v1, "%1$s NOT IN ( SELECT %1$s FROM ( SELECT %1$s FROM %2$s ORDER BY %1$s DESC LIMIT 1))"

    invoke-static {v1, v0}, Lcom/salesforce/marketingcloud/storage/db/k;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    .line 24
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/storage/db/b;->i(Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public k(Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/registration/Registration;
    .locals 8

    .line 1
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/k;->f:[Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "id"

    .line 4
    .line 5
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const-string v2, "%s DESC"

    .line 10
    .line 11
    invoke-static {v2, v0}, Lcom/salesforce/marketingcloud/storage/db/k;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v6

    .line 15
    const/4 v5, 0x0

    .line 16
    const-string v7, "1"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    const/4 v3, 0x0

    .line 20
    const/4 v4, 0x0

    .line 21
    move-object v0, p0

    .line 22
    invoke-virtual/range {v0 .. v7}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    const/4 v0, 0x0

    .line 27
    if-eqz p0, :cond_1

    .line 28
    .line 29
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_0

    .line 34
    .line 35
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/d;->d(Landroid/database/Cursor;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/registration/Registration;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    :cond_0
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 40
    .line 41
    .line 42
    :cond_1
    return-object v0
.end method

.method public n()I
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

.method public o()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "registration"

    .line 2
    .line 3
    return-object p0
.end method
