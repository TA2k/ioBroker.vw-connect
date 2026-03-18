.class public final Lcom/salesforce/marketingcloud/storage/db/h;
.super Lcom/salesforce/marketingcloud/storage/db/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/storage/g;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness",
        "Range"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/storage/db/h$a;
    }
.end annotation


# static fields
.field public static final e:Ljava/lang/String; = "location_table"

.field private static final f:Ljava/lang/String; = "CREATE TABLE location_table (id INTEGER PRIMARY KEY CHECK (id = 0), latitude VARCHAR, longitude VARCHAR );"

.field private static final g:[Ljava/lang/String;

.field private static final h:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-string v0, "latitude"

    .line 2
    .line 3
    const-string v1, "longitude"

    .line 4
    .line 5
    const-string v2, "id"

    .line 6
    .line 7
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/h;->g:[Ljava/lang/String;

    .line 12
    .line 13
    const-string v0, "LocationDbStorage"

    .line 14
    .line 15
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/h;->h:Ljava/lang/String;

    .line 20
    .line 21
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

.method public static a(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "DROP TABLE IF EXISTS location_table"

    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    return-void
.end method

.method public static b(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "CREATE TABLE location_table (id INTEGER PRIMARY KEY CHECK (id = 0), latitude VARCHAR, longitude VARCHAR );"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private static c(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 4

    .line 1
    const-string v0, "location_table"

    .line 2
    .line 3
    :try_start_0
    const-string v1, "SELECT %s FROM %s"

    .line 4
    .line 5
    const-string v2, ","

    .line 6
    .line 7
    sget-object v3, Lcom/salesforce/marketingcloud/storage/db/h;->g:[Ljava/lang/String;

    .line 8
    .line 9
    invoke-static {v2, v3}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;[Ljava/lang/Object;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    filled-new-array {v2, v0}, [Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-static {v1, v2}, Lcom/salesforce/marketingcloud/storage/db/c;->a(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-virtual {p0, v1}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    .line 23
    .line 24
    const/4 p0, 0x1

    .line 25
    return p0

    .line 26
    :catch_0
    move-exception p0

    .line 27
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/h;->h:Ljava/lang/String;

    .line 28
    .line 29
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    const-string v2, "%s is invalid"

    .line 34
    .line 35
    invoke-static {v1, p0, v2, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    const/4 p0, 0x0

    .line 39
    return p0
.end method

.method public static d(Landroid/database/sqlite/SQLiteDatabase;)Z
    .locals 4

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/h;->c(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    :try_start_0
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/h;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 8
    .line 9
    .line 10
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/h;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p0}, Lcom/salesforce/marketingcloud/storage/db/h;->c(Landroid/database/sqlite/SQLiteDatabase;)Z

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
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/h;->h:Ljava/lang/String;

    .line 20
    .line 21
    const-string v2, "location_table"

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
.method public a(Lcom/salesforce/marketingcloud/location/LatLon;Lcom/salesforce/marketingcloud/util/Crypto;)V
    .locals 3

    .line 2
    new-instance v0, Landroid/content/ContentValues;

    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V

    const/4 v1, 0x0

    .line 3
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    const-string v2, "id"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 4
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/location/LatLon;->latitude()D

    move-result-wide v1

    invoke-static {v1, v2}, Ljava/lang/Double;->toString(D)Ljava/lang/String;

    move-result-object v1

    invoke-interface {p2, v1}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string v2, "latitude"

    invoke-virtual {v0, v2, v1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 5
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/location/LatLon;->longitude()D

    move-result-wide v1

    invoke-static {v1, v2}, Ljava/lang/Double;->toString(D)Ljava/lang/String;

    move-result-object p1

    invoke-interface {p2, p1}, Lcom/salesforce/marketingcloud/util/Crypto;->encString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    const-string p2, "longitude"

    invoke-virtual {v0, p2, p1}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 6
    sget-object p1, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    const-string p1, "0"

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    const-string p2, "id = ?"

    invoke-virtual {p0, v0, p2, p1}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    move-result p1

    if-nez p1, :cond_0

    .line 7
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/storage/db/b;->a(Landroid/content/ContentValues;)J

    :cond_0
    return-void
.end method

.method public e(Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/location/LatLon;
    .locals 5

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/h;->g:[Ljava/lang/String;

    .line 2
    .line 3
    sget-object v1, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 4
    .line 5
    const-string v1, "0"

    .line 6
    .line 7
    filled-new-array {v1}, [Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    const-string v2, "id = ?"

    .line 12
    .line 13
    invoke-virtual {p0, v0, v2, v1}, Lcom/salesforce/marketingcloud/storage/db/b;->a([Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    const/4 v0, 0x0

    .line 18
    if-eqz p0, :cond_1

    .line 19
    .line 20
    invoke-interface {p0}, Landroid/database/Cursor;->moveToFirst()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_0

    .line 25
    .line 26
    :try_start_0
    const-string v1, "latitude"

    .line 27
    .line 28
    invoke-interface {p0, v1}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    invoke-interface {p0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-interface {p1, v1}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-static {v1}, Ljava/lang/Double;->valueOf(Ljava/lang/String;)Ljava/lang/Double;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-virtual {v1}, Ljava/lang/Double;->doubleValue()D

    .line 45
    .line 46
    .line 47
    move-result-wide v1

    .line 48
    const-string v3, "longitude"

    .line 49
    .line 50
    invoke-interface {p0, v3}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    invoke-interface {p0, v3}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    invoke-interface {p1, v3}, Lcom/salesforce/marketingcloud/util/Crypto;->decString(Ljava/lang/String;)Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-static {p1}, Ljava/lang/Double;->valueOf(Ljava/lang/String;)Ljava/lang/Double;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    invoke-virtual {p1}, Ljava/lang/Double;->doubleValue()D

    .line 67
    .line 68
    .line 69
    move-result-wide v3

    .line 70
    new-instance p1, Lcom/salesforce/marketingcloud/location/LatLon;

    .line 71
    .line 72
    invoke-direct {p1, v1, v2, v3, v4}, Lcom/salesforce/marketingcloud/location/LatLon;-><init>(DD)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 73
    .line 74
    .line 75
    move-object v0, p1

    .line 76
    goto :goto_0

    .line 77
    :catch_0
    move-exception p1

    .line 78
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/h;->h:Ljava/lang/String;

    .line 79
    .line 80
    const/4 v2, 0x0

    .line 81
    new-array v2, v2, [Ljava/lang/Object;

    .line 82
    .line 83
    const-string v3, "Unable to read location from database."

    .line 84
    .line 85
    invoke-static {v1, p1, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :cond_0
    :goto_0
    invoke-interface {p0}, Landroid/database/Cursor;->close()V

    .line 89
    .line 90
    .line 91
    :cond_1
    return-object v0
.end method

.method public g()I
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
    const-string p0, "location_table"

    .line 2
    .line 3
    return-object p0
.end method
