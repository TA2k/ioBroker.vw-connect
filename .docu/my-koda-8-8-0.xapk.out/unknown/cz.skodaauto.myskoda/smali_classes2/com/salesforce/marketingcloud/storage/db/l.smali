.class public final Lcom/salesforce/marketingcloud/storage/db/l;
.super Landroid/database/sqlite/SQLiteOpenHelper;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field public static final e:I = 0xd

.field private static final f:Ljava/lang/String; = "mcsdk_%s.db"

.field private static final g:Ljava/lang/String;


# instance fields
.field private final a:Landroid/content/Context;

.field private final b:Lcom/salesforce/marketingcloud/util/Crypto;

.field private final c:Lcom/salesforce/marketingcloud/util/Crypto;

.field private d:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "StorageSqliteOpenHelper"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/l;->g:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;)V
    .locals 6

    .line 5
    invoke-static {p3}, Lcom/salesforce/marketingcloud/storage/db/l;->a(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    const/16 v4, 0xd

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/storage/db/l;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;ILcom/salesforce/marketingcloud/util/Crypto;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;ILcom/salesforce/marketingcloud/util/Crypto;)V
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-direct {p0, p1, p3, v0, p4}, Landroid/database/sqlite/SQLiteOpenHelper;-><init>(Landroid/content/Context;Ljava/lang/String;Landroid/database/sqlite/SQLiteDatabase$CursorFactory;I)V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/storage/db/l;->a:Landroid/content/Context;

    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/storage/db/l;->b:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 4
    iput-object p5, p0, Lcom/salesforce/marketingcloud/storage/db/l;->c:Lcom/salesforce/marketingcloud/util/Crypto;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;Lcom/salesforce/marketingcloud/util/Crypto;)V
    .locals 6

    .line 6
    invoke-static {p3}, Lcom/salesforce/marketingcloud/storage/db/l;->a(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    const/16 v4, 0xd

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v5, p4

    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/storage/db/l;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;ILcom/salesforce/marketingcloud/util/Crypto;)V

    return-void
.end method

.method public static a(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    const-string v0, "mcsdk_"

    const-string v1, ".db"

    .line 2
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method private a(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 0

    .line 9
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 10
    :try_start_0
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/k;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 11
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/g;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 12
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/a;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 13
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/j;->c(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 14
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/i;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 15
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/h;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 16
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/f;->e(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 17
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/m;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 18
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/e;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 19
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    return-void

    :catchall_0
    move-exception p0

    .line 21
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 22
    throw p0
.end method


# virtual methods
.method public a()Z
    .locals 0

    .line 8
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/storage/db/l;->d:Z

    return p0
.end method

.method public b()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/storage/db/l;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 6
    .line 7
    .line 8
    const-string v1, "VACUUM"

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/storage/db/l;->onCreate(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public c()V
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lcom/salesforce/marketingcloud/storage/db/k;->c(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_1

    .line 10
    .line 11
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/l;->g:Ljava/lang/String;

    .line 12
    .line 13
    const-string v2, "registration"

    .line 14
    .line 15
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    const-string v3, "Database table %s was not initialized properly and will be dropped and recreated.  Some data may be lost."

    .line 20
    .line 21
    invoke-static {v1, v3, v2}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    :try_start_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/db/l;->b()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 25
    .line 26
    .line 27
    invoke-static {v0}, Lcom/salesforce/marketingcloud/storage/db/k;->c(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-nez p0, :cond_0

    .line 32
    .line 33
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 34
    .line 35
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 36
    .line 37
    const-string v0, "registration could not be initialized."

    .line 38
    .line 39
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :cond_0
    new-instance p0, Lcom/salesforce/marketingcloud/storage/exceptions/a;

    .line 44
    .line 45
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/storage/exceptions/a;-><init>()V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :catch_0
    move-exception p0

    .line 50
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    invoke-direct {v0, v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 57
    .line 58
    .line 59
    throw v0

    .line 60
    :cond_1
    invoke-static {v0}, Lcom/salesforce/marketingcloud/storage/db/g;->d(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    if-eqz p0, :cond_9

    .line 65
    .line 66
    invoke-static {v0}, Lcom/salesforce/marketingcloud/storage/db/a;->d(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    if-eqz p0, :cond_8

    .line 71
    .line 72
    invoke-static {v0}, Lcom/salesforce/marketingcloud/storage/db/j;->g(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    if-eqz p0, :cond_7

    .line 77
    .line 78
    invoke-static {v0}, Lcom/salesforce/marketingcloud/storage/db/i;->d(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    if-eqz p0, :cond_6

    .line 83
    .line 84
    invoke-static {v0}, Lcom/salesforce/marketingcloud/storage/db/h;->d(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 85
    .line 86
    .line 87
    move-result p0

    .line 88
    if-eqz p0, :cond_5

    .line 89
    .line 90
    invoke-static {v0}, Lcom/salesforce/marketingcloud/storage/db/m;->d(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 91
    .line 92
    .line 93
    move-result p0

    .line 94
    if-eqz p0, :cond_4

    .line 95
    .line 96
    invoke-static {v0}, Lcom/salesforce/marketingcloud/storage/db/f;->m(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    if-eqz p0, :cond_3

    .line 101
    .line 102
    invoke-static {v0}, Lcom/salesforce/marketingcloud/storage/db/e;->d(Landroid/database/sqlite/SQLiteDatabase;)Z

    .line 103
    .line 104
    .line 105
    move-result p0

    .line 106
    if-eqz p0, :cond_2

    .line 107
    .line 108
    return-void

    .line 109
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 110
    .line 111
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 112
    .line 113
    const-string v0, "device_stats could not be initialized."

    .line 114
    .line 115
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    throw p0

    .line 119
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 120
    .line 121
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 122
    .line 123
    const-string v0, "in_app_messages could not be initialized."

    .line 124
    .line 125
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    throw p0

    .line 129
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 130
    .line 131
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 132
    .line 133
    const-string v0, "triggers could not be initialized."

    .line 134
    .line 135
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    throw p0

    .line 139
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 140
    .line 141
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 142
    .line 143
    const-string v0, "location_table could not be initialized."

    .line 144
    .line 145
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    throw p0

    .line 149
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 150
    .line 151
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 152
    .line 153
    const-string v0, "messages could not be initialized."

    .line 154
    .line 155
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    throw p0

    .line 159
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 160
    .line 161
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 162
    .line 163
    const-string v0, "regions could not be initialized."

    .line 164
    .line 165
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    throw p0

    .line 169
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 170
    .line 171
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 172
    .line 173
    const-string v0, "analytic_item could not be initialized."

    .line 174
    .line 175
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    throw p0

    .line 179
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 180
    .line 181
    sget-object v0, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    .line 182
    .line 183
    const-string v0, "inbox_messages could not be initialized."

    .line 184
    .line 185
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 186
    .line 187
    .line 188
    throw p0
.end method

.method public onCreate(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 2
    .line 3
    .line 4
    :try_start_0
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/k;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 5
    .line 6
    .line 7
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/g;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 8
    .line 9
    .line 10
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/a;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/j;->d(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 14
    .line 15
    .line 16
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/i;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 17
    .line 18
    .line 19
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/h;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 20
    .line 21
    .line 22
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/f;->i(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 23
    .line 24
    .line 25
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/m;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 26
    .line 27
    .line 28
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/e;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    .line 33
    .line 34
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :catchall_0
    move-exception p0

    .line 39
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 40
    .line 41
    .line 42
    throw p0
.end method

.method public onDowngrade(Landroid/database/sqlite/SQLiteDatabase;II)V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/l;->g:Ljava/lang/String;

    .line 2
    .line 3
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object p3

    .line 7
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    filled-new-array {p3, p2}, [Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    const-string p3, "SQLite database being downgraded from %d to %d"

    .line 16
    .line 17
    invoke-static {v0, p3, p2}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    const/4 p2, 0x1

    .line 21
    iput-boolean p2, p0, Lcom/salesforce/marketingcloud/storage/db/l;->d:Z

    .line 22
    .line 23
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/l;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/storage/db/l;->onCreate(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public onOpen(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroid/database/sqlite/SQLiteOpenHelper;->onOpen(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->isReadOnly()Z

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    if-nez p0, :cond_0

    .line 9
    .line 10
    const-string p0, "PRAGMA foreign_keys=ON"

    .line 11
    .line 12
    invoke-virtual {p1, p0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    return-void
.end method

.method public onUpgrade(Landroid/database/sqlite/SQLiteDatabase;II)V
    .locals 1

    .line 1
    const/4 p3, 0x2

    .line 2
    if-ge p2, p3, :cond_1

    .line 3
    .line 4
    iget-object p3, p0, Lcom/salesforce/marketingcloud/storage/db/l;->c:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 5
    .line 6
    if-eqz p3, :cond_0

    .line 7
    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/storage/db/l;->a:Landroid/content/Context;

    .line 9
    .line 10
    invoke-static {p1, v0, p3}, Lcom/salesforce/marketingcloud/storage/db/upgrades/d;->b(Landroid/database/sqlite/SQLiteDatabase;Landroid/content/Context;Lcom/salesforce/marketingcloud/util/Crypto;)V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 15
    .line 16
    const-string p1, "Null crypto. Could not upgrade DB schema to 2."

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    :cond_1
    :goto_0
    const/4 p3, 0x3

    .line 23
    if-ge p2, p3, :cond_2

    .line 24
    .line 25
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/e;->f(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 26
    .line 27
    .line 28
    :cond_2
    const/4 p3, 0x4

    .line 29
    if-ge p2, p3, :cond_3

    .line 30
    .line 31
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/f;->c(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 32
    .line 33
    .line 34
    :cond_3
    const/4 p3, 0x5

    .line 35
    if-ge p2, p3, :cond_4

    .line 36
    .line 37
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/g;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 38
    .line 39
    .line 40
    :cond_4
    const/4 p3, 0x6

    .line 41
    if-ge p2, p3, :cond_5

    .line 42
    .line 43
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/h;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 44
    .line 45
    .line 46
    :cond_5
    const/4 p3, 0x7

    .line 47
    if-ge p2, p3, :cond_6

    .line 48
    .line 49
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/i;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 50
    .line 51
    .line 52
    :cond_6
    const/16 p3, 0x8

    .line 53
    .line 54
    if-ge p2, p3, :cond_7

    .line 55
    .line 56
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/j;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 57
    .line 58
    .line 59
    :cond_7
    const/16 p3, 0x9

    .line 60
    .line 61
    if-ge p2, p3, :cond_8

    .line 62
    .line 63
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/k;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 64
    .line 65
    .line 66
    :cond_8
    const/16 p3, 0xa

    .line 67
    .line 68
    if-ge p2, p3, :cond_a

    .line 69
    .line 70
    iget-object p3, p0, Lcom/salesforce/marketingcloud/storage/db/l;->c:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 71
    .line 72
    if-eqz p3, :cond_9

    .line 73
    .line 74
    invoke-static {p1, p3}, Lcom/salesforce/marketingcloud/storage/db/upgrades/l;->b(Landroid/database/sqlite/SQLiteDatabase;Lcom/salesforce/marketingcloud/util/Crypto;)V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 79
    .line 80
    const-string p1, "Null crypto. Could not upgrade DB schema to 10."

    .line 81
    .line 82
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    throw p0

    .line 86
    :cond_a
    :goto_1
    const/16 p3, 0xb

    .line 87
    .line 88
    if-ge p2, p3, :cond_c

    .line 89
    .line 90
    iget-object p3, p0, Lcom/salesforce/marketingcloud/storage/db/l;->c:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 91
    .line 92
    if-eqz p3, :cond_b

    .line 93
    .line 94
    invoke-static {p1, p3}, Lcom/salesforce/marketingcloud/storage/db/upgrades/a;->b(Landroid/database/sqlite/SQLiteDatabase;Lcom/salesforce/marketingcloud/util/Crypto;)V

    .line 95
    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 99
    .line 100
    const-string p1, "Null crypto. Could not upgrade DB schema to 11."

    .line 101
    .line 102
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    throw p0

    .line 106
    :cond_c
    :goto_2
    const/16 p3, 0xc

    .line 107
    .line 108
    if-ge p2, p3, :cond_d

    .line 109
    .line 110
    iget-object p3, p0, Lcom/salesforce/marketingcloud/storage/db/l;->b:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 111
    .line 112
    iget-object p0, p0, Lcom/salesforce/marketingcloud/storage/db/l;->c:Lcom/salesforce/marketingcloud/util/Crypto;

    .line 113
    .line 114
    invoke-static {p1, p3, p0}, Lcom/salesforce/marketingcloud/storage/db/upgrades/b;->a(Landroid/database/sqlite/SQLiteDatabase;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/util/Crypto;)V

    .line 115
    .line 116
    .line 117
    :cond_d
    const/16 p0, 0xd

    .line 118
    .line 119
    if-ge p2, p0, :cond_e

    .line 120
    .line 121
    invoke-static {p1}, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->c(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 122
    .line 123
    .line 124
    :cond_e
    return-void
.end method
