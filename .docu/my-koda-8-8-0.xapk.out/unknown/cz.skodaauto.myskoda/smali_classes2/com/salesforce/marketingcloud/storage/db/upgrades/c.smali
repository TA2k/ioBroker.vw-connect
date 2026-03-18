.class public final Lcom/salesforce/marketingcloud/storage/db/upgrades/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "Range"
    }
.end annotation


# static fields
.field public static final a:Lcom/salesforce/marketingcloud/storage/db/upgrades/c;

.field private static final b:Ljava/lang/String;

.field private static c:Landroid/database/sqlite/SQLiteDatabase;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->a:Lcom/salesforce/marketingcloud/storage/db/upgrades/c;

    .line 7
    .line 8
    const-string v0, "Version12ToVersion13"

    .line 9
    .line 10
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->b:Ljava/lang/String;

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

.method private final a(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 8

    .line 1
    const-string p0, "ALTER TABLE inbox_messages ADD COLUMN message_type INTEGER DEFAULT "

    .line 2
    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->LEGACY:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->getIndex()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const-string v2, "CREATE TABLE inbox_messages (id TEXT PRIMARY KEY, start_date INTEGER DEFAULT NULL, end_date INTEGER DEFAULT NULL, is_deleted INTEGER DEFAULT 0, is_read INTEGER DEFAULT 0, is_dirty INTEGER DEFAULT 0, message_type INTEGER DEFAULT "

    .line 10
    .line 11
    const-string v3, ", message_hash TEXT DEFAULT NULL, notification_message_json TEXT DEFAULT NULL, message_json TEXT);"

    .line 12
    .line 13
    invoke-static {v2, v1, v3}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    :try_start_0
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$InboxMessageType;->getIndex()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    new-instance v2, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    invoke-direct {v2, p0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string p0, ";"

    .line 33
    .line 34
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-virtual {p1, p0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    const-string p0, "ALTER TABLE inbox_messages ADD COLUMN notification_message_json TEXT DEFAULT NULL;"

    .line 45
    .line 46
    invoke-virtual {p1, p0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 50
    .line 51
    .line 52
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :catchall_0
    move-exception v0

    .line 57
    move-object p0, v0

    .line 58
    goto :goto_1

    .line 59
    :catch_0
    move-exception v0

    .line 60
    move-object p0, v0

    .line 61
    :try_start_1
    sget-object v2, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 62
    .line 63
    sget-object v3, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->b:Ljava/lang/String;

    .line 64
    .line 65
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/c$a;->b:Lcom/salesforce/marketingcloud/storage/db/upgrades/c$a;

    .line 66
    .line 67
    invoke-virtual {v2, v3, p0, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 68
    .line 69
    .line 70
    :try_start_2
    const-string p0, "DROP TABLE IF EXISTS inbox_messages"

    .line 71
    .line 72
    invoke-virtual {p1, p0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {p1, v1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    sget-object v5, Lcom/salesforce/marketingcloud/storage/db/upgrades/c$b;->b:Lcom/salesforce/marketingcloud/storage/db/upgrades/c$b;

    .line 79
    .line 80
    const/4 v6, 0x2

    .line 81
    const/4 v7, 0x0

    .line 82
    const/4 v4, 0x0

    .line 83
    invoke-static/range {v2 .. v7}, Lcom/salesforce/marketingcloud/g;->e(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :catch_1
    move-exception v0

    .line 91
    move-object p0, v0

    .line 92
    :try_start_3
    sget-object v0, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 93
    .line 94
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->b:Ljava/lang/String;

    .line 95
    .line 96
    sget-object v2, Lcom/salesforce/marketingcloud/storage/db/upgrades/c$c;->b:Lcom/salesforce/marketingcloud/storage/db/upgrades/c$c;

    .line 97
    .line 98
    invoke-virtual {v0, v1, p0, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 99
    .line 100
    .line 101
    :goto_0
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 102
    .line 103
    .line 104
    return-void

    .line 105
    :goto_1
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 106
    .line 107
    .line 108
    throw p0
.end method

.method private final b(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 8

    .line 1
    const-string p0, "DELETE FROM registration WHERE id != "

    .line 2
    .line 3
    const-string v1, "CREATE TABLE registration (id INTEGER PRIMARY KEY AUTOINCREMENT, platform VARCHAR, subscriber_key VARCHAR, et_app_id VARCHAR, timezone INTEGER, dst SMALLINT, tags VARCHAR,  attributes VARCHAR, platform_version VARCHAR, push_enabled SMALLINT,  location_enabled SMALLINT, proximity_enabled SMALLINT, hwid VARCHAR,  system_token VARCHAR, device_id VARCHAR, app_version VARCHAR, sdk_version VARCHAR,  signed_string VARCHAR, locale VARCHAR, uuid VARCHAR)"

    .line 4
    .line 5
    :try_start_0
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 6
    .line 7
    .line 8
    const-string v0, "ALTER TABLE registration ADD COLUMN uuid VARCHAR"

    .line 9
    .line 10
    invoke-virtual {p1, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string v0, "SELECT id FROM registration ORDER BY id DESC LIMIT 1"

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    invoke-virtual {p1, v0, v2}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 17
    .line 18
    .line 19
    move-result-object v3
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 20
    :try_start_1
    invoke-interface {v3}, Landroid/database/Cursor;->moveToFirst()Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    const-string v0, "id"

    .line 27
    .line 28
    invoke-interface {v3, v0}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    invoke-interface {v3, v0}, Landroid/database/Cursor;->getInt(I)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 37
    .line 38
    .line 39
    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 40
    goto :goto_0

    .line 41
    :catchall_0
    move-exception v0

    .line 42
    move-object p0, v0

    .line 43
    goto :goto_2

    .line 44
    :cond_0
    :goto_0
    :try_start_2
    invoke-interface {v3}, Ljava/io/Closeable;->close()V

    .line 45
    .line 46
    .line 47
    if-eqz v2, :cond_1

    .line 48
    .line 49
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    new-instance v2, Ljava/lang/StringBuilder;

    .line 54
    .line 55
    invoke-direct {v2, p0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-virtual {p1, p0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    new-instance p0, Landroid/content/ContentValues;

    .line 69
    .line 70
    invoke-direct {p0}, Landroid/content/ContentValues;-><init>()V

    .line 71
    .line 72
    .line 73
    const-string v2, "uuid"

    .line 74
    .line 75
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    invoke-virtual {v3}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v3

    .line 83
    invoke-virtual {p0, v2, v3}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    const-string v2, "registration"

    .line 87
    .line 88
    const-string v3, "id=?"

    .line 89
    .line 90
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    filled-new-array {v0}, [Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    invoke-virtual {p1, v2, p0, v3, v0}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I

    .line 99
    .line 100
    .line 101
    goto :goto_1

    .line 102
    :catchall_1
    move-exception v0

    .line 103
    move-object p0, v0

    .line 104
    goto :goto_5

    .line 105
    :catch_0
    move-exception v0

    .line 106
    move-object p0, v0

    .line 107
    goto :goto_3

    .line 108
    :cond_1
    :goto_1
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V

    .line 109
    .line 110
    .line 111
    sget-object v2, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 112
    .line 113
    sget-object v3, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->b:Ljava/lang/String;

    .line 114
    .line 115
    sget-object v5, Lcom/salesforce/marketingcloud/storage/db/upgrades/c$d;->b:Lcom/salesforce/marketingcloud/storage/db/upgrades/c$d;

    .line 116
    .line 117
    const/4 v6, 0x2

    .line 118
    const/4 v7, 0x0

    .line 119
    const/4 v4, 0x0

    .line 120
    invoke-static/range {v2 .. v7}, Lcom/salesforce/marketingcloud/g;->c(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 121
    .line 122
    .line 123
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 124
    .line 125
    .line 126
    return-void

    .line 127
    :goto_2
    :try_start_3
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 128
    :catchall_2
    move-exception v0

    .line 129
    :try_start_4
    invoke-static {v3, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 130
    .line 131
    .line 132
    throw v0
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 133
    :goto_3
    :try_start_5
    sget-object v0, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 134
    .line 135
    sget-object v2, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->b:Ljava/lang/String;

    .line 136
    .line 137
    sget-object v3, Lcom/salesforce/marketingcloud/storage/db/upgrades/c$e;->b:Lcom/salesforce/marketingcloud/storage/db/upgrades/c$e;

    .line 138
    .line 139
    invoke-virtual {v0, v2, p0, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 140
    .line 141
    .line 142
    :try_start_6
    const-string p0, "DROP TABLE IF EXISTS registration"

    .line 143
    .line 144
    invoke-virtual {p1, p0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {p1, v1}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_1
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 151
    .line 152
    .line 153
    goto :goto_4

    .line 154
    :catch_1
    move-exception v0

    .line 155
    move-object p0, v0

    .line 156
    :try_start_7
    sget-object v0, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 157
    .line 158
    sget-object v1, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->b:Ljava/lang/String;

    .line 159
    .line 160
    sget-object v2, Lcom/salesforce/marketingcloud/storage/db/upgrades/c$f;->b:Lcom/salesforce/marketingcloud/storage/db/upgrades/c$f;

    .line 161
    .line 162
    invoke-virtual {v0, v1, p0, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 163
    .line 164
    .line 165
    :goto_4
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 166
    .line 167
    .line 168
    return-void

    .line 169
    :goto_5
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 170
    .line 171
    .line 172
    throw p0
.end method

.method public static final c(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 7

    .line 1
    const-string v0, "db"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 7
    .line 8
    sget-object v2, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->b:Ljava/lang/String;

    .line 9
    .line 10
    sget-object v4, Lcom/salesforce/marketingcloud/storage/db/upgrades/c$g;->b:Lcom/salesforce/marketingcloud/storage/db/upgrades/c$g;

    .line 11
    .line 12
    const/4 v5, 0x2

    .line 13
    const/4 v6, 0x0

    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-static/range {v1 .. v6}, Lcom/salesforce/marketingcloud/g;->c(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    sput-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 19
    .line 20
    sget-object v0, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->a:Lcom/salesforce/marketingcloud/storage/db/upgrades/c;

    .line 21
    .line 22
    invoke-direct {v0, p0}, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->b(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 23
    .line 24
    .line 25
    sget-object p0, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->c:Landroid/database/sqlite/SQLiteDatabase;

    .line 26
    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    invoke-direct {v0, p0}, Lcom/salesforce/marketingcloud/storage/db/upgrades/c;->a(Landroid/database/sqlite/SQLiteDatabase;)V

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :cond_0
    const-string p0, "database"

    .line 34
    .line 35
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const/4 p0, 0x0

    .line 39
    throw p0
.end method
