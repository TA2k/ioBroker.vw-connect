.class public final Lvp/m;
.super Landroid/database/sqlite/SQLiteOpenHelper;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lap0/o;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;)V
    .locals 3

    .line 5
    const-string v0, ""

    .line 6
    invoke-virtual {p2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-ne v2, v0, :cond_0

    move-object p2, v1

    .line 7
    :cond_0
    invoke-direct {p0, p1, p2, v1, v2}, Landroid/database/sqlite/SQLiteOpenHelper;-><init>(Landroid/content/Context;Ljava/lang/String;Landroid/database/sqlite/SQLiteDatabase$CursorFactory;I)V

    return-void
.end method

.method public constructor <init>(Lvp/j0;Landroid/content/Context;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lvp/m;->d:I

    .line 3
    iput-object p1, p0, Lvp/m;->e:Lap0/o;

    const-string p1, "google_app_measurement_local.db"

    .line 4
    invoke-direct {p0, p2, p1}, Lvp/m;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Lvp/n;Landroid/content/Context;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lvp/m;->d:I

    .line 1
    iput-object p1, p0, Lvp/m;->e:Lap0/o;

    const-string p1, "google_app_measurement.db"

    .line 2
    invoke-direct {p0, p2, p1}, Lvp/m;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    return-void
.end method

.method private final a(Landroid/database/sqlite/SQLiteDatabase;II)V
    .locals 0

    .line 1
    return-void
.end method

.method private final b(Landroid/database/sqlite/SQLiteDatabase;II)V
    .locals 0

    .line 1
    return-void
.end method

.method private final d(Landroid/database/sqlite/SQLiteDatabase;II)V
    .locals 0

    .line 1
    return-void
.end method

.method private final f(Landroid/database/sqlite/SQLiteDatabase;II)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;
    .locals 9

    .line 1
    iget v0, p0, Lvp/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lvp/m;->e:Lap0/o;

    .line 7
    .line 8
    check-cast v0, Lvp/j0;

    .line 9
    .line 10
    :try_start_0
    invoke-super {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    .line 11
    .line 12
    .line 13
    move-result-object p0
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    goto :goto_0

    .line 15
    :catch_0
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Lvp/g1;

    .line 18
    .line 19
    iget-object v2, v1, Lvp/g1;->i:Lvp/p0;

    .line 20
    .line 21
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 22
    .line 23
    .line 24
    iget-object v2, v2, Lvp/p0;->j:Lvp/n0;

    .line 25
    .line 26
    const-string v3, "Opening the local database failed, dropping and recreating it"

    .line 27
    .line 28
    invoke-virtual {v2, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    iget-object v2, v1, Lvp/g1;->d:Landroid/content/Context;

    .line 32
    .line 33
    const-string v3, "google_app_measurement_local.db"

    .line 34
    .line 35
    invoke-virtual {v2, v3}, Landroid/content/Context;->getDatabasePath(Ljava/lang/String;)Ljava/io/File;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    invoke-virtual {v2}, Ljava/io/File;->delete()Z

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    if-nez v2, :cond_0

    .line 44
    .line 45
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 46
    .line 47
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 48
    .line 49
    .line 50
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 51
    .line 52
    const-string v2, "Failed to delete corrupted local db file"

    .line 53
    .line 54
    invoke-virtual {v1, v3, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    :cond_0
    :try_start_1
    invoke-super {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    .line 58
    .line 59
    .line 60
    move-result-object p0
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_1

    .line 61
    goto :goto_0

    .line 62
    :catch_1
    move-exception p0

    .line 63
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v0, Lvp/g1;

    .line 66
    .line 67
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 68
    .line 69
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 70
    .line 71
    .line 72
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 73
    .line 74
    const-string v1, "Failed to open local database. Events will bypass local storage"

    .line 75
    .line 76
    invoke-virtual {v0, p0, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    const/4 p0, 0x0

    .line 80
    :goto_0
    return-object p0

    .line 81
    :catch_2
    move-exception p0

    .line 82
    throw p0

    .line 83
    :pswitch_0
    iget-object v0, p0, Lvp/m;->e:Lap0/o;

    .line 84
    .line 85
    check-cast v0, Lvp/n;

    .line 86
    .line 87
    iget-object v1, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast v1, Lvp/g1;

    .line 90
    .line 91
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast v2, Lvp/g1;

    .line 94
    .line 95
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 96
    .line 97
    .line 98
    iget-object v0, v0, Lvp/n;->i:Lg1/i3;

    .line 99
    .line 100
    iget-wide v3, v0, Lg1/i3;->e:J

    .line 101
    .line 102
    const-wide/16 v5, 0x0

    .line 103
    .line 104
    cmp-long v1, v3, v5

    .line 105
    .line 106
    if-nez v1, :cond_1

    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_1
    iget-object v1, v0, Lg1/i3;->f:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v1, Lto/a;

    .line 112
    .line 113
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 114
    .line 115
    .line 116
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 117
    .line 118
    .line 119
    move-result-wide v3

    .line 120
    iget-wide v7, v0, Lg1/i3;->e:J

    .line 121
    .line 122
    sub-long/2addr v3, v7

    .line 123
    const-wide/32 v7, 0x36ee80

    .line 124
    .line 125
    .line 126
    cmp-long v1, v3, v7

    .line 127
    .line 128
    if-ltz v1, :cond_3

    .line 129
    .line 130
    :goto_1
    :try_start_2
    invoke-super {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    .line 131
    .line 132
    .line 133
    move-result-object p0
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_3

    .line 134
    goto :goto_2

    .line 135
    :catch_3
    iget-object v1, v0, Lg1/i3;->f:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v1, Lto/a;

    .line 138
    .line 139
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 143
    .line 144
    .line 145
    move-result-wide v3

    .line 146
    iput-wide v3, v0, Lg1/i3;->e:J

    .line 147
    .line 148
    iget-object v1, v2, Lvp/g1;->i:Lvp/p0;

    .line 149
    .line 150
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 151
    .line 152
    .line 153
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 154
    .line 155
    const-string v3, "Opening the database failed, dropping and recreating it"

    .line 156
    .line 157
    invoke-virtual {v1, v3}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    iget-object v1, v2, Lvp/g1;->d:Landroid/content/Context;

    .line 161
    .line 162
    const-string v3, "google_app_measurement.db"

    .line 163
    .line 164
    invoke-virtual {v1, v3}, Landroid/content/Context;->getDatabasePath(Ljava/lang/String;)Ljava/io/File;

    .line 165
    .line 166
    .line 167
    move-result-object v1

    .line 168
    invoke-virtual {v1}, Ljava/io/File;->delete()Z

    .line 169
    .line 170
    .line 171
    move-result v1

    .line 172
    if-nez v1, :cond_2

    .line 173
    .line 174
    iget-object v1, v2, Lvp/g1;->i:Lvp/p0;

    .line 175
    .line 176
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 177
    .line 178
    .line 179
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 180
    .line 181
    const-string v4, "Failed to delete corrupted db file"

    .line 182
    .line 183
    invoke-virtual {v1, v3, v4}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    :cond_2
    :try_start_3
    invoke-super {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    iput-wide v5, v0, Lg1/i3;->e:J
    :try_end_3
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_3 .. :try_end_3} :catch_4

    .line 191
    .line 192
    :goto_2
    return-object p0

    .line 193
    :catch_4
    move-exception p0

    .line 194
    iget-object v0, v2, Lvp/g1;->i:Lvp/p0;

    .line 195
    .line 196
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 197
    .line 198
    .line 199
    iget-object v0, v0, Lvp/p0;->j:Lvp/n0;

    .line 200
    .line 201
    const-string v1, "Failed to open freshly created database"

    .line 202
    .line 203
    invoke-virtual {v0, p0, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    throw p0

    .line 207
    :cond_3
    new-instance p0, Landroid/database/sqlite/SQLiteException;

    .line 208
    .line 209
    const-string v0, "Database open failed"

    .line 210
    .line 211
    invoke-direct {p0, v0}, Landroid/database/sqlite/SQLiteException;-><init>(Ljava/lang/String;)V

    .line 212
    .line 213
    .line 214
    throw p0

    .line 215
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onCreate(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    iget v0, p0, Lvp/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lvp/m;->e:Lap0/o;

    .line 7
    .line 8
    check-cast p0, Lvp/j0;

    .line 9
    .line 10
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lvp/g1;

    .line 13
    .line 14
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 15
    .line 16
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 17
    .line 18
    .line 19
    invoke-static {p0, p1}, Lvp/t1;->f(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :pswitch_0
    iget-object p0, p0, Lvp/m;->e:Lap0/o;

    .line 24
    .line 25
    check-cast p0, Lvp/n;

    .line 26
    .line 27
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Lvp/g1;

    .line 30
    .line 31
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 32
    .line 33
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 34
    .line 35
    .line 36
    invoke-static {p0, p1}, Lvp/t1;->f(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;)V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onDowngrade(Landroid/database/sqlite/SQLiteDatabase;II)V
    .locals 0

    .line 1
    iget p0, p0, Lvp/m;->d:I

    .line 2
    .line 3
    return-void
.end method

.method public final onOpen(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 12

    .line 1
    iget v0, p0, Lvp/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lvp/m;->e:Lap0/o;

    .line 7
    .line 8
    check-cast p0, Lvp/j0;

    .line 9
    .line 10
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lvp/g1;

    .line 13
    .line 14
    iget-object v0, p0, Lvp/g1;->i:Lvp/p0;

    .line 15
    .line 16
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 17
    .line 18
    .line 19
    const-string v2, "messages"

    .line 20
    .line 21
    const-string v3, "create table if not exists messages ( type INTEGER NOT NULL, entry BLOB NOT NULL)"

    .line 22
    .line 23
    const-string v4, "type,entry"

    .line 24
    .line 25
    sget-object v5, Lvp/j0;->i:[Ljava/lang/String;

    .line 26
    .line 27
    move-object v1, p1

    .line 28
    invoke-static/range {v0 .. v5}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :pswitch_0
    move-object v7, p1

    .line 33
    iget-object p0, p0, Lvp/m;->e:Lap0/o;

    .line 34
    .line 35
    check-cast p0, Lvp/n;

    .line 36
    .line 37
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast p0, Lvp/g1;

    .line 40
    .line 41
    iget-object v6, p0, Lvp/g1;->i:Lvp/p0;

    .line 42
    .line 43
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 44
    .line 45
    .line 46
    const-string v8, "events"

    .line 47
    .line 48
    const-string v9, "CREATE TABLE IF NOT EXISTS events ( app_id TEXT NOT NULL, name TEXT NOT NULL, lifetime_count INTEGER NOT NULL, current_bundle_count INTEGER NOT NULL, last_fire_timestamp INTEGER NOT NULL, PRIMARY KEY (app_id, name)) ;"

    .line 49
    .line 50
    const-string v10, "app_id,name,lifetime_count,current_bundle_count,last_fire_timestamp"

    .line 51
    .line 52
    sget-object v11, Lvp/n;->j:[Ljava/lang/String;

    .line 53
    .line 54
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object v6, p0, Lvp/g1;->i:Lvp/p0;

    .line 58
    .line 59
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 60
    .line 61
    .line 62
    const/4 v11, 0x0

    .line 63
    const-string v8, "events_snapshot"

    .line 64
    .line 65
    const-string v9, "CREATE TABLE IF NOT EXISTS events_snapshot ( app_id TEXT NOT NULL, name TEXT NOT NULL, lifetime_count INTEGER NOT NULL, current_bundle_count INTEGER NOT NULL, last_fire_timestamp INTEGER NOT NULL, last_bundled_timestamp INTEGER, last_bundled_day INTEGER, last_sampled_complex_event_id INTEGER, last_sampling_rate INTEGER, last_exempt_from_sampling INTEGER, current_session_count INTEGER, PRIMARY KEY (app_id, name)) ;"

    .line 66
    .line 67
    const-string v10, "app_id,name,lifetime_count,current_bundle_count,last_fire_timestamp,last_bundled_timestamp,last_bundled_day,last_sampled_complex_event_id,last_sampling_rate,last_exempt_from_sampling,current_session_count"

    .line 68
    .line 69
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 73
    .line 74
    .line 75
    const-string v8, "conditional_properties"

    .line 76
    .line 77
    const-string v9, "CREATE TABLE IF NOT EXISTS conditional_properties ( app_id TEXT NOT NULL, origin TEXT NOT NULL, name TEXT NOT NULL, value BLOB NOT NULL, creation_timestamp INTEGER NOT NULL, active INTEGER NOT NULL, trigger_event_name TEXT, trigger_timeout INTEGER NOT NULL, timed_out_event BLOB,triggered_event BLOB, triggered_timestamp INTEGER NOT NULL, time_to_live INTEGER NOT NULL, expired_event BLOB, PRIMARY KEY (app_id, name)) ;"

    .line 78
    .line 79
    const-string v10, "app_id,origin,name,value,active,trigger_event_name,trigger_timeout,creation_timestamp,timed_out_event,triggered_event,triggered_timestamp,time_to_live,expired_event"

    .line 80
    .line 81
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 85
    .line 86
    .line 87
    const-string v8, "user_attributes"

    .line 88
    .line 89
    const-string v9, "CREATE TABLE IF NOT EXISTS user_attributes ( app_id TEXT NOT NULL, name TEXT NOT NULL, set_timestamp INTEGER NOT NULL, value BLOB NOT NULL, PRIMARY KEY (app_id, name)) ;"

    .line 90
    .line 91
    const-string v10, "app_id,name,set_timestamp,value"

    .line 92
    .line 93
    sget-object v11, Lvp/n;->l:[Ljava/lang/String;

    .line 94
    .line 95
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 96
    .line 97
    .line 98
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 99
    .line 100
    .line 101
    const-string v8, "apps"

    .line 102
    .line 103
    const-string v9, "CREATE TABLE IF NOT EXISTS apps ( app_id TEXT NOT NULL, app_instance_id TEXT, gmp_app_id TEXT, resettable_device_id_hash TEXT, last_bundle_index INTEGER NOT NULL, last_bundle_end_timestamp INTEGER NOT NULL, PRIMARY KEY (app_id)) ;"

    .line 104
    .line 105
    const-string v10, "app_id,app_instance_id,gmp_app_id,resettable_device_id_hash,last_bundle_index,last_bundle_end_timestamp"

    .line 106
    .line 107
    sget-object v11, Lvp/n;->m:[Ljava/lang/String;

    .line 108
    .line 109
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 113
    .line 114
    .line 115
    const-string v8, "queue"

    .line 116
    .line 117
    const-string v9, "CREATE TABLE IF NOT EXISTS queue ( app_id TEXT NOT NULL, bundle_end_timestamp INTEGER NOT NULL, data BLOB NOT NULL);"

    .line 118
    .line 119
    const-string v10, "app_id,bundle_end_timestamp,data"

    .line 120
    .line 121
    sget-object v11, Lvp/n;->o:[Ljava/lang/String;

    .line 122
    .line 123
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 127
    .line 128
    .line 129
    const/4 v11, 0x0

    .line 130
    const-string v8, "raw_events_metadata"

    .line 131
    .line 132
    const-string v9, "CREATE TABLE IF NOT EXISTS raw_events_metadata ( app_id TEXT NOT NULL, metadata_fingerprint INTEGER NOT NULL, metadata BLOB NOT NULL, PRIMARY KEY (app_id, metadata_fingerprint));"

    .line 133
    .line 134
    const-string v10, "app_id,metadata_fingerprint,metadata"

    .line 135
    .line 136
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 140
    .line 141
    .line 142
    const-string v8, "raw_events"

    .line 143
    .line 144
    const-string v9, "CREATE TABLE IF NOT EXISTS raw_events ( app_id TEXT NOT NULL, name TEXT NOT NULL, timestamp INTEGER NOT NULL, metadata_fingerprint INTEGER NOT NULL, data BLOB NOT NULL);"

    .line 145
    .line 146
    const-string v10, "app_id,name,timestamp,metadata_fingerprint,data"

    .line 147
    .line 148
    sget-object v11, Lvp/n;->n:[Ljava/lang/String;

    .line 149
    .line 150
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 154
    .line 155
    .line 156
    const-string v8, "event_filters"

    .line 157
    .line 158
    const-string v9, "CREATE TABLE IF NOT EXISTS event_filters ( app_id TEXT NOT NULL, audience_id INTEGER NOT NULL, filter_id INTEGER NOT NULL, event_name TEXT NOT NULL, data BLOB NOT NULL, PRIMARY KEY (app_id, event_name, audience_id, filter_id));"

    .line 159
    .line 160
    const-string v10, "app_id,audience_id,filter_id,event_name,data"

    .line 161
    .line 162
    sget-object v11, Lvp/n;->p:[Ljava/lang/String;

    .line 163
    .line 164
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 168
    .line 169
    .line 170
    const-string v8, "property_filters"

    .line 171
    .line 172
    const-string v9, "CREATE TABLE IF NOT EXISTS property_filters ( app_id TEXT NOT NULL, audience_id INTEGER NOT NULL, filter_id INTEGER NOT NULL, property_name TEXT NOT NULL, data BLOB NOT NULL, PRIMARY KEY (app_id, property_name, audience_id, filter_id));"

    .line 173
    .line 174
    const-string v10, "app_id,audience_id,filter_id,property_name,data"

    .line 175
    .line 176
    sget-object v11, Lvp/n;->q:[Ljava/lang/String;

    .line 177
    .line 178
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 179
    .line 180
    .line 181
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 182
    .line 183
    .line 184
    const/4 v11, 0x0

    .line 185
    const-string v8, "audience_filter_values"

    .line 186
    .line 187
    const-string v9, "CREATE TABLE IF NOT EXISTS audience_filter_values ( app_id TEXT NOT NULL, audience_id INTEGER NOT NULL, current_results BLOB, PRIMARY KEY (app_id, audience_id));"

    .line 188
    .line 189
    const-string v10, "app_id,audience_id,current_results"

    .line 190
    .line 191
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 195
    .line 196
    .line 197
    const-string v8, "app2"

    .line 198
    .line 199
    const-string v9, "CREATE TABLE IF NOT EXISTS app2 ( app_id TEXT NOT NULL, first_open_count INTEGER NOT NULL, PRIMARY KEY (app_id));"

    .line 200
    .line 201
    const-string v10, "app_id,first_open_count"

    .line 202
    .line 203
    sget-object v11, Lvp/n;->r:[Ljava/lang/String;

    .line 204
    .line 205
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 209
    .line 210
    .line 211
    const-string v10, "app_id,event_id,children_to_process,main_event"

    .line 212
    .line 213
    const/4 v11, 0x0

    .line 214
    const-string v8, "main_event_params"

    .line 215
    .line 216
    const-string v9, "CREATE TABLE IF NOT EXISTS main_event_params ( app_id TEXT NOT NULL, event_id TEXT NOT NULL, children_to_process INTEGER NOT NULL, main_event BLOB NOT NULL, PRIMARY KEY (app_id));"

    .line 217
    .line 218
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 222
    .line 223
    .line 224
    const-string v8, "default_event_params"

    .line 225
    .line 226
    const-string v9, "CREATE TABLE IF NOT EXISTS default_event_params ( app_id TEXT NOT NULL, parameters BLOB NOT NULL, PRIMARY KEY (app_id));"

    .line 227
    .line 228
    const-string v10, "app_id,parameters"

    .line 229
    .line 230
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 234
    .line 235
    .line 236
    const-string v8, "consent_settings"

    .line 237
    .line 238
    const-string v9, "CREATE TABLE IF NOT EXISTS consent_settings ( app_id TEXT NOT NULL, consent_state TEXT NOT NULL, PRIMARY KEY (app_id));"

    .line 239
    .line 240
    const-string v10, "app_id,consent_state"

    .line 241
    .line 242
    sget-object v11, Lvp/n;->s:[Ljava/lang/String;

    .line 243
    .line 244
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    invoke-static {}, Lcom/google/android/gms/internal/measurement/u8;->a()V

    .line 248
    .line 249
    .line 250
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 251
    .line 252
    .line 253
    const-string v8, "trigger_uris"

    .line 254
    .line 255
    const-string v9, "CREATE TABLE IF NOT EXISTS trigger_uris ( app_id TEXT NOT NULL, trigger_uri TEXT NOT NULL, timestamp_millis INTEGER NOT NULL, source INTEGER NOT NULL);"

    .line 256
    .line 257
    const-string v10, "app_id,trigger_uri,source,timestamp_millis"

    .line 258
    .line 259
    sget-object v11, Lvp/n;->t:[Ljava/lang/String;

    .line 260
    .line 261
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 265
    .line 266
    .line 267
    sget-object v11, Lvp/n;->k:[Ljava/lang/String;

    .line 268
    .line 269
    const-string v8, "upload_queue"

    .line 270
    .line 271
    const-string v9, "CREATE TABLE IF NOT EXISTS upload_queue ( app_id TEXT NOT NULL, upload_uri TEXT NOT NULL, upload_headers TEXT NOT NULL, upload_type INTEGER NOT NULL, measurement_batch BLOB NOT NULL, retry_count INTEGER NOT NULL, creation_timestamp INTEGER NOT NULL );"

    .line 272
    .line 273
    const-string v10, "app_id,upload_uri,upload_headers,upload_type,measurement_batch,retry_count,creation_timestamp"

    .line 274
    .line 275
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 276
    .line 277
    .line 278
    sget-object p0, Lcom/google/android/gms/internal/measurement/t7;->e:Lcom/google/android/gms/internal/measurement/t7;

    .line 279
    .line 280
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/t7;->d:Lgr/p;

    .line 281
    .line 282
    iget-object p0, p0, Lgr/p;->d:Ljava/lang/Object;

    .line 283
    .line 284
    check-cast p0, Lcom/google/android/gms/internal/measurement/u7;

    .line 285
    .line 286
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 287
    .line 288
    .line 289
    const-string v10, "app_id,name,data,timestamp_millis"

    .line 290
    .line 291
    const/4 v11, 0x0

    .line 292
    const-string v8, "no_data_mode_events"

    .line 293
    .line 294
    const-string v9, "CREATE TABLE IF NOT EXISTS no_data_mode_events ( app_id TEXT NOT NULL, name TEXT NOT NULL, data BLOB NOT NULL, timestamp_millis INTEGER NOT NULL);"

    .line 295
    .line 296
    invoke-static/range {v6 .. v11}, Lvp/t1;->d(Lvp/p0;Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V

    .line 297
    .line 298
    .line 299
    return-void

    .line 300
    nop

    .line 301
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onUpgrade(Landroid/database/sqlite/SQLiteDatabase;II)V
    .locals 0

    .line 1
    iget p0, p0, Lvp/m;->d:I

    .line 2
    .line 3
    return-void
.end method
