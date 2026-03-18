.class public final synthetic Lrx/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt01/b;
.implements Lo8/g;
.implements Ly4/i;
.implements Lh0/b1;
.implements Lk0/a;
.implements Lx7/r;
.implements Lzn/b;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lrx/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lrx/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a(J)J
    .locals 8

    .line 1
    iget-object p0, p0, Lrx/b;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/u;

    .line 4
    .line 5
    iget v0, p0, Lo8/u;->e:I

    .line 6
    .line 7
    int-to-long v0, v0

    .line 8
    mul-long/2addr p1, v0

    .line 9
    const-wide/32 v0, 0xf4240

    .line 10
    .line 11
    .line 12
    div-long v2, p1, v0

    .line 13
    .line 14
    iget-wide p0, p0, Lo8/u;->j:J

    .line 15
    .line 16
    const-wide/16 v0, 0x1

    .line 17
    .line 18
    sub-long v6, p0, v0

    .line 19
    .line 20
    const-wide/16 v4, 0x0

    .line 21
    .line 22
    invoke-static/range {v2 .. v7}, Lw7/w;->h(JJJ)J

    .line 23
    .line 24
    .line 25
    move-result-wide p0

    .line 26
    return-wide p0
.end method

.method public apply(Ljava/lang/Object;)Lcom/google/common/util/concurrent/ListenableFuture;
    .locals 0

    .line 1
    iget-object p0, p0, Lrx/b;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lcom/google/common/util/concurrent/ListenableFuture;

    .line 10
    .line 11
    return-object p0
.end method

.method public b(JLw7/p;)V
    .locals 1

    .line 1
    iget v0, p0, Lrx/b;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lrx/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lv9/c0;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lv9/c0;->c:[Lo8/i0;

    .line 11
    .line 12
    invoke-static {p1, p2, p3, p0}, Lo8/b;->e(JLw7/p;[Lo8/i0;)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :pswitch_0
    iget-object p0, p0, Lv9/c0;->c:[Lo8/i0;

    .line 17
    .line 18
    invoke-static {p1, p2, p3, p0}, Lo8/b;->d(JLw7/p;[Lo8/i0;)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    nop

    .line 23
    :pswitch_data_0
    .packed-switch 0xc
        :pswitch_0
    .end packed-switch
.end method

.method public c(Lh0/c1;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lrx/b;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lu/l1;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    :try_start_0
    invoke-interface {p1}, Lh0/c1;->b()Lb0/a1;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    iget-object p0, p0, Lu/l1;->c:Lil/g;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lil/g;->v(Lb0/a1;)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 17
    .line 18
    .line 19
    :cond_0
    return-void

    .line 20
    :catch_0
    move-exception p0

    .line 21
    new-instance p1, Ljava/lang/StringBuilder;

    .line 22
    .line 23
    const-string v0, "Failed to acquire latest image IllegalStateException = "

    .line 24
    .line 25
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    const-string p1, "ZslControlImpl"

    .line 40
    .line 41
    invoke-static {p1, p0}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    return-void
.end method

.method public d()V
    .locals 2

    .line 1
    iget v0, p0, Lrx/b;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lrx/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lay0/n;

    .line 9
    .line 10
    sget-object v0, Lv2/l;->c:Ljava/lang/Object;

    .line 11
    .line 12
    monitor-enter v0

    .line 13
    :try_start_0
    sget-object v1, Lv2/l;->h:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v1, Ljava/lang/Iterable;

    .line 16
    .line 17
    invoke-static {v1, p0}, Lmx0/q;->W(Ljava/lang/Iterable;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    sput-object p0, Lv2/l;->h:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 22
    .line 23
    monitor-exit v0

    .line 24
    return-void

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    monitor-exit v0

    .line 27
    throw p0

    .line 28
    :pswitch_0
    check-cast p0, Lb1/e;

    .line 29
    .line 30
    sget-object v0, Lv2/l;->c:Ljava/lang/Object;

    .line 31
    .line 32
    monitor-enter v0

    .line 33
    :try_start_1
    sget-object v1, Lv2/l;->i:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v1, Ljava/lang/Iterable;

    .line 36
    .line 37
    invoke-static {v1, p0}, Lmx0/q;->W(Ljava/lang/Iterable;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    sput-object p0, Lv2/l;->i:Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 42
    .line 43
    monitor-exit v0

    .line 44
    invoke-static {}, Lv2/l;->a()V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :catchall_1
    move-exception p0

    .line 49
    monitor-exit v0

    .line 50
    throw p0

    .line 51
    :pswitch_data_0
    .packed-switch 0xa
        :pswitch_0
    .end packed-switch
.end method

.method public e(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Lrx/b;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lz4/q;

    .line 4
    .line 5
    iget-object p0, p0, Lz4/q;->k:Lt4/c;

    .line 6
    .line 7
    invoke-interface {p0}, Lt4/c;->a()F

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    mul-float/2addr p0, p1

    .line 12
    return p0
.end method

.method public execute()Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lrx/b;->d:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    const/4 v3, 0x0

    .line 6
    iget-object p0, p0, Lrx/b;->e:Ljava/lang/Object;

    .line 7
    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    check-cast p0, Lun/a;

    .line 12
    .line 13
    iget-object v0, p0, Lun/a;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Lyn/d;

    .line 16
    .line 17
    check-cast v0, Lyn/h;

    .line 18
    .line 19
    new-instance v4, Lt0/c;

    .line 20
    .line 21
    const/16 v5, 0x17

    .line 22
    .line 23
    invoke-direct {v4, v5}, Lt0/c;-><init>(I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, v4}, Lyn/h;->d(Lyn/f;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    check-cast v0, Ljava/lang/Iterable;

    .line 31
    .line 32
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v4

    .line 40
    if-eqz v4, :cond_0

    .line 41
    .line 42
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    check-cast v4, Lrn/j;

    .line 47
    .line 48
    iget-object v5, p0, Lun/a;->g:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v5, Lrn/i;

    .line 51
    .line 52
    invoke-virtual {v5, v4, v1, v3}, Lrn/i;->z(Lrn/j;IZ)V

    .line 53
    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_0
    return-object v2

    .line 57
    :pswitch_0
    check-cast p0, Lqn/s;

    .line 58
    .line 59
    iget-object p0, p0, Lqn/s;->i:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p0, Lyn/c;

    .line 62
    .line 63
    check-cast p0, Lyn/h;

    .line 64
    .line 65
    invoke-virtual {p0}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 70
    .line 71
    .line 72
    :try_start_0
    const-string v1, "DELETE FROM log_event_dropped"

    .line 73
    .line 74
    invoke-virtual {v0, v1}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    invoke-virtual {v1}, Landroid/database/sqlite/SQLiteStatement;->execute()V

    .line 79
    .line 80
    .line 81
    new-instance v1, Ljava/lang/StringBuilder;

    .line 82
    .line 83
    const-string v3, "UPDATE global_log_event_state SET last_metrics_upload_ms="

    .line 84
    .line 85
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iget-object p0, p0, Lyn/h;->e:Lao/a;

    .line 89
    .line 90
    invoke-interface {p0}, Lao/a;->a()J

    .line 91
    .line 92
    .line 93
    move-result-wide v3

    .line 94
    invoke-virtual {v1, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    invoke-virtual {v0, p0}, Landroid/database/sqlite/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Landroid/database/sqlite/SQLiteStatement;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteStatement;->execute()V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 109
    .line 110
    .line 111
    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 112
    .line 113
    .line 114
    return-object v2

    .line 115
    :catchall_0
    move-exception p0

    .line 116
    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 117
    .line 118
    .line 119
    throw p0

    .line 120
    :pswitch_1
    check-cast p0, Lyn/d;

    .line 121
    .line 122
    check-cast p0, Lyn/h;

    .line 123
    .line 124
    iget-object v0, p0, Lyn/h;->e:Lao/a;

    .line 125
    .line 126
    invoke-interface {v0}, Lao/a;->a()J

    .line 127
    .line 128
    .line 129
    move-result-wide v4

    .line 130
    iget-object v0, p0, Lyn/h;->g:Lyn/a;

    .line 131
    .line 132
    iget-wide v6, v0, Lyn/a;->d:J

    .line 133
    .line 134
    sub-long/2addr v4, v6

    .line 135
    invoke-virtual {p0}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 140
    .line 141
    .line 142
    :try_start_1
    const-string v2, "SELECT COUNT(*), transport_name FROM events WHERE timestamp_ms < ? GROUP BY transport_name"

    .line 143
    .line 144
    invoke-static {v4, v5}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v4

    .line 148
    filled-new-array {v4}, [Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v4

    .line 152
    invoke-virtual {v0, v2, v4}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 153
    .line 154
    .line 155
    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 156
    :goto_1
    :try_start_2
    invoke-interface {v2}, Landroid/database/Cursor;->moveToNext()Z

    .line 157
    .line 158
    .line 159
    move-result v5

    .line 160
    if-eqz v5, :cond_1

    .line 161
    .line 162
    invoke-interface {v2, v3}, Landroid/database/Cursor;->getInt(I)I

    .line 163
    .line 164
    .line 165
    move-result v5

    .line 166
    invoke-interface {v2, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v6

    .line 170
    int-to-long v7, v5

    .line 171
    sget-object v5, Lun/d;->f:Lun/d;

    .line 172
    .line 173
    invoke-virtual {p0, v7, v8, v5, v6}, Lyn/h;->g(JLun/d;Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 174
    .line 175
    .line 176
    goto :goto_1

    .line 177
    :cond_1
    :try_start_3
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 178
    .line 179
    .line 180
    const-string p0, "events"

    .line 181
    .line 182
    const-string v1, "timestamp_ms < ?"

    .line 183
    .line 184
    invoke-virtual {v0, p0, v1, v4}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I

    .line 185
    .line 186
    .line 187
    move-result p0

    .line 188
    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 189
    .line 190
    .line 191
    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 192
    .line 193
    .line 194
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    return-object p0

    .line 199
    :catchall_1
    move-exception p0

    .line 200
    goto :goto_2

    .line 201
    :catchall_2
    move-exception p0

    .line 202
    :try_start_4
    invoke-interface {v2}, Landroid/database/Cursor;->close()V

    .line 203
    .line 204
    .line 205
    throw p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 206
    :goto_2
    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 207
    .line 208
    .line 209
    throw p0

    .line 210
    :pswitch_2
    check-cast p0, Lyn/c;

    .line 211
    .line 212
    check-cast p0, Lyn/h;

    .line 213
    .line 214
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 215
    .line 216
    .line 217
    sget v0, Lun/b;->e:I

    .line 218
    .line 219
    new-instance v0, Lun/a;

    .line 220
    .line 221
    invoke-direct {v0}, Lun/a;-><init>()V

    .line 222
    .line 223
    .line 224
    iput-object v2, v0, Lun/a;->e:Ljava/lang/Object;

    .line 225
    .line 226
    new-instance v1, Ljava/util/ArrayList;

    .line 227
    .line 228
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 229
    .line 230
    .line 231
    iput-object v1, v0, Lun/a;->f:Ljava/lang/Object;

    .line 232
    .line 233
    iput-object v2, v0, Lun/a;->g:Ljava/lang/Object;

    .line 234
    .line 235
    const-string v1, ""

    .line 236
    .line 237
    iput-object v1, v0, Lun/a;->h:Ljava/lang/Object;

    .line 238
    .line 239
    new-instance v1, Ljava/util/HashMap;

    .line 240
    .line 241
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 242
    .line 243
    .line 244
    const-string v2, "SELECT log_source, reason, events_dropped_count FROM log_event_dropped"

    .line 245
    .line 246
    invoke-virtual {p0}, Lyn/h;->a()Landroid/database/sqlite/SQLiteDatabase;

    .line 247
    .line 248
    .line 249
    move-result-object v4

    .line 250
    invoke-virtual {v4}, Landroid/database/sqlite/SQLiteDatabase;->beginTransaction()V

    .line 251
    .line 252
    .line 253
    :try_start_5
    new-array v3, v3, [Ljava/lang/String;

    .line 254
    .line 255
    invoke-virtual {v4, v2, v3}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 256
    .line 257
    .line 258
    move-result-object v2

    .line 259
    new-instance v3, Lbb/i;

    .line 260
    .line 261
    const/16 v5, 0x11

    .line 262
    .line 263
    invoke-direct {v3, p0, v1, v0, v5}, Lbb/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 264
    .line 265
    .line 266
    invoke-static {v2, v3}, Lyn/h;->k(Landroid/database/Cursor;Lyn/f;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object p0

    .line 270
    check-cast p0, Lun/b;

    .line 271
    .line 272
    invoke-virtual {v4}, Landroid/database/sqlite/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 273
    .line 274
    .line 275
    invoke-virtual {v4}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 276
    .line 277
    .line 278
    return-object p0

    .line 279
    :catchall_3
    move-exception p0

    .line 280
    invoke-virtual {v4}, Landroid/database/sqlite/SQLiteDatabase;->endTransaction()V

    .line 281
    .line 282
    .line 283
    throw p0

    .line 284
    nop

    .line 285
    :pswitch_data_0
    .packed-switch 0x11
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public f(Ljava/lang/String;)V
    .locals 1

    .line 1
    iget v0, p0, Lrx/b;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lrx/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    sparse-switch v0, :sswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lcz/myskoda/api/bff_maps/v3/infrastructure/ApiClient;

    .line 9
    .line 10
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_maps/v3/infrastructure/ApiClient;->d(Lcz/myskoda/api/bff_maps/v3/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :sswitch_0
    check-cast p0, Lcz/myskoda/api/bff_maps/v2/infrastructure/ApiClient;

    .line 15
    .line 16
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_maps/v2/infrastructure/ApiClient;->b(Lcz/myskoda/api/bff_maps/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :sswitch_1
    check-cast p0, Lcz/myskoda/api/bff_manuals/v2/infrastructure/ApiClient;

    .line 21
    .line 22
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_manuals/v2/infrastructure/ApiClient;->e(Lcz/myskoda/api/bff_manuals/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :sswitch_2
    check-cast p0, Lcz/myskoda/api/bff_loyalty_program/v2/infrastructure/ApiClient;

    .line 27
    .line 28
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_loyalty_program/v2/infrastructure/ApiClient;->d(Lcz/myskoda/api/bff_loyalty_program/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :sswitch_3
    check-cast p0, Lcz/myskoda/api/bff_garage/v2/infrastructure/ApiClient;

    .line 33
    .line 34
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_garage/v2/infrastructure/ApiClient;->b(Lcz/myskoda/api/bff_garage/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :sswitch_4
    check-cast p0, Lcz/myskoda/api/bff_fueling/v2/infrastructure/ApiClient;

    .line 39
    .line 40
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_fueling/v2/infrastructure/ApiClient;->b(Lcz/myskoda/api/bff_fueling/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    :sswitch_5
    check-cast p0, Lcz/myskoda/api/bff_feedbacks/v2/infrastructure/ApiClient;

    .line 45
    .line 46
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_feedbacks/v2/infrastructure/ApiClient;->c(Lcz/myskoda/api/bff_feedbacks/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :sswitch_6
    check-cast p0, Lcz/myskoda/api/bff_dealers/v2/infrastructure/ApiClient;

    .line 51
    .line 52
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_dealers/v2/infrastructure/ApiClient;->e(Lcz/myskoda/api/bff_dealers/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    return-void

    .line 56
    :sswitch_7
    check-cast p0, Lcz/myskoda/api/bff_data_plan/v2/infrastructure/ApiClient;

    .line 57
    .line 58
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_data_plan/v2/infrastructure/ApiClient;->d(Lcz/myskoda/api/bff_data_plan/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    nop

    .line 63
    :sswitch_data_0
    .sparse-switch
        0x0 -> :sswitch_7
        0x1 -> :sswitch_6
        0x3 -> :sswitch_5
        0x8 -> :sswitch_4
        0xe -> :sswitch_3
        0x10 -> :sswitch_2
        0x15 -> :sswitch_1
        0x17 -> :sswitch_0
    .end sparse-switch
.end method

.method public h(Ly4/h;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lrx/b;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lrx/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    sparse-switch v0, :sswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lu/k;

    .line 9
    .line 10
    iput-object p1, p0, Lu/k;->c:Ljava/lang/Object;

    .line 11
    .line 12
    new-instance p1, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v0, "RequestCompleteListener["

    .line 15
    .line 16
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string p0, "]"

    .line 23
    .line 24
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :sswitch_0
    check-cast p0, Lw0/r;

    .line 33
    .line 34
    iget-object p0, p0, Lw0/r;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 35
    .line 36
    invoke-virtual {p0, p1}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    const-string p0, "textureViewImpl_waitForNextFrame"

    .line 40
    .line 41
    return-object p0

    .line 42
    :sswitch_1
    check-cast p0, Lb0/d1;

    .line 43
    .line 44
    iget-object v0, p0, Lb0/d1;->j:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v0, Ljava/util/concurrent/Executor;

    .line 47
    .line 48
    new-instance v1, Lno/nordicsemi/android/ble/o0;

    .line 49
    .line 50
    const/16 v2, 0x12

    .line 51
    .line 52
    invoke-direct {v1, v2, p0, p1}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 56
    .line 57
    .line 58
    const-string p0, "FetchData for CameraAvailability"

    .line 59
    .line 60
    return-object p0

    .line 61
    :sswitch_2
    check-cast p0, Lu/m;

    .line 62
    .line 63
    iget-object v0, p0, Lu/m;->c:Lj0/h;

    .line 64
    .line 65
    new-instance v1, Lno/nordicsemi/android/ble/o0;

    .line 66
    .line 67
    const/16 v2, 0xd

    .line 68
    .line 69
    invoke-direct {v1, v2, p0, p1}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0, v1}, Lj0/h;->execute(Ljava/lang/Runnable;)V

    .line 73
    .line 74
    .line 75
    const-string p0, "updateSessionConfigAsync"

    .line 76
    .line 77
    return-object p0

    .line 78
    nop

    .line 79
    :sswitch_data_0
    .sparse-switch
        0x4 -> :sswitch_2
        0x6 -> :sswitch_1
        0xf -> :sswitch_0
    .end sparse-switch
.end method
