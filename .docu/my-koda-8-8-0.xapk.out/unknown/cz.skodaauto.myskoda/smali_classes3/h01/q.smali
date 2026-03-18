.class public final Lh01/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llp/kg;
.implements Ld01/k;


# instance fields
.field public final synthetic d:I

.field public e:J

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x5

    iput v0, p0, Lh01/q;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(JLandroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lh01/q;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p4, p0, Lh01/q;->f:Ljava/lang/Object;

    iput-object p5, p0, Lh01/q;->g:Ljava/lang/Object;

    iput-object p3, p0, Lh01/q;->h:Ljava/lang/Object;

    iput-wide p1, p0, Lh01/q;->e:J

    return-void
.end method

.method public constructor <init>(Ld01/k;Lyt/h;Lzt/h;J)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Lh01/q;->d:I

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    iput-object p1, p0, Lh01/q;->f:Ljava/lang/Object;

    .line 14
    new-instance p1, Ltt/e;

    invoke-direct {p1, p2}, Ltt/e;-><init>(Lyt/h;)V

    .line 15
    iput-object p1, p0, Lh01/q;->g:Ljava/lang/Object;

    .line 16
    iput-wide p4, p0, Lh01/q;->e:J

    .line 17
    iput-object p3, p0, Lh01/q;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lg01/c;)V
    .locals 3

    const/4 v0, 0x0

    iput v0, p0, Lh01/q;->d:I

    sget-object v0, Ljava/util/concurrent/TimeUnit;->MINUTES:Ljava/util/concurrent/TimeUnit;

    const-string v1, "taskRunner"

    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "timeUnit"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-wide/16 v1, 0x5

    .line 6
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide v0

    iput-wide v0, p0, Lh01/q;->e:J

    .line 7
    invoke-virtual {p1}, Lg01/c;->d()Lg01/b;

    move-result-object p1

    iput-object p1, p0, Lh01/q;->f:Ljava/lang/Object;

    .line 8
    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v0, Le01/g;->b:Ljava/lang/String;

    const-string v1, " ConnectionPool connection closer"

    .line 9
    invoke-static {p1, v0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 10
    new-instance v0, Lf01/e;

    const/4 v1, 0x2

    invoke-direct {v0, p1, v1, p0}, Lf01/e;-><init>(Ljava/lang/String;ILjava/lang/Object;)V

    iput-object v0, p0, Lh01/q;->g:Ljava/lang/Object;

    .line 11
    new-instance p1, Ljava/util/concurrent/ConcurrentLinkedQueue;

    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentLinkedQueue;-><init>()V

    iput-object p1, p0, Lh01/q;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lpv/a;JLlp/tb;Lmv/a;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lh01/q;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh01/q;->f:Ljava/lang/Object;

    iput-wide p2, p0, Lh01/q;->e:J

    iput-object p4, p0, Lh01/q;->g:Ljava/lang/Object;

    iput-object p5, p0, Lh01/q;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lvp/d;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Lh01/q;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh01/q;->h:Ljava/lang/Object;

    return-void
.end method

.method public static d(Lvp/t;)Lh01/q;
    .locals 6

    .line 1
    new-instance v0, Lh01/q;

    .line 2
    .line 3
    iget-object v4, p0, Lvp/t;->d:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v5, p0, Lvp/t;->f:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v1, p0, Lvp/t;->e:Lvp/s;

    .line 8
    .line 9
    invoke-virtual {v1}, Lvp/s;->A0()Landroid/os/Bundle;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    iget-wide v1, p0, Lvp/t;->g:J

    .line 14
    .line 15
    invoke-direct/range {v0 .. v5}, Lh01/q;-><init>(JLandroid/os/Bundle;Ljava/lang/String;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method


# virtual methods
.method public a(Lh01/p;J)I
    .locals 6

    .line 1
    sget-object v0, Le01/g;->a:Ljava/util/TimeZone;

    .line 2
    .line 3
    iget-object v0, p1, Lh01/p;->p:Ljava/util/ArrayList;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    move v2, v1

    .line 7
    :cond_0
    :goto_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    if-ge v2, v3, :cond_2

    .line 12
    .line 13
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    check-cast v3, Ljava/lang/ref/Reference;

    .line 18
    .line 19
    invoke-virtual {v3}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    if-eqz v4, :cond_1

    .line 24
    .line 25
    add-int/lit8 v2, v2, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    check-cast v3, Lh01/m;

    .line 29
    .line 30
    new-instance v4, Ljava/lang/StringBuilder;

    .line 31
    .line 32
    const-string v5, "A connection to "

    .line 33
    .line 34
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget-object v5, p1, Lh01/p;->c:Ld01/w0;

    .line 38
    .line 39
    iget-object v5, v5, Ld01/w0;->a:Ld01/a;

    .line 40
    .line 41
    iget-object v5, v5, Ld01/a;->h:Ld01/a0;

    .line 42
    .line 43
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    const-string v5, " was leaked. Did you forget to close a response body?"

    .line 47
    .line 48
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    sget-object v5, Ln01/d;->a:Ln01/b;

    .line 56
    .line 57
    sget-object v5, Ln01/d;->a:Ln01/b;

    .line 58
    .line 59
    iget-object v3, v3, Lh01/m;->a:Ljava/lang/Object;

    .line 60
    .line 61
    invoke-virtual {v5, v3, v4}, Ln01/b;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    if-eqz v3, :cond_0

    .line 72
    .line 73
    iget-wide v2, p0, Lh01/q;->e:J

    .line 74
    .line 75
    sub-long/2addr p2, v2

    .line 76
    iput-wide p2, p1, Lh01/p;->q:J

    .line 77
    .line 78
    return v1

    .line 79
    :cond_2
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    return p0
.end method

.method public b(Lcom/google/android/gms/internal/measurement/b3;Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/b3;
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v5, p1

    .line 4
    .line 5
    move-object/from16 v7, p2

    .line 6
    .line 7
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/b3;->s()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v6

    .line 11
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/b3;->p()Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object v12

    .line 15
    iget-object v0, v1, Lh01/q;->h:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lvp/d;

    .line 18
    .line 19
    iget-object v2, v0, Lvp/q3;->f:Lvp/z3;

    .line 20
    .line 21
    iget-object v3, v0, Lvp/q3;->f:Lvp/z3;

    .line 22
    .line 23
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v4, v0

    .line 26
    check-cast v4, Lvp/g1;

    .line 27
    .line 28
    invoke-virtual {v2}, Lvp/z3;->i0()Lvp/s0;

    .line 29
    .line 30
    .line 31
    const-string v8, "_eid"

    .line 32
    .line 33
    invoke-static {v5, v8}, Lvp/s0;->i0(Lcom/google/android/gms/internal/measurement/b3;Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/e3;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    const/4 v9, 0x0

    .line 38
    if-nez v0, :cond_0

    .line 39
    .line 40
    move-object v0, v9

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    invoke-static {v0}, Lvp/s0;->p0(Lcom/google/android/gms/internal/measurement/e3;)Ljava/io/Serializable;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    :goto_0
    move-object v10, v0

    .line 47
    check-cast v10, Ljava/lang/Long;

    .line 48
    .line 49
    if-eqz v10, :cond_11

    .line 50
    .line 51
    const-string v0, "_ep"

    .line 52
    .line 53
    invoke-virtual {v6, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_e

    .line 58
    .line 59
    invoke-virtual {v2}, Lvp/z3;->i0()Lvp/s0;

    .line 60
    .line 61
    .line 62
    const-string v0, "_en"

    .line 63
    .line 64
    invoke-static {v5, v0}, Lvp/s0;->i0(Lcom/google/android/gms/internal/measurement/b3;Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/e3;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    if-nez v0, :cond_1

    .line 69
    .line 70
    move-object v0, v9

    .line 71
    goto :goto_1

    .line 72
    :cond_1
    invoke-static {v0}, Lvp/s0;->p0(Lcom/google/android/gms/internal/measurement/e3;)Ljava/io/Serializable;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    :goto_1
    move-object v15, v0

    .line 77
    check-cast v15, Ljava/lang/String;

    .line 78
    .line 79
    invoke-static {v15}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    if-eqz v0, :cond_2

    .line 84
    .line 85
    iget-object v0, v4, Lvp/g1;->i:Lvp/p0;

    .line 86
    .line 87
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 88
    .line 89
    .line 90
    iget-object v0, v0, Lvp/p0;->k:Lvp/n0;

    .line 91
    .line 92
    const-string v1, "Extra parameter without an event name. eventId"

    .line 93
    .line 94
    invoke-virtual {v0, v10, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    return-object v9

    .line 98
    :cond_2
    iget-object v0, v1, Lh01/q;->f:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v0, Lcom/google/android/gms/internal/measurement/b3;

    .line 101
    .line 102
    if-eqz v0, :cond_4

    .line 103
    .line 104
    iget-object v0, v1, Lh01/q;->g:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v0, Ljava/lang/Long;

    .line 107
    .line 108
    if-eqz v0, :cond_4

    .line 109
    .line 110
    invoke-virtual {v10}, Ljava/lang/Long;->longValue()J

    .line 111
    .line 112
    .line 113
    move-result-wide v16

    .line 114
    iget-object v0, v1, Lh01/q;->g:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast v0, Ljava/lang/Long;

    .line 117
    .line 118
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 119
    .line 120
    .line 121
    move-result-wide v18

    .line 122
    cmp-long v0, v16, v18

    .line 123
    .line 124
    if-eqz v0, :cond_3

    .line 125
    .line 126
    goto :goto_2

    .line 127
    :cond_3
    const-wide/16 v17, 0x0

    .line 128
    .line 129
    goto/16 :goto_b

    .line 130
    .line 131
    :cond_4
    :goto_2
    iget-object v0, v2, Lvp/z3;->f:Lvp/n;

    .line 132
    .line 133
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 134
    .line 135
    .line 136
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v2, Lvp/g1;

    .line 139
    .line 140
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v0}, Lvp/u3;->b0()V

    .line 144
    .line 145
    .line 146
    :try_start_0
    invoke-virtual {v0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    const-string v6, "select main_event, children_to_process from main_event_params where app_id=? and event_id=?"

    .line 151
    .line 152
    invoke-virtual {v10}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v11

    .line 156
    filled-new-array {v7, v11}, [Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object v11

    .line 160
    invoke-virtual {v0, v6, v11}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 161
    .line 162
    .line 163
    move-result-object v6
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_4
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 164
    :try_start_1
    invoke-interface {v6}, Landroid/database/Cursor;->moveToFirst()Z

    .line 165
    .line 166
    .line 167
    move-result v0

    .line 168
    if-nez v0, :cond_5

    .line 169
    .line 170
    iget-object v0, v2, Lvp/g1;->i:Lvp/p0;

    .line 171
    .line 172
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 173
    .line 174
    .line 175
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 176
    .line 177
    const-string v11, "Main event not found"

    .line 178
    .line 179
    invoke-virtual {v0, v11}, Lvp/n0;->a(Ljava/lang/String;)V
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 180
    .line 181
    .line 182
    invoke-interface {v6}, Landroid/database/Cursor;->close()V

    .line 183
    .line 184
    .line 185
    move-object v0, v9

    .line 186
    move-object/from16 v16, v0

    .line 187
    .line 188
    :goto_3
    const-wide/16 v17, 0x0

    .line 189
    .line 190
    goto/16 :goto_a

    .line 191
    .line 192
    :catchall_0
    move-exception v0

    .line 193
    goto :goto_6

    .line 194
    :catch_0
    move-exception v0

    .line 195
    move-object/from16 v16, v9

    .line 196
    .line 197
    goto :goto_5

    .line 198
    :cond_5
    const/4 v0, 0x0

    .line 199
    :try_start_2
    invoke-interface {v6, v0}, Landroid/database/Cursor;->getBlob(I)[B

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    const/4 v11, 0x1

    .line 204
    invoke-interface {v6, v11}, Landroid/database/Cursor;->getLong(I)J

    .line 205
    .line 206
    .line 207
    move-result-wide v16

    .line 208
    invoke-static/range {v16 .. v17}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 209
    .line 210
    .line 211
    move-result-object v11
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 212
    move-object/from16 v16, v9

    .line 213
    .line 214
    :try_start_3
    invoke-static {}, Lcom/google/android/gms/internal/measurement/b3;->z()Lcom/google/android/gms/internal/measurement/a3;

    .line 215
    .line 216
    .line 217
    move-result-object v9

    .line 218
    invoke-static {v9, v0}, Lvp/s0;->N0(Lcom/google/android/gms/internal/measurement/k5;[B)Lcom/google/android/gms/internal/measurement/k5;

    .line 219
    .line 220
    .line 221
    move-result-object v0

    .line 222
    check-cast v0, Lcom/google/android/gms/internal/measurement/a3;

    .line 223
    .line 224
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 225
    .line 226
    .line 227
    move-result-object v0

    .line 228
    check-cast v0, Lcom/google/android/gms/internal/measurement/b3;
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_3 .. :try_end_3} :catch_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 229
    .line 230
    :try_start_4
    invoke-static {v0, v11}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 231
    .line 232
    .line 233
    move-result-object v0
    :try_end_4
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_4 .. :try_end_4} :catch_3
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 234
    invoke-interface {v6}, Landroid/database/Cursor;->close()V

    .line 235
    .line 236
    .line 237
    goto :goto_3

    .line 238
    :catch_1
    move-exception v0

    .line 239
    :try_start_5
    iget-object v9, v2, Lvp/g1;->i:Lvp/p0;

    .line 240
    .line 241
    invoke-static {v9}, Lvp/g1;->k(Lvp/n1;)V

    .line 242
    .line 243
    .line 244
    iget-object v9, v9, Lvp/p0;->j:Lvp/n0;

    .line 245
    .line 246
    const-string v11, "Failed to merge main event. appId, eventId"
    :try_end_5
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_5 .. :try_end_5} :catch_3
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 247
    .line 248
    const-wide/16 v17, 0x0

    .line 249
    .line 250
    :try_start_6
    invoke-static {v7}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 251
    .line 252
    .line 253
    move-result-object v13

    .line 254
    invoke-virtual {v9, v11, v13, v10, v0}, Lvp/n0;->d(Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_6
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_6 .. :try_end_6} :catch_2
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 255
    .line 256
    .line 257
    :goto_4
    invoke-interface {v6}, Landroid/database/Cursor;->close()V

    .line 258
    .line 259
    .line 260
    :cond_6
    move-object/from16 v0, v16

    .line 261
    .line 262
    goto :goto_a

    .line 263
    :catch_2
    move-exception v0

    .line 264
    goto :goto_9

    .line 265
    :catch_3
    move-exception v0

    .line 266
    :goto_5
    const-wide/16 v17, 0x0

    .line 267
    .line 268
    goto :goto_9

    .line 269
    :goto_6
    move-object v9, v6

    .line 270
    goto/16 :goto_10

    .line 271
    .line 272
    :catchall_1
    move-exception v0

    .line 273
    move-object/from16 v16, v9

    .line 274
    .line 275
    goto :goto_7

    .line 276
    :catch_4
    move-exception v0

    .line 277
    move-object/from16 v16, v9

    .line 278
    .line 279
    const-wide/16 v17, 0x0

    .line 280
    .line 281
    goto :goto_8

    .line 282
    :goto_7
    move-object/from16 v9, v16

    .line 283
    .line 284
    goto/16 :goto_10

    .line 285
    .line 286
    :goto_8
    move-object/from16 v6, v16

    .line 287
    .line 288
    :goto_9
    :try_start_7
    iget-object v2, v2, Lvp/g1;->i:Lvp/p0;

    .line 289
    .line 290
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 291
    .line 292
    .line 293
    iget-object v2, v2, Lvp/p0;->j:Lvp/n0;

    .line 294
    .line 295
    const-string v9, "Error selecting main event"

    .line 296
    .line 297
    invoke-virtual {v2, v0, v9}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 298
    .line 299
    .line 300
    if-eqz v6, :cond_6

    .line 301
    .line 302
    goto :goto_4

    .line 303
    :goto_a
    if-eqz v0, :cond_7

    .line 304
    .line 305
    iget-object v2, v0, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 306
    .line 307
    if-nez v2, :cond_8

    .line 308
    .line 309
    :cond_7
    move-object v8, v10

    .line 310
    goto/16 :goto_f

    .line 311
    .line 312
    :cond_8
    check-cast v2, Lcom/google/android/gms/internal/measurement/b3;

    .line 313
    .line 314
    iput-object v2, v1, Lh01/q;->f:Ljava/lang/Object;

    .line 315
    .line 316
    iget-object v0, v0, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 317
    .line 318
    check-cast v0, Ljava/lang/Long;

    .line 319
    .line 320
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 321
    .line 322
    .line 323
    move-result-wide v13

    .line 324
    iput-wide v13, v1, Lh01/q;->e:J

    .line 325
    .line 326
    invoke-virtual {v3}, Lvp/z3;->i0()Lvp/s0;

    .line 327
    .line 328
    .line 329
    iget-object v0, v1, Lh01/q;->f:Ljava/lang/Object;

    .line 330
    .line 331
    check-cast v0, Lcom/google/android/gms/internal/measurement/b3;

    .line 332
    .line 333
    invoke-static {v0, v8}, Lvp/s0;->j0(Lcom/google/android/gms/internal/measurement/b3;Ljava/lang/String;)Ljava/io/Serializable;

    .line 334
    .line 335
    .line 336
    move-result-object v0

    .line 337
    check-cast v0, Ljava/lang/Long;

    .line 338
    .line 339
    iput-object v0, v1, Lh01/q;->g:Ljava/lang/Object;

    .line 340
    .line 341
    :goto_b
    iget-wide v8, v1, Lh01/q;->e:J

    .line 342
    .line 343
    const-wide/16 v13, -0x1

    .line 344
    .line 345
    add-long/2addr v8, v13

    .line 346
    iput-wide v8, v1, Lh01/q;->e:J

    .line 347
    .line 348
    cmp-long v0, v8, v17

    .line 349
    .line 350
    if-gtz v0, :cond_9

    .line 351
    .line 352
    iget-object v0, v3, Lvp/z3;->f:Lvp/n;

    .line 353
    .line 354
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 355
    .line 356
    .line 357
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 358
    .line 359
    check-cast v2, Lvp/g1;

    .line 360
    .line 361
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 362
    .line 363
    .line 364
    iget-object v6, v2, Lvp/g1;->i:Lvp/p0;

    .line 365
    .line 366
    invoke-static {v6}, Lvp/g1;->k(Lvp/n1;)V

    .line 367
    .line 368
    .line 369
    iget-object v6, v6, Lvp/p0;->r:Lvp/n0;

    .line 370
    .line 371
    const-string v8, "Clearing complex main event info. appId"

    .line 372
    .line 373
    invoke-virtual {v6, v7, v8}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 374
    .line 375
    .line 376
    :try_start_8
    invoke-virtual {v0}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 377
    .line 378
    .line 379
    move-result-object v0

    .line 380
    const-string v6, "delete from main_event_params where app_id=?"

    .line 381
    .line 382
    filled-new-array {v7}, [Ljava/lang/String;

    .line 383
    .line 384
    .line 385
    move-result-object v7

    .line 386
    invoke-virtual {v0, v6, v7}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_8
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_8 .. :try_end_8} :catch_5

    .line 387
    .line 388
    .line 389
    goto :goto_c

    .line 390
    :catch_5
    move-exception v0

    .line 391
    iget-object v2, v2, Lvp/g1;->i:Lvp/p0;

    .line 392
    .line 393
    invoke-static {v2}, Lvp/g1;->k(Lvp/n1;)V

    .line 394
    .line 395
    .line 396
    iget-object v2, v2, Lvp/p0;->j:Lvp/n0;

    .line 397
    .line 398
    const-string v6, "Error clearing complex main event"

    .line 399
    .line 400
    invoke-virtual {v2, v0, v6}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 401
    .line 402
    .line 403
    goto :goto_c

    .line 404
    :cond_9
    iget-object v6, v3, Lvp/z3;->f:Lvp/n;

    .line 405
    .line 406
    invoke-static {v6}, Lvp/z3;->T(Lvp/u3;)V

    .line 407
    .line 408
    .line 409
    move-object v2, v10

    .line 410
    iget-wide v9, v1, Lh01/q;->e:J

    .line 411
    .line 412
    iget-object v0, v1, Lh01/q;->f:Ljava/lang/Object;

    .line 413
    .line 414
    move-object v11, v0

    .line 415
    check-cast v11, Lcom/google/android/gms/internal/measurement/b3;

    .line 416
    .line 417
    move-object v8, v2

    .line 418
    invoke-virtual/range {v6 .. v11}, Lvp/n;->r0(Ljava/lang/String;Ljava/lang/Long;JLcom/google/android/gms/internal/measurement/b3;)V

    .line 419
    .line 420
    .line 421
    :goto_c
    new-instance v0, Ljava/util/ArrayList;

    .line 422
    .line 423
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 424
    .line 425
    .line 426
    iget-object v1, v1, Lh01/q;->f:Ljava/lang/Object;

    .line 427
    .line 428
    check-cast v1, Lcom/google/android/gms/internal/measurement/b3;

    .line 429
    .line 430
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/b3;->p()Ljava/util/List;

    .line 431
    .line 432
    .line 433
    move-result-object v1

    .line 434
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 435
    .line 436
    .line 437
    move-result-object v1

    .line 438
    :cond_a
    :goto_d
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 439
    .line 440
    .line 441
    move-result v2

    .line 442
    if-eqz v2, :cond_b

    .line 443
    .line 444
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 445
    .line 446
    .line 447
    move-result-object v2

    .line 448
    check-cast v2, Lcom/google/android/gms/internal/measurement/e3;

    .line 449
    .line 450
    invoke-virtual {v3}, Lvp/z3;->i0()Lvp/s0;

    .line 451
    .line 452
    .line 453
    invoke-virtual {v2}, Lcom/google/android/gms/internal/measurement/e3;->q()Ljava/lang/String;

    .line 454
    .line 455
    .line 456
    move-result-object v6

    .line 457
    invoke-static {v5, v6}, Lvp/s0;->i0(Lcom/google/android/gms/internal/measurement/b3;Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/e3;

    .line 458
    .line 459
    .line 460
    move-result-object v6

    .line 461
    if-nez v6, :cond_a

    .line 462
    .line 463
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 464
    .line 465
    .line 466
    goto :goto_d

    .line 467
    :cond_b
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 468
    .line 469
    .line 470
    move-result v1

    .line 471
    if-nez v1, :cond_c

    .line 472
    .line 473
    invoke-virtual {v0, v12}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 474
    .line 475
    .line 476
    move-object v12, v0

    .line 477
    goto :goto_e

    .line 478
    :cond_c
    iget-object v0, v4, Lvp/g1;->i:Lvp/p0;

    .line 479
    .line 480
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 481
    .line 482
    .line 483
    iget-object v0, v0, Lvp/p0;->k:Lvp/n0;

    .line 484
    .line 485
    const-string v1, "No unique parameters in main event. eventName"

    .line 486
    .line 487
    invoke-virtual {v0, v15, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 488
    .line 489
    .line 490
    :goto_e
    move-object v6, v15

    .line 491
    goto :goto_12

    .line 492
    :goto_f
    iget-object v0, v4, Lvp/g1;->i:Lvp/p0;

    .line 493
    .line 494
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 495
    .line 496
    .line 497
    iget-object v0, v0, Lvp/p0;->k:Lvp/n0;

    .line 498
    .line 499
    const-string v1, "Extra parameter without existing main event. eventName, eventId"

    .line 500
    .line 501
    invoke-virtual {v0, v15, v8, v1}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 502
    .line 503
    .line 504
    return-object v16

    .line 505
    :goto_10
    if-eqz v9, :cond_d

    .line 506
    .line 507
    invoke-interface {v9}, Landroid/database/Cursor;->close()V

    .line 508
    .line 509
    .line 510
    :cond_d
    throw v0

    .line 511
    :cond_e
    move-object v8, v10

    .line 512
    const-wide/16 v17, 0x0

    .line 513
    .line 514
    iput-object v8, v1, Lh01/q;->g:Ljava/lang/Object;

    .line 515
    .line 516
    iput-object v5, v1, Lh01/q;->f:Ljava/lang/Object;

    .line 517
    .line 518
    invoke-virtual {v2}, Lvp/z3;->i0()Lvp/s0;

    .line 519
    .line 520
    .line 521
    invoke-static/range {v17 .. v18}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 522
    .line 523
    .line 524
    move-result-object v0

    .line 525
    const-string v3, "_epc"

    .line 526
    .line 527
    invoke-static {v5, v3}, Lvp/s0;->j0(Lcom/google/android/gms/internal/measurement/b3;Ljava/lang/String;)Ljava/io/Serializable;

    .line 528
    .line 529
    .line 530
    move-result-object v3

    .line 531
    if-nez v3, :cond_f

    .line 532
    .line 533
    goto :goto_11

    .line 534
    :cond_f
    move-object v0, v3

    .line 535
    :goto_11
    check-cast v0, Ljava/lang/Long;

    .line 536
    .line 537
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 538
    .line 539
    .line 540
    move-result-wide v9

    .line 541
    iput-wide v9, v1, Lh01/q;->e:J

    .line 542
    .line 543
    cmp-long v0, v9, v17

    .line 544
    .line 545
    if-gtz v0, :cond_10

    .line 546
    .line 547
    iget-object v0, v4, Lvp/g1;->i:Lvp/p0;

    .line 548
    .line 549
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 550
    .line 551
    .line 552
    iget-object v0, v0, Lvp/p0;->k:Lvp/n0;

    .line 553
    .line 554
    const-string v1, "Complex event with zero extra param count. eventName"

    .line 555
    .line 556
    invoke-virtual {v0, v6, v1}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 557
    .line 558
    .line 559
    goto :goto_12

    .line 560
    :cond_10
    iget-object v0, v2, Lvp/z3;->f:Lvp/n;

    .line 561
    .line 562
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 563
    .line 564
    .line 565
    iget-wide v3, v1, Lh01/q;->e:J

    .line 566
    .line 567
    move-object/from16 v1, p2

    .line 568
    .line 569
    move-object v2, v8

    .line 570
    invoke-virtual/range {v0 .. v5}, Lvp/n;->r0(Ljava/lang/String;Ljava/lang/Long;JLcom/google/android/gms/internal/measurement/b3;)V

    .line 571
    .line 572
    .line 573
    :cond_11
    :goto_12
    invoke-virtual/range {p1 .. p1}, Lcom/google/android/gms/internal/measurement/l5;->i()Lcom/google/android/gms/internal/measurement/k5;

    .line 574
    .line 575
    .line 576
    move-result-object v0

    .line 577
    check-cast v0, Lcom/google/android/gms/internal/measurement/a3;

    .line 578
    .line 579
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 580
    .line 581
    .line 582
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 583
    .line 584
    check-cast v1, Lcom/google/android/gms/internal/measurement/b3;

    .line 585
    .line 586
    invoke-virtual {v1, v6}, Lcom/google/android/gms/internal/measurement/b3;->F(Ljava/lang/String;)V

    .line 587
    .line 588
    .line 589
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 590
    .line 591
    .line 592
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 593
    .line 594
    check-cast v1, Lcom/google/android/gms/internal/measurement/b3;

    .line 595
    .line 596
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/b3;->D()V

    .line 597
    .line 598
    .line 599
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 600
    .line 601
    .line 602
    iget-object v1, v0, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 603
    .line 604
    check-cast v1, Lcom/google/android/gms/internal/measurement/b3;

    .line 605
    .line 606
    invoke-virtual {v1, v12}, Lcom/google/android/gms/internal/measurement/b3;->C(Ljava/lang/Iterable;)V

    .line 607
    .line 608
    .line 609
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 610
    .line 611
    .line 612
    move-result-object v0

    .line 613
    check-cast v0, Lcom/google/android/gms/internal/measurement/b3;

    .line 614
    .line 615
    return-object v0
.end method

.method public c()Lbb/g0;
    .locals 11

    .line 1
    iget-object v0, p0, Lh01/q;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lpv/a;

    .line 4
    .line 5
    iget-wide v1, p0, Lh01/q;->e:J

    .line 6
    .line 7
    iget-object v3, p0, Lh01/q;->g:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Llp/tb;

    .line 10
    .line 11
    iget-object p0, p0, Lh01/q;->h:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lmv/a;

    .line 14
    .line 15
    new-instance v4, Llp/f0;

    .line 16
    .line 17
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 18
    .line 19
    .line 20
    new-instance v5, Landroidx/lifecycle/c1;

    .line 21
    .line 22
    const/16 v6, 0x10

    .line 23
    .line 24
    invoke-direct {v5, v6}, Landroidx/lifecycle/c1;-><init>(I)V

    .line 25
    .line 26
    .line 27
    const-wide v6, 0x7fffffffffffffffL

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    and-long/2addr v1, v6

    .line 33
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    iput-object v1, v5, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 38
    .line 39
    iput-object v3, v5, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 40
    .line 41
    sget-boolean v1, Lpv/a;->m:Z

    .line 42
    .line 43
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    iput-object v1, v5, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 48
    .line 49
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 50
    .line 51
    iput-object v1, v5, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 52
    .line 53
    iput-object v1, v5, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 54
    .line 55
    new-instance v1, Llp/ib;

    .line 56
    .line 57
    invoke-direct {v1, v5}, Llp/ib;-><init>(Landroidx/lifecycle/c1;)V

    .line 58
    .line 59
    .line 60
    iput-object v1, v4, Llp/f0;->d:Ljava/lang/Object;

    .line 61
    .line 62
    iget v1, p0, Lmv/a;->f:I

    .line 63
    .line 64
    const/16 v2, 0x23

    .line 65
    .line 66
    const v3, 0x32315659

    .line 67
    .line 68
    .line 69
    const/16 v5, 0x11

    .line 70
    .line 71
    const/4 v6, 0x0

    .line 72
    const/4 v7, -0x1

    .line 73
    if-ne v1, v7, :cond_0

    .line 74
    .line 75
    iget-object p0, p0, Lmv/a;->a:Landroid/graphics/Bitmap;

    .line 76
    .line 77
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {p0}, Landroid/graphics/Bitmap;->getAllocationByteCount()I

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    goto :goto_0

    .line 85
    :cond_0
    if-eq v1, v5, :cond_8

    .line 86
    .line 87
    if-eq v1, v3, :cond_8

    .line 88
    .line 89
    if-eq v1, v2, :cond_1

    .line 90
    .line 91
    move p0, v6

    .line 92
    goto :goto_0

    .line 93
    :cond_1
    invoke-virtual {p0}, Lmv/a;->b()[Landroid/media/Image$Plane;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    aget-object p0, p0, v6

    .line 101
    .line 102
    invoke-virtual {p0}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-virtual {p0}, Ljava/nio/Buffer;->limit()I

    .line 107
    .line 108
    .line 109
    move-result p0

    .line 110
    mul-int/lit8 p0, p0, 0x3

    .line 111
    .line 112
    div-int/lit8 p0, p0, 0x2

    .line 113
    .line 114
    :goto_0
    new-instance v8, Lb81/c;

    .line 115
    .line 116
    const/16 v9, 0x10

    .line 117
    .line 118
    const/4 v10, 0x0

    .line 119
    invoke-direct {v8, v9, v10}, Lb81/c;-><init>(IZ)V

    .line 120
    .line 121
    .line 122
    if-eq v1, v7, :cond_6

    .line 123
    .line 124
    if-eq v1, v2, :cond_5

    .line 125
    .line 126
    if-eq v1, v3, :cond_4

    .line 127
    .line 128
    const/16 v2, 0x10

    .line 129
    .line 130
    if-eq v1, v2, :cond_3

    .line 131
    .line 132
    if-eq v1, v5, :cond_2

    .line 133
    .line 134
    sget-object v1, Llp/db;->e:Llp/db;

    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_2
    sget-object v1, Llp/db;->g:Llp/db;

    .line 138
    .line 139
    goto :goto_1

    .line 140
    :cond_3
    sget-object v1, Llp/db;->f:Llp/db;

    .line 141
    .line 142
    goto :goto_1

    .line 143
    :cond_4
    sget-object v1, Llp/db;->h:Llp/db;

    .line 144
    .line 145
    goto :goto_1

    .line 146
    :cond_5
    sget-object v1, Llp/db;->i:Llp/db;

    .line 147
    .line 148
    goto :goto_1

    .line 149
    :cond_6
    sget-object v1, Llp/db;->j:Llp/db;

    .line 150
    .line 151
    :goto_1
    iput-object v1, v8, Lb81/c;->e:Ljava/lang/Object;

    .line 152
    .line 153
    const v1, 0x7fffffff

    .line 154
    .line 155
    .line 156
    and-int/2addr p0, v1

    .line 157
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    iput-object p0, v8, Lb81/c;->f:Ljava/lang/Object;

    .line 162
    .line 163
    new-instance p0, Llp/eb;

    .line 164
    .line 165
    invoke-direct {p0, v8}, Llp/eb;-><init>(Lb81/c;)V

    .line 166
    .line 167
    .line 168
    iput-object p0, v4, Llp/f0;->e:Ljava/lang/Object;

    .line 169
    .line 170
    new-instance p0, Lh6/e;

    .line 171
    .line 172
    const/16 v1, 0x12

    .line 173
    .line 174
    invoke-direct {p0, v1}, Lh6/e;-><init>(I)V

    .line 175
    .line 176
    .line 177
    iget-object v1, v0, Lpv/a;->k:Lov/f;

    .line 178
    .line 179
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 180
    .line 181
    .line 182
    sget-object v1, Llp/ve;->e:Llp/ve;

    .line 183
    .line 184
    iput-object v1, p0, Lh6/e;->e:Ljava/lang/Object;

    .line 185
    .line 186
    new-instance v1, Llp/we;

    .line 187
    .line 188
    invoke-direct {v1, p0}, Llp/we;-><init>(Lh6/e;)V

    .line 189
    .line 190
    .line 191
    iput-object v1, v4, Llp/f0;->f:Ljava/lang/Object;

    .line 192
    .line 193
    new-instance p0, Llp/ue;

    .line 194
    .line 195
    invoke-direct {p0, v4}, Llp/ue;-><init>(Llp/f0;)V

    .line 196
    .line 197
    .line 198
    new-instance v1, Lin/z1;

    .line 199
    .line 200
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 201
    .line 202
    .line 203
    iget-object v0, v0, Lpv/a;->k:Lov/f;

    .line 204
    .line 205
    check-cast v0, Lqv/a;

    .line 206
    .line 207
    invoke-virtual {v0}, Lqv/a;->a()Z

    .line 208
    .line 209
    .line 210
    move-result v0

    .line 211
    if-eqz v0, :cond_7

    .line 212
    .line 213
    sget-object v0, Llp/sb;->f:Llp/sb;

    .line 214
    .line 215
    goto :goto_2

    .line 216
    :cond_7
    sget-object v0, Llp/sb;->e:Llp/sb;

    .line 217
    .line 218
    :goto_2
    iput-object v0, v1, Lin/z1;->c:Ljava/lang/Object;

    .line 219
    .line 220
    iput-object p0, v1, Lin/z1;->d:Ljava/lang/Object;

    .line 221
    .line 222
    new-instance p0, Lbb/g0;

    .line 223
    .line 224
    const/4 v0, 0x0

    .line 225
    invoke-direct {p0, v1, v6, v0}, Lbb/g0;-><init>(Lin/z1;IB)V

    .line 226
    .line 227
    .line 228
    return-object p0

    .line 229
    :cond_8
    const/4 p0, 0x0

    .line 230
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    throw p0
.end method

.method public e()Lvp/t;
    .locals 6

    .line 1
    new-instance v0, Lvp/t;

    .line 2
    .line 3
    new-instance v2, Lvp/s;

    .line 4
    .line 5
    new-instance v1, Landroid/os/Bundle;

    .line 6
    .line 7
    iget-object v3, p0, Lh01/q;->h:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Landroid/os/Bundle;

    .line 10
    .line 11
    invoke-direct {v1, v3}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 12
    .line 13
    .line 14
    invoke-direct {v2, v1}, Lvp/s;-><init>(Landroid/os/Bundle;)V

    .line 15
    .line 16
    .line 17
    iget-object v1, p0, Lh01/q;->g:Ljava/lang/Object;

    .line 18
    .line 19
    move-object v3, v1

    .line 20
    check-cast v3, Ljava/lang/String;

    .line 21
    .line 22
    iget-object v1, p0, Lh01/q;->f:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v1, Ljava/lang/String;

    .line 25
    .line 26
    iget-wide v4, p0, Lh01/q;->e:J

    .line 27
    .line 28
    invoke-direct/range {v0 .. v5}, Lvp/t;-><init>(Ljava/lang/String;Lvp/s;Ljava/lang/String;J)V

    .line 29
    .line 30
    .line 31
    return-object v0
.end method

.method public onFailure(Ld01/j;Ljava/io/IOException;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lh01/q;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ltt/e;

    .line 4
    .line 5
    invoke-interface {p1}, Ld01/j;->request()Ld01/k0;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    if-eqz v1, :cond_1

    .line 10
    .line 11
    iget-object v2, v1, Ld01/k0;->a:Ld01/a0;

    .line 12
    .line 13
    if-eqz v2, :cond_0

    .line 14
    .line 15
    invoke-virtual {v2}, Ld01/a0;->k()Ljava/net/URL;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    invoke-virtual {v2}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-virtual {v0, v2}, Ltt/e;->p(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    iget-object v1, v1, Ld01/k0;->b:Ljava/lang/String;

    .line 27
    .line 28
    if-eqz v1, :cond_1

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ltt/e;->i(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    :cond_1
    iget-wide v1, p0, Lh01/q;->e:J

    .line 34
    .line 35
    invoke-virtual {v0, v1, v2}, Ltt/e;->l(J)V

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lh01/q;->h:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v1, Lzt/h;

    .line 41
    .line 42
    invoke-static {v1, v0, v0}, Lvj/b;->A(Lzt/h;Ltt/e;Ltt/e;)V

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lh01/q;->f:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p0, Ld01/k;

    .line 48
    .line 49
    invoke-interface {p0, p1, p2}, Ld01/k;->onFailure(Ld01/j;Ljava/io/IOException;)V

    .line 50
    .line 51
    .line 52
    return-void
.end method

.method public onResponse(Ld01/j;Ld01/t0;)V
    .locals 7

    .line 1
    iget-object v0, p0, Lh01/q;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lzt/h;

    .line 4
    .line 5
    invoke-virtual {v0}, Lzt/h;->j()J

    .line 6
    .line 7
    .line 8
    move-result-wide v5

    .line 9
    iget-object v0, p0, Lh01/q;->g:Ljava/lang/Object;

    .line 10
    .line 11
    move-object v2, v0

    .line 12
    check-cast v2, Ltt/e;

    .line 13
    .line 14
    iget-wide v3, p0, Lh01/q;->e:J

    .line 15
    .line 16
    move-object v1, p2

    .line 17
    invoke-static/range {v1 .. v6}, Lcom/google/firebase/perf/network/FirebasePerfOkHttpClient;->a(Ld01/t0;Ltt/e;JJ)V

    .line 18
    .line 19
    .line 20
    iget-object p0, p0, Lh01/q;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Ld01/k;

    .line 23
    .line 24
    invoke-interface {p0, p1, v1}, Ld01/k;->onResponse(Ld01/j;Ld01/t0;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget v0, p0, Lh01/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object v0, p0, Lh01/q;->g:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Ljava/lang/String;

    .line 14
    .line 15
    iget-object v1, p0, Lh01/q;->h:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Landroid/os/Bundle;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    iget-object p0, p0, Lh01/q;->f:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    invoke-virtual {v3}, Ljava/lang/String;->length()I

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    add-int/lit8 v2, v2, 0xd

    .line 48
    .line 49
    add-int/2addr v2, v3

    .line 50
    new-instance v3, Ljava/lang/StringBuilder;

    .line 51
    .line 52
    add-int/lit8 v2, v2, 0x8

    .line 53
    .line 54
    add-int/2addr v2, v4

    .line 55
    invoke-direct {v3, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 56
    .line 57
    .line 58
    const-string v2, "origin="

    .line 59
    .line 60
    const-string v4, ",name="

    .line 61
    .line 62
    invoke-static {v3, v2, v0, v4, p0}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    const-string p0, ",params="

    .line 66
    .line 67
    invoke-static {v3, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method
