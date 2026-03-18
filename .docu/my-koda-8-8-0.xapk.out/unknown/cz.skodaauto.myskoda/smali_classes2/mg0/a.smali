.class public final Lmg0/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Lmg0/e;

.field public e:J

.field public f:I

.field public final synthetic g:Lmg0/e;

.field public final synthetic h:J

.field public final synthetic i:Llg0/f;


# direct methods
.method public constructor <init>(Lmg0/e;JLlg0/f;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lmg0/a;->g:Lmg0/e;

    .line 2
    .line 3
    iput-wide p2, p0, Lmg0/a;->h:J

    .line 4
    .line 5
    iput-object p4, p0, Lmg0/a;->i:Llg0/f;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6

    .line 1
    new-instance v0, Lmg0/a;

    .line 2
    .line 3
    iget-wide v2, p0, Lmg0/a;->h:J

    .line 4
    .line 5
    iget-object v4, p0, Lmg0/a;->i:Llg0/f;

    .line 6
    .line 7
    iget-object v1, p0, Lmg0/a;->g:Lmg0/e;

    .line 8
    .line 9
    move-object v5, p2

    .line 10
    invoke-direct/range {v0 .. v5}, Lmg0/a;-><init>(Lmg0/e;JLlg0/f;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lmg0/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lmg0/a;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lmg0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 38

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Lmg0/a;->f:I

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    if-eqz v2, :cond_1

    .line 9
    .line 10
    if-ne v2, v3, :cond_0

    .line 11
    .line 12
    iget-wide v1, v0, Lmg0/a;->e:J

    .line 13
    .line 14
    iget-object v0, v0, Lmg0/a;->d:Lmg0/e;

    .line 15
    .line 16
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    goto/16 :goto_5

    .line 20
    .line 21
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw v0

    .line 29
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object v2, v0, Lmg0/a;->g:Lmg0/e;

    .line 33
    .line 34
    iget-object v4, v2, Lmg0/e;->d:Ljava/util/concurrent/ConcurrentHashMap;

    .line 35
    .line 36
    new-instance v5, Ljava/lang/Long;

    .line 37
    .line 38
    iget-wide v6, v0, Lmg0/a;->h:J

    .line 39
    .line 40
    invoke-direct {v5, v6, v7}, Ljava/lang/Long;-><init>(J)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v4, v5}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    check-cast v4, Llg0/d;

    .line 48
    .line 49
    if-eqz v4, :cond_d

    .line 50
    .line 51
    iget-object v5, v2, Lmg0/e;->c:Lgm0/m;

    .line 52
    .line 53
    iget-object v8, v2, Lmg0/e;->a:Landroid/app/DownloadManager;

    .line 54
    .line 55
    new-instance v9, Landroid/app/DownloadManager$Query;

    .line 56
    .line 57
    invoke-direct {v9}, Landroid/app/DownloadManager$Query;-><init>()V

    .line 58
    .line 59
    .line 60
    new-array v10, v3, [J

    .line 61
    .line 62
    const/4 v11, 0x0

    .line 63
    aput-wide v6, v10, v11

    .line 64
    .line 65
    invoke-virtual {v9, v10}, Landroid/app/DownloadManager$Query;->setFilterById([J)Landroid/app/DownloadManager$Query;

    .line 66
    .line 67
    .line 68
    move-result-object v9

    .line 69
    invoke-virtual {v8, v9}, Landroid/app/DownloadManager;->query(Landroid/app/DownloadManager$Query;)Landroid/database/Cursor;

    .line 70
    .line 71
    .line 72
    move-result-object v8

    .line 73
    :try_start_0
    invoke-interface {v8}, Landroid/database/Cursor;->moveToFirst()Z

    .line 74
    .line 75
    .line 76
    move-result v9

    .line 77
    const/4 v10, 0x0

    .line 78
    const/4 v12, -0x1

    .line 79
    if-eqz v9, :cond_4

    .line 80
    .line 81
    const-string v9, "reason"

    .line 82
    .line 83
    invoke-interface {v8, v9}, Landroid/database/Cursor;->getColumnIndex(Ljava/lang/String;)I

    .line 84
    .line 85
    .line 86
    move-result v9

    .line 87
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 88
    .line 89
    .line 90
    move-result-object v13

    .line 91
    if-ltz v9, :cond_2

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_2
    move-object v13, v10

    .line 95
    :goto_0
    if-eqz v13, :cond_3

    .line 96
    .line 97
    invoke-virtual {v13}, Ljava/lang/Integer;->intValue()I

    .line 98
    .line 99
    .line 100
    move-result v12

    .line 101
    goto :goto_1

    .line 102
    :catchall_0
    move-exception v0

    .line 103
    move-object v1, v0

    .line 104
    goto/16 :goto_6

    .line 105
    .line 106
    :cond_3
    :goto_1
    invoke-interface {v8, v12}, Landroid/database/Cursor;->getInt(I)I

    .line 107
    .line 108
    .line 109
    move-result v12
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 110
    :cond_4
    invoke-interface {v8}, Ljava/io/Closeable;->close()V

    .line 111
    .line 112
    .line 113
    iget-object v8, v0, Lmg0/a;->i:Llg0/f;

    .line 114
    .line 115
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 116
    .line 117
    .line 118
    move-result v9

    .line 119
    const/4 v13, 0x2

    .line 120
    const/4 v14, 0x5

    .line 121
    const/4 v15, 0x3

    .line 122
    if-eqz v9, :cond_9

    .line 123
    .line 124
    if-eq v9, v3, :cond_8

    .line 125
    .line 126
    if-eq v9, v13, :cond_7

    .line 127
    .line 128
    if-eq v9, v15, :cond_6

    .line 129
    .line 130
    const/4 v11, 0x4

    .line 131
    if-eq v9, v11, :cond_6

    .line 132
    .line 133
    if-ne v9, v14, :cond_5

    .line 134
    .line 135
    sget-object v9, Lhm0/d;->e:Lhm0/d;

    .line 136
    .line 137
    :goto_2
    move-object/from16 v32, v9

    .line 138
    .line 139
    goto :goto_3

    .line 140
    :cond_5
    new-instance v0, La8/r0;

    .line 141
    .line 142
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 143
    .line 144
    .line 145
    throw v0

    .line 146
    :cond_6
    sget-object v9, Lhm0/d;->f:Lhm0/d;

    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_7
    sget-object v9, Lhm0/d;->d:Lhm0/d;

    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_8
    sget-object v9, Lhm0/d;->g:Lhm0/d;

    .line 153
    .line 154
    goto :goto_2

    .line 155
    :cond_9
    sget-object v9, Lhm0/d;->d:Lhm0/d;

    .line 156
    .line 157
    goto :goto_2

    .line 158
    :goto_3
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 159
    .line 160
    .line 161
    move-result v8

    .line 162
    if-eqz v8, :cond_b

    .line 163
    .line 164
    if-eq v8, v15, :cond_b

    .line 165
    .line 166
    if-eq v8, v14, :cond_a

    .line 167
    .line 168
    const/16 v22, 0x0

    .line 169
    .line 170
    goto :goto_4

    .line 171
    :cond_a
    const/16 v11, 0xc8

    .line 172
    .line 173
    move/from16 v22, v11

    .line 174
    .line 175
    goto :goto_4

    .line 176
    :cond_b
    move/from16 v22, v12

    .line 177
    .line 178
    :goto_4
    iget-wide v8, v4, Llg0/d;->a:J

    .line 179
    .line 180
    iget-object v11, v4, Llg0/d;->b:Ljava/lang/String;

    .line 181
    .line 182
    iget-object v12, v4, Llg0/d;->d:Ljava/lang/String;

    .line 183
    .line 184
    iget-wide v14, v4, Llg0/d;->e:J

    .line 185
    .line 186
    const-string v4, "requestHeaders"

    .line 187
    .line 188
    invoke-static {v11, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    const-string v4, "requestUrl"

    .line 192
    .line 193
    invoke-static {v12, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    new-instance v16, Lhm0/b;

    .line 197
    .line 198
    const/16 v34, 0x0

    .line 199
    .line 200
    const v37, 0x93eb

    .line 201
    .line 202
    .line 203
    const/16 v17, 0x0

    .line 204
    .line 205
    const/16 v18, 0x0

    .line 206
    .line 207
    const/16 v21, 0x0

    .line 208
    .line 209
    const/16 v23, 0x0

    .line 210
    .line 211
    const/16 v24, 0x0

    .line 212
    .line 213
    const-wide/16 v25, 0x0

    .line 214
    .line 215
    const/16 v27, 0x0

    .line 216
    .line 217
    const/16 v28, 0x0

    .line 218
    .line 219
    const-string v30, "GET"

    .line 220
    .line 221
    const/16 v31, 0x0

    .line 222
    .line 223
    move-wide/from16 v19, v8

    .line 224
    .line 225
    move-object/from16 v29, v11

    .line 226
    .line 227
    move-object/from16 v33, v12

    .line 228
    .line 229
    move-wide/from16 v35, v14

    .line 230
    .line 231
    invoke-direct/range {v16 .. v37}, Lhm0/b;-><init>(Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;ILjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lhm0/d;Ljava/lang/String;Lhm0/c;JI)V

    .line 232
    .line 233
    .line 234
    move-object/from16 v4, v16

    .line 235
    .line 236
    iput-object v2, v0, Lmg0/a;->d:Lmg0/e;

    .line 237
    .line 238
    iput-wide v6, v0, Lmg0/a;->e:J

    .line 239
    .line 240
    iput v3, v0, Lmg0/a;->f:I

    .line 241
    .line 242
    iget-object v3, v5, Lgm0/m;->a:Lem0/m;

    .line 243
    .line 244
    sget-object v5, Lge0/b;->a:Lcz0/e;

    .line 245
    .line 246
    new-instance v8, Le60/m;

    .line 247
    .line 248
    invoke-direct {v8, v13, v3, v4, v10}, Le60/m;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 249
    .line 250
    .line 251
    invoke-static {v5, v8, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v0

    .line 255
    if-ne v0, v1, :cond_c

    .line 256
    .line 257
    return-object v1

    .line 258
    :cond_c
    move-object v0, v2

    .line 259
    move-wide v1, v6

    .line 260
    :goto_5
    iget-object v0, v0, Lmg0/e;->d:Ljava/util/concurrent/ConcurrentHashMap;

    .line 261
    .line 262
    new-instance v3, Ljava/lang/Long;

    .line 263
    .line 264
    invoke-direct {v3, v1, v2}, Ljava/lang/Long;-><init>(J)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v0, v3}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    goto :goto_7

    .line 271
    :goto_6
    :try_start_1
    throw v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 272
    :catchall_1
    move-exception v0

    .line 273
    invoke-static {v8, v1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 274
    .line 275
    .line 276
    throw v0

    .line 277
    :cond_d
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 278
    .line 279
    return-object v0
.end method
