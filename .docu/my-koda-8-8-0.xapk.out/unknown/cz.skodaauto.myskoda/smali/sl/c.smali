.class public final Lsl/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ld01/k0;

.field public final b:Lsl/b;

.field public final c:Ljava/util/Date;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/util/Date;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/util/Date;

.field public final h:J

.field public final i:J

.field public final j:Ljava/lang/String;

.field public final k:I


# direct methods
.method public constructor <init>(Ld01/k0;Lsl/b;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lsl/c;->a:Ld01/k0;

    .line 5
    .line 6
    iput-object p2, p0, Lsl/c;->b:Lsl/b;

    .line 7
    .line 8
    const/4 p1, -0x1

    .line 9
    iput p1, p0, Lsl/c;->k:I

    .line 10
    .line 11
    if-eqz p2, :cond_b

    .line 12
    .line 13
    iget-wide v0, p2, Lsl/b;->c:J

    .line 14
    .line 15
    iput-wide v0, p0, Lsl/c;->h:J

    .line 16
    .line 17
    iget-wide v0, p2, Lsl/b;->d:J

    .line 18
    .line 19
    iput-wide v0, p0, Lsl/c;->i:J

    .line 20
    .line 21
    iget-object p2, p2, Lsl/b;->f:Ld01/y;

    .line 22
    .line 23
    invoke-virtual {p2}, Ld01/y;->size()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    const/4 v1, 0x0

    .line 28
    move v2, v1

    .line 29
    :goto_0
    if-ge v2, v0, :cond_b

    .line 30
    .line 31
    invoke-virtual {p2, v2}, Ld01/y;->e(I)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    const-string v4, "Date"

    .line 36
    .line 37
    invoke-virtual {v3, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 38
    .line 39
    .line 40
    move-result v5

    .line 41
    const/4 v6, 0x0

    .line 42
    if-eqz v5, :cond_1

    .line 43
    .line 44
    invoke-virtual {p2, v4}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    if-eqz v3, :cond_0

    .line 49
    .line 50
    invoke-static {v3}, Li01/b;->a(Ljava/lang/String;)Ljava/util/Date;

    .line 51
    .line 52
    .line 53
    move-result-object v6

    .line 54
    :cond_0
    iput-object v6, p0, Lsl/c;->c:Ljava/util/Date;

    .line 55
    .line 56
    invoke-virtual {p2, v2}, Ld01/y;->k(I)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    iput-object v3, p0, Lsl/c;->d:Ljava/lang/String;

    .line 61
    .line 62
    goto/16 :goto_2

    .line 63
    .line 64
    :cond_1
    const-string v4, "Expires"

    .line 65
    .line 66
    invoke-virtual {v3, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 67
    .line 68
    .line 69
    move-result v5

    .line 70
    if-eqz v5, :cond_3

    .line 71
    .line 72
    invoke-virtual {p2, v4}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v3

    .line 76
    if-eqz v3, :cond_2

    .line 77
    .line 78
    invoke-static {v3}, Li01/b;->a(Ljava/lang/String;)Ljava/util/Date;

    .line 79
    .line 80
    .line 81
    move-result-object v6

    .line 82
    :cond_2
    iput-object v6, p0, Lsl/c;->g:Ljava/util/Date;

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_3
    const-string v4, "Last-Modified"

    .line 86
    .line 87
    invoke-virtual {v3, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 88
    .line 89
    .line 90
    move-result v5

    .line 91
    if-eqz v5, :cond_5

    .line 92
    .line 93
    invoke-virtual {p2, v4}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    if-eqz v3, :cond_4

    .line 98
    .line 99
    invoke-static {v3}, Li01/b;->a(Ljava/lang/String;)Ljava/util/Date;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    :cond_4
    iput-object v6, p0, Lsl/c;->e:Ljava/util/Date;

    .line 104
    .line 105
    invoke-virtual {p2, v2}, Ld01/y;->k(I)Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    iput-object v3, p0, Lsl/c;->f:Ljava/lang/String;

    .line 110
    .line 111
    goto :goto_2

    .line 112
    :cond_5
    const-string v4, "ETag"

    .line 113
    .line 114
    invoke-virtual {v3, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 115
    .line 116
    .line 117
    move-result v4

    .line 118
    if-eqz v4, :cond_6

    .line 119
    .line 120
    invoke-virtual {p2, v2}, Ld01/y;->k(I)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v3

    .line 124
    iput-object v3, p0, Lsl/c;->j:Ljava/lang/String;

    .line 125
    .line 126
    goto :goto_2

    .line 127
    :cond_6
    const-string v4, "Age"

    .line 128
    .line 129
    invoke-virtual {v3, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 130
    .line 131
    .line 132
    move-result v3

    .line 133
    if-eqz v3, :cond_a

    .line 134
    .line 135
    invoke-virtual {p2, v2}, Ld01/y;->k(I)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v3

    .line 139
    sget-object v4, Lxl/c;->a:[Landroid/graphics/Bitmap$Config;

    .line 140
    .line 141
    invoke-static {v3}, Lly0/w;->z(Ljava/lang/String;)Ljava/lang/Long;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    if-eqz v3, :cond_9

    .line 146
    .line 147
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 148
    .line 149
    .line 150
    move-result-wide v3

    .line 151
    const-wide/32 v5, 0x7fffffff

    .line 152
    .line 153
    .line 154
    cmp-long v5, v3, v5

    .line 155
    .line 156
    if-lez v5, :cond_7

    .line 157
    .line 158
    const v3, 0x7fffffff

    .line 159
    .line 160
    .line 161
    goto :goto_1

    .line 162
    :cond_7
    const-wide/16 v5, 0x0

    .line 163
    .line 164
    cmp-long v5, v3, v5

    .line 165
    .line 166
    if-gez v5, :cond_8

    .line 167
    .line 168
    move v3, v1

    .line 169
    goto :goto_1

    .line 170
    :cond_8
    long-to-int v3, v3

    .line 171
    goto :goto_1

    .line 172
    :cond_9
    move v3, p1

    .line 173
    :goto_1
    iput v3, p0, Lsl/c;->k:I

    .line 174
    .line 175
    :cond_a
    :goto_2
    add-int/lit8 v2, v2, 0x1

    .line 176
    .line 177
    goto/16 :goto_0

    .line 178
    .line 179
    :cond_b
    return-void
.end method


# virtual methods
.method public final a()Lsl/d;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lsl/c;->a:Ld01/k0;

    .line 4
    .line 5
    iget-object v2, v1, Ld01/k0;->c:Ld01/y;

    .line 6
    .line 7
    iget-object v3, v1, Ld01/k0;->a:Ld01/a0;

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    iget-object v5, v0, Lsl/c;->b:Lsl/b;

    .line 11
    .line 12
    if-nez v5, :cond_0

    .line 13
    .line 14
    new-instance v0, Lsl/d;

    .line 15
    .line 16
    invoke-direct {v0, v1, v4}, Lsl/d;-><init>(Ld01/k0;Lsl/b;)V

    .line 17
    .line 18
    .line 19
    return-object v0

    .line 20
    :cond_0
    iget-object v6, v5, Lsl/b;->a:Ljava/lang/Object;

    .line 21
    .line 22
    invoke-virtual {v3}, Ld01/a0;->f()Z

    .line 23
    .line 24
    .line 25
    move-result v7

    .line 26
    if-eqz v7, :cond_1

    .line 27
    .line 28
    iget-boolean v7, v5, Lsl/b;->e:Z

    .line 29
    .line 30
    if-nez v7, :cond_1

    .line 31
    .line 32
    new-instance v0, Lsl/d;

    .line 33
    .line 34
    invoke-direct {v0, v1, v4}, Lsl/d;-><init>(Ld01/k0;Lsl/b;)V

    .line 35
    .line 36
    .line 37
    return-object v0

    .line 38
    :cond_1
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v7

    .line 42
    check-cast v7, Ld01/h;

    .line 43
    .line 44
    invoke-virtual {v1}, Ld01/k0;->a()Ld01/h;

    .line 45
    .line 46
    .line 47
    move-result-object v8

    .line 48
    iget-boolean v8, v8, Ld01/h;->b:Z

    .line 49
    .line 50
    if-nez v8, :cond_13

    .line 51
    .line 52
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v8

    .line 56
    check-cast v8, Ld01/h;

    .line 57
    .line 58
    iget-boolean v8, v8, Ld01/h;->b:Z

    .line 59
    .line 60
    if-nez v8, :cond_13

    .line 61
    .line 62
    iget-object v8, v5, Lsl/b;->f:Ld01/y;

    .line 63
    .line 64
    const-string v9, "Vary"

    .line 65
    .line 66
    invoke-virtual {v8, v9}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v8

    .line 70
    const-string v9, "*"

    .line 71
    .line 72
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v8

    .line 76
    if-nez v8, :cond_13

    .line 77
    .line 78
    invoke-virtual {v1}, Ld01/k0;->a()Ld01/h;

    .line 79
    .line 80
    .line 81
    move-result-object v8

    .line 82
    iget-boolean v9, v8, Ld01/h;->a:Z

    .line 83
    .line 84
    if-nez v9, :cond_12

    .line 85
    .line 86
    const-string v9, "If-Modified-Since"

    .line 87
    .line 88
    invoke-virtual {v2, v9}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v10

    .line 92
    if-nez v10, :cond_12

    .line 93
    .line 94
    const-string v10, "If-None-Match"

    .line 95
    .line 96
    invoke-virtual {v2, v10}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v2

    .line 100
    if-eqz v2, :cond_2

    .line 101
    .line 102
    goto/16 :goto_7

    .line 103
    .line 104
    :cond_2
    iget-wide v11, v0, Lsl/c;->i:J

    .line 105
    .line 106
    iget-object v2, v0, Lsl/c;->c:Ljava/util/Date;

    .line 107
    .line 108
    const-wide/16 v13, 0x0

    .line 109
    .line 110
    if-eqz v2, :cond_3

    .line 111
    .line 112
    invoke-virtual {v2}, Ljava/util/Date;->getTime()J

    .line 113
    .line 114
    .line 115
    move-result-wide v15

    .line 116
    move-object/from16 v17, v5

    .line 117
    .line 118
    sub-long v4, v11, v15

    .line 119
    .line 120
    invoke-static {v13, v14, v4, v5}, Ljava/lang/Math;->max(JJ)J

    .line 121
    .line 122
    .line 123
    move-result-wide v4

    .line 124
    goto :goto_0

    .line 125
    :cond_3
    move-object/from16 v17, v5

    .line 126
    .line 127
    move-wide v4, v13

    .line 128
    :goto_0
    const/4 v15, -0x1

    .line 129
    move-wide/from16 v18, v13

    .line 130
    .line 131
    iget v13, v0, Lsl/c;->k:I

    .line 132
    .line 133
    if-eq v13, v15, :cond_4

    .line 134
    .line 135
    sget-object v14, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 136
    .line 137
    move-object/from16 v16, v9

    .line 138
    .line 139
    move-object/from16 v20, v10

    .line 140
    .line 141
    int-to-long v9, v13

    .line 142
    invoke-virtual {v14, v9, v10}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 143
    .line 144
    .line 145
    move-result-wide v9

    .line 146
    invoke-static {v4, v5, v9, v10}, Ljava/lang/Math;->max(JJ)J

    .line 147
    .line 148
    .line 149
    move-result-wide v4

    .line 150
    goto :goto_1

    .line 151
    :cond_4
    move-object/from16 v16, v9

    .line 152
    .line 153
    move-object/from16 v20, v10

    .line 154
    .line 155
    :goto_1
    iget-wide v9, v0, Lsl/c;->h:J

    .line 156
    .line 157
    sub-long v13, v11, v9

    .line 158
    .line 159
    sget-object v21, Lxl/h;->a:Lxl/g;

    .line 160
    .line 161
    invoke-virtual/range {v21 .. v21}, Lxl/g;->invoke()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v21

    .line 165
    check-cast v21, Ljava/lang/Number;

    .line 166
    .line 167
    invoke-virtual/range {v21 .. v21}, Ljava/lang/Number;->longValue()J

    .line 168
    .line 169
    .line 170
    move-result-wide v21

    .line 171
    sub-long v21, v21, v11

    .line 172
    .line 173
    add-long/2addr v4, v13

    .line 174
    add-long v4, v4, v21

    .line 175
    .line 176
    invoke-interface {v6}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v6

    .line 180
    check-cast v6, Ld01/h;

    .line 181
    .line 182
    iget v6, v6, Ld01/h;->c:I

    .line 183
    .line 184
    iget-object v13, v0, Lsl/c;->e:Ljava/util/Date;

    .line 185
    .line 186
    if-eq v6, v15, :cond_5

    .line 187
    .line 188
    sget-object v3, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 189
    .line 190
    int-to-long v9, v6

    .line 191
    invoke-virtual {v3, v9, v10}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 192
    .line 193
    .line 194
    move-result-wide v9

    .line 195
    goto :goto_3

    .line 196
    :cond_5
    iget-object v6, v0, Lsl/c;->g:Ljava/util/Date;

    .line 197
    .line 198
    if-eqz v6, :cond_8

    .line 199
    .line 200
    if-eqz v2, :cond_6

    .line 201
    .line 202
    invoke-virtual {v2}, Ljava/util/Date;->getTime()J

    .line 203
    .line 204
    .line 205
    move-result-wide v11

    .line 206
    :cond_6
    invoke-virtual {v6}, Ljava/util/Date;->getTime()J

    .line 207
    .line 208
    .line 209
    move-result-wide v9

    .line 210
    sub-long/2addr v9, v11

    .line 211
    cmp-long v3, v9, v18

    .line 212
    .line 213
    if-lez v3, :cond_7

    .line 214
    .line 215
    goto :goto_3

    .line 216
    :cond_7
    move-wide/from16 v9, v18

    .line 217
    .line 218
    goto :goto_3

    .line 219
    :cond_8
    if-eqz v13, :cond_7

    .line 220
    .line 221
    iget-object v3, v3, Ld01/a0;->g:Ljava/util/List;

    .line 222
    .line 223
    if-nez v3, :cond_9

    .line 224
    .line 225
    const/4 v3, 0x0

    .line 226
    goto :goto_2

    .line 227
    :cond_9
    new-instance v6, Ljava/lang/StringBuilder;

    .line 228
    .line 229
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 230
    .line 231
    .line 232
    invoke-static {v3, v6}, Ld01/r;->b(Ljava/util/List;Ljava/lang/StringBuilder;)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v3

    .line 239
    :goto_2
    if-nez v3, :cond_7

    .line 240
    .line 241
    if-eqz v2, :cond_a

    .line 242
    .line 243
    invoke-virtual {v2}, Ljava/util/Date;->getTime()J

    .line 244
    .line 245
    .line 246
    move-result-wide v9

    .line 247
    :cond_a
    invoke-virtual {v13}, Ljava/util/Date;->getTime()J

    .line 248
    .line 249
    .line 250
    move-result-wide v11

    .line 251
    sub-long/2addr v9, v11

    .line 252
    cmp-long v3, v9, v18

    .line 253
    .line 254
    if-lez v3, :cond_7

    .line 255
    .line 256
    const/16 v3, 0xa

    .line 257
    .line 258
    int-to-long v11, v3

    .line 259
    div-long/2addr v9, v11

    .line 260
    :goto_3
    iget v3, v8, Ld01/h;->c:I

    .line 261
    .line 262
    if-eq v3, v15, :cond_b

    .line 263
    .line 264
    sget-object v6, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 265
    .line 266
    int-to-long v11, v3

    .line 267
    invoke-virtual {v6, v11, v12}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 268
    .line 269
    .line 270
    move-result-wide v11

    .line 271
    invoke-static {v9, v10, v11, v12}, Ljava/lang/Math;->min(JJ)J

    .line 272
    .line 273
    .line 274
    move-result-wide v9

    .line 275
    :cond_b
    iget v3, v8, Ld01/h;->i:I

    .line 276
    .line 277
    if-eq v3, v15, :cond_c

    .line 278
    .line 279
    sget-object v6, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 280
    .line 281
    int-to-long v11, v3

    .line 282
    invoke-virtual {v6, v11, v12}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 283
    .line 284
    .line 285
    move-result-wide v11

    .line 286
    goto :goto_4

    .line 287
    :cond_c
    move-wide/from16 v11, v18

    .line 288
    .line 289
    :goto_4
    iget-boolean v3, v7, Ld01/h;->g:Z

    .line 290
    .line 291
    if-nez v3, :cond_d

    .line 292
    .line 293
    iget v3, v8, Ld01/h;->h:I

    .line 294
    .line 295
    if-eq v3, v15, :cond_d

    .line 296
    .line 297
    sget-object v6, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 298
    .line 299
    int-to-long v14, v3

    .line 300
    invoke-virtual {v6, v14, v15}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 301
    .line 302
    .line 303
    move-result-wide v14

    .line 304
    move-wide/from16 v18, v14

    .line 305
    .line 306
    :cond_d
    iget-boolean v3, v7, Ld01/h;->a:Z

    .line 307
    .line 308
    if-nez v3, :cond_e

    .line 309
    .line 310
    add-long/2addr v4, v11

    .line 311
    add-long v9, v9, v18

    .line 312
    .line 313
    cmp-long v3, v4, v9

    .line 314
    .line 315
    if-gez v3, :cond_e

    .line 316
    .line 317
    new-instance v0, Lsl/d;

    .line 318
    .line 319
    move-object/from16 v3, v17

    .line 320
    .line 321
    const/4 v1, 0x0

    .line 322
    invoke-direct {v0, v1, v3}, Lsl/d;-><init>(Ld01/k0;Lsl/b;)V

    .line 323
    .line 324
    .line 325
    return-object v0

    .line 326
    :cond_e
    move-object/from16 v3, v17

    .line 327
    .line 328
    iget-object v4, v0, Lsl/c;->j:Ljava/lang/String;

    .line 329
    .line 330
    if-eqz v4, :cond_f

    .line 331
    .line 332
    move-object/from16 v9, v20

    .line 333
    .line 334
    goto :goto_6

    .line 335
    :cond_f
    if-eqz v13, :cond_10

    .line 336
    .line 337
    iget-object v4, v0, Lsl/c;->f:Ljava/lang/String;

    .line 338
    .line 339
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 340
    .line 341
    .line 342
    :goto_5
    move-object/from16 v9, v16

    .line 343
    .line 344
    goto :goto_6

    .line 345
    :cond_10
    if-eqz v2, :cond_11

    .line 346
    .line 347
    iget-object v4, v0, Lsl/c;->d:Ljava/lang/String;

    .line 348
    .line 349
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 350
    .line 351
    .line 352
    goto :goto_5

    .line 353
    :goto_6
    invoke-virtual {v1}, Ld01/k0;->b()Ld01/j0;

    .line 354
    .line 355
    .line 356
    move-result-object v0

    .line 357
    invoke-static {v0, v9, v4, v0}, Lp3/m;->c(Ld01/j0;Ljava/lang/String;Ljava/lang/String;Ld01/j0;)Ld01/k0;

    .line 358
    .line 359
    .line 360
    move-result-object v0

    .line 361
    new-instance v1, Lsl/d;

    .line 362
    .line 363
    invoke-direct {v1, v0, v3}, Lsl/d;-><init>(Ld01/k0;Lsl/b;)V

    .line 364
    .line 365
    .line 366
    return-object v1

    .line 367
    :cond_11
    new-instance v0, Lsl/d;

    .line 368
    .line 369
    const/4 v2, 0x0

    .line 370
    invoke-direct {v0, v1, v2}, Lsl/d;-><init>(Ld01/k0;Lsl/b;)V

    .line 371
    .line 372
    .line 373
    return-object v0

    .line 374
    :cond_12
    :goto_7
    move-object v2, v4

    .line 375
    new-instance v0, Lsl/d;

    .line 376
    .line 377
    invoke-direct {v0, v1, v2}, Lsl/d;-><init>(Ld01/k0;Lsl/b;)V

    .line 378
    .line 379
    .line 380
    return-object v0

    .line 381
    :cond_13
    move-object v2, v4

    .line 382
    new-instance v0, Lsl/d;

    .line 383
    .line 384
    invoke-direct {v0, v1, v2}, Lsl/d;-><init>(Ld01/k0;Lsl/b;)V

    .line 385
    .line 386
    .line 387
    return-object v0
.end method
