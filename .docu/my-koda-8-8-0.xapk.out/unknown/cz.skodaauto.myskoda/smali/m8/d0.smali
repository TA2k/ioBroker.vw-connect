.class public final Lm8/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lb81/a;

.field public final b:Lm8/y;

.field public final c:Li9/a;

.field public final d:Li4/c;

.field public final e:Li4/c;

.field public final f:Lcom/google/android/material/datepicker/w;

.field public g:J

.field public h:J

.field public i:J

.field public j:Lt7/a1;

.field public k:J


# direct methods
.method public constructor <init>(Lb81/a;Lm8/y;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lm8/d0;->a:Lb81/a;

    .line 5
    .line 6
    iput-object p2, p0, Lm8/d0;->b:Lm8/y;

    .line 7
    .line 8
    new-instance p1, Li9/a;

    .line 9
    .line 10
    invoke-direct {p1}, Li9/a;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lm8/d0;->c:Li9/a;

    .line 14
    .line 15
    new-instance p1, Li4/c;

    .line 16
    .line 17
    invoke-direct {p1}, Li4/c;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lm8/d0;->d:Li4/c;

    .line 21
    .line 22
    new-instance p1, Li4/c;

    .line 23
    .line 24
    invoke-direct {p1}, Li4/c;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object p1, p0, Lm8/d0;->e:Li4/c;

    .line 28
    .line 29
    new-instance p1, Lcom/google/android/material/datepicker/w;

    .line 30
    .line 31
    invoke-direct {p1}, Lcom/google/android/material/datepicker/w;-><init>()V

    .line 32
    .line 33
    .line 34
    const/16 p2, 0x10

    .line 35
    .line 36
    invoke-static {p2}, Ljava/lang/Integer;->bitCount(I)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    const/4 v1, 0x1

    .line 41
    if-eq v0, v1, :cond_0

    .line 42
    .line 43
    const/16 p2, 0xf

    .line 44
    .line 45
    invoke-static {p2}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    shl-int/2addr p2, v1

    .line 50
    :cond_0
    const/4 v0, 0x0

    .line 51
    iput v0, p1, Lcom/google/android/material/datepicker/w;->e:I

    .line 52
    .line 53
    const/4 v2, -0x1

    .line 54
    iput v2, p1, Lcom/google/android/material/datepicker/w;->f:I

    .line 55
    .line 56
    iput v0, p1, Lcom/google/android/material/datepicker/w;->g:I

    .line 57
    .line 58
    new-array v0, p2, [J

    .line 59
    .line 60
    iput-object v0, p1, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 61
    .line 62
    sub-int/2addr p2, v1

    .line 63
    iput p2, p1, Lcom/google/android/material/datepicker/w;->h:I

    .line 64
    .line 65
    iput-object p1, p0, Lm8/d0;->f:Lcom/google/android/material/datepicker/w;

    .line 66
    .line 67
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 68
    .line 69
    .line 70
    .line 71
    .line 72
    iput-wide p1, p0, Lm8/d0;->g:J

    .line 73
    .line 74
    sget-object v0, Lt7/a1;->d:Lt7/a1;

    .line 75
    .line 76
    iput-object v0, p0, Lm8/d0;->j:Lt7/a1;

    .line 77
    .line 78
    iput-wide p1, p0, Lm8/d0;->h:J

    .line 79
    .line 80
    iput-wide p1, p0, Lm8/d0;->i:J

    .line 81
    .line 82
    return-void
.end method


# virtual methods
.method public final a(JJ)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lm8/d0;->a:Lb81/a;

    .line 4
    .line 5
    iget-object v2, v1, Lb81/a;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Lm8/c;

    .line 8
    .line 9
    :goto_0
    iget-object v3, v0, Lm8/d0;->f:Lcom/google/android/material/datepicker/w;

    .line 10
    .line 11
    iget v4, v3, Lcom/google/android/material/datepicker/w;->g:I

    .line 12
    .line 13
    if-nez v4, :cond_0

    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    if-eqz v4, :cond_c

    .line 17
    .line 18
    iget-object v4, v3, Lcom/google/android/material/datepicker/w;->i:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v4, [J

    .line 21
    .line 22
    iget v5, v3, Lcom/google/android/material/datepicker/w;->e:I

    .line 23
    .line 24
    aget-wide v7, v4, v5

    .line 25
    .line 26
    iget-object v4, v0, Lm8/d0;->e:Li4/c;

    .line 27
    .line 28
    invoke-virtual {v4, v7, v8}, Li4/c;->K(J)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    check-cast v4, Ljava/lang/Long;

    .line 33
    .line 34
    const/4 v5, 0x2

    .line 35
    iget-object v6, v0, Lm8/d0;->b:Lm8/y;

    .line 36
    .line 37
    if-eqz v4, :cond_1

    .line 38
    .line 39
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 40
    .line 41
    .line 42
    move-result-wide v9

    .line 43
    iget-wide v11, v0, Lm8/d0;->k:J

    .line 44
    .line 45
    cmp-long v9, v9, v11

    .line 46
    .line 47
    if-eqz v9, :cond_1

    .line 48
    .line 49
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 50
    .line 51
    .line 52
    move-result-wide v9

    .line 53
    iput-wide v9, v0, Lm8/d0;->k:J

    .line 54
    .line 55
    invoke-virtual {v6, v5}, Lm8/y;->f(I)V

    .line 56
    .line 57
    .line 58
    :cond_1
    iget-wide v13, v0, Lm8/d0;->k:J

    .line 59
    .line 60
    const/4 v15, 0x0

    .line 61
    const/16 v16, 0x0

    .line 62
    .line 63
    move-object v4, v6

    .line 64
    iget-object v6, v0, Lm8/d0;->b:Lm8/y;

    .line 65
    .line 66
    iget-object v9, v0, Lm8/d0;->c:Li9/a;

    .line 67
    .line 68
    move-wide/from16 v11, p3

    .line 69
    .line 70
    move-object/from16 v17, v9

    .line 71
    .line 72
    move-wide/from16 v9, p1

    .line 73
    .line 74
    invoke-virtual/range {v6 .. v17}, Lm8/y;->a(JJJJZZLi9/a;)I

    .line 75
    .line 76
    .line 77
    move-result v6

    .line 78
    move-object/from16 v9, v17

    .line 79
    .line 80
    const/4 v10, 0x3

    .line 81
    const/4 v11, 0x1

    .line 82
    if-eqz v6, :cond_5

    .line 83
    .line 84
    if-eq v6, v11, :cond_5

    .line 85
    .line 86
    if-eq v6, v5, :cond_4

    .line 87
    .line 88
    if-eq v6, v10, :cond_4

    .line 89
    .line 90
    const/4 v3, 0x4

    .line 91
    if-eq v6, v3, :cond_3

    .line 92
    .line 93
    const/4 v0, 0x5

    .line 94
    if-ne v6, v0, :cond_2

    .line 95
    .line 96
    return-void

    .line 97
    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 98
    .line 99
    invoke-static {v6}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    throw v0

    .line 107
    :cond_3
    iput-wide v7, v0, Lm8/d0;->h:J

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_4
    iput-wide v7, v0, Lm8/d0;->h:J

    .line 111
    .line 112
    invoke-virtual {v3}, Lcom/google/android/material/datepicker/w;->d()J

    .line 113
    .line 114
    .line 115
    iget-object v3, v2, Lm8/c;->h:Ljava/util/concurrent/Executor;

    .line 116
    .line 117
    new-instance v4, Lm8/b;

    .line 118
    .line 119
    const/4 v5, 0x1

    .line 120
    invoke-direct {v4, v1, v5}, Lm8/b;-><init>(Lb81/a;I)V

    .line 121
    .line 122
    .line 123
    invoke-interface {v3, v4}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 124
    .line 125
    .line 126
    iget-object v3, v2, Lm8/c;->c:Ljava/util/ArrayDeque;

    .line 127
    .line 128
    invoke-virtual {v3}, Ljava/util/ArrayDeque;->remove()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v3

    .line 132
    check-cast v3, Lm8/h;

    .line 133
    .line 134
    iget-object v4, v3, Lm8/h;->c:Lm8/l;

    .line 135
    .line 136
    iget-object v5, v3, Lm8/h;->a:Lf8/m;

    .line 137
    .line 138
    iget v3, v3, Lm8/h;->b:I

    .line 139
    .line 140
    invoke-virtual {v4, v5, v3}, Lm8/l;->N0(Lf8/m;I)V

    .line 141
    .line 142
    .line 143
    goto/16 :goto_0

    .line 144
    .line 145
    :cond_5
    iput-wide v7, v0, Lm8/d0;->h:J

    .line 146
    .line 147
    const/4 v5, 0x0

    .line 148
    if-nez v6, :cond_6

    .line 149
    .line 150
    move v6, v11

    .line 151
    goto :goto_1

    .line 152
    :cond_6
    move v6, v5

    .line 153
    :goto_1
    invoke-virtual {v3}, Lcom/google/android/material/datepicker/w;->d()J

    .line 154
    .line 155
    .line 156
    move-result-wide v13

    .line 157
    iget-object v3, v0, Lm8/d0;->d:Li4/c;

    .line 158
    .line 159
    invoke-virtual {v3, v13, v14}, Li4/c;->K(J)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v3

    .line 163
    check-cast v3, Lt7/a1;

    .line 164
    .line 165
    if-eqz v3, :cond_7

    .line 166
    .line 167
    sget-object v7, Lt7/a1;->d:Lt7/a1;

    .line 168
    .line 169
    invoke-virtual {v3, v7}, Lt7/a1;->equals(Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result v7

    .line 173
    if-nez v7, :cond_7

    .line 174
    .line 175
    iget-object v7, v0, Lm8/d0;->j:Lt7/a1;

    .line 176
    .line 177
    invoke-virtual {v3, v7}, Lt7/a1;->equals(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v7

    .line 181
    if-nez v7, :cond_7

    .line 182
    .line 183
    iput-object v3, v0, Lm8/d0;->j:Lt7/a1;

    .line 184
    .line 185
    new-instance v7, Lt7/n;

    .line 186
    .line 187
    invoke-direct {v7}, Lt7/n;-><init>()V

    .line 188
    .line 189
    .line 190
    iget v8, v3, Lt7/a1;->a:I

    .line 191
    .line 192
    iput v8, v7, Lt7/n;->t:I

    .line 193
    .line 194
    iget v8, v3, Lt7/a1;->b:I

    .line 195
    .line 196
    iput v8, v7, Lt7/n;->u:I

    .line 197
    .line 198
    const-string v8, "video/raw"

    .line 199
    .line 200
    invoke-static {v8}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v8

    .line 204
    iput-object v8, v7, Lt7/n;->m:Ljava/lang/String;

    .line 205
    .line 206
    new-instance v8, Lt7/o;

    .line 207
    .line 208
    invoke-direct {v8, v7}, Lt7/o;-><init>(Lt7/n;)V

    .line 209
    .line 210
    .line 211
    iput-object v8, v1, Lb81/a;->e:Ljava/lang/Object;

    .line 212
    .line 213
    iget-object v7, v2, Lm8/c;->h:Ljava/util/concurrent/Executor;

    .line 214
    .line 215
    new-instance v8, Lh0/h0;

    .line 216
    .line 217
    const/16 v12, 0x13

    .line 218
    .line 219
    invoke-direct {v8, v12, v1, v3}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    invoke-interface {v7, v8}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 223
    .line 224
    .line 225
    :cond_7
    if-eqz v6, :cond_8

    .line 226
    .line 227
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 228
    .line 229
    .line 230
    move-result-wide v6

    .line 231
    :goto_2
    move-wide v15, v6

    .line 232
    goto :goto_3

    .line 233
    :cond_8
    iget-wide v6, v9, Li9/a;->b:J

    .line 234
    .line 235
    goto :goto_2

    .line 236
    :goto_3
    iget v3, v4, Lm8/y;->e:I

    .line 237
    .line 238
    if-eq v3, v10, :cond_9

    .line 239
    .line 240
    goto :goto_4

    .line 241
    :cond_9
    move v11, v5

    .line 242
    :goto_4
    iput v10, v4, Lm8/y;->e:I

    .line 243
    .line 244
    iget-object v3, v4, Lm8/y;->l:Lw7/r;

    .line 245
    .line 246
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 247
    .line 248
    .line 249
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 250
    .line 251
    .line 252
    move-result-wide v5

    .line 253
    invoke-static {v5, v6}, Lw7/w;->D(J)J

    .line 254
    .line 255
    .line 256
    move-result-wide v5

    .line 257
    iput-wide v5, v4, Lm8/y;->g:J

    .line 258
    .line 259
    if-eqz v11, :cond_a

    .line 260
    .line 261
    iget-object v3, v2, Lm8/c;->d:Landroid/view/Surface;

    .line 262
    .line 263
    if-eqz v3, :cond_a

    .line 264
    .line 265
    iget-object v3, v2, Lm8/c;->h:Ljava/util/concurrent/Executor;

    .line 266
    .line 267
    new-instance v4, Lm8/b;

    .line 268
    .line 269
    const/4 v5, 0x0

    .line 270
    invoke-direct {v4, v1, v5}, Lm8/b;-><init>(Lb81/a;I)V

    .line 271
    .line 272
    .line 273
    invoke-interface {v3, v4}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 274
    .line 275
    .line 276
    :cond_a
    iget-object v3, v1, Lb81/a;->e:Ljava/lang/Object;

    .line 277
    .line 278
    check-cast v3, Lt7/o;

    .line 279
    .line 280
    if-nez v3, :cond_b

    .line 281
    .line 282
    new-instance v3, Lt7/n;

    .line 283
    .line 284
    invoke-direct {v3}, Lt7/n;-><init>()V

    .line 285
    .line 286
    .line 287
    new-instance v4, Lt7/o;

    .line 288
    .line 289
    invoke-direct {v4, v3}, Lt7/o;-><init>(Lt7/n;)V

    .line 290
    .line 291
    .line 292
    move-object/from16 v17, v4

    .line 293
    .line 294
    goto :goto_5

    .line 295
    :cond_b
    move-object/from16 v17, v3

    .line 296
    .line 297
    :goto_5
    iget-object v12, v2, Lm8/c;->i:Lm8/x;

    .line 298
    .line 299
    const/16 v18, 0x0

    .line 300
    .line 301
    invoke-interface/range {v12 .. v18}, Lm8/x;->b(JJLt7/o;Landroid/media/MediaFormat;)V

    .line 302
    .line 303
    .line 304
    move-wide v6, v15

    .line 305
    iget-object v3, v2, Lm8/c;->c:Ljava/util/ArrayDeque;

    .line 306
    .line 307
    invoke-virtual {v3}, Ljava/util/ArrayDeque;->remove()Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object v3

    .line 311
    check-cast v3, Lm8/h;

    .line 312
    .line 313
    iget-object v4, v3, Lm8/h;->c:Lm8/l;

    .line 314
    .line 315
    iget-object v5, v3, Lm8/h;->a:Lf8/m;

    .line 316
    .line 317
    iget v3, v3, Lm8/h;->b:I

    .line 318
    .line 319
    invoke-virtual {v4, v5, v3, v6, v7}, Lm8/l;->J0(Lf8/m;IJ)V

    .line 320
    .line 321
    .line 322
    goto/16 :goto_0

    .line 323
    .line 324
    :cond_c
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 325
    .line 326
    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 327
    .line 328
    .line 329
    throw v0
.end method
