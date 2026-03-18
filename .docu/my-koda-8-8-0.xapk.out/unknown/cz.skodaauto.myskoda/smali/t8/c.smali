.class public final Lt8/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/o;


# instance fields
.field public final a:[B

.field public final b:Lw7/p;

.field public final c:Z

.field public final d:Lo8/s;

.field public e:Lo8/q;

.field public f:Lo8/i0;

.field public g:I

.field public h:Lt7/c0;

.field public i:Lo8/u;

.field public j:I

.field public k:I

.field public l:Lt8/b;

.field public m:I

.field public n:J


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0x2a

    .line 5
    .line 6
    new-array v0, v0, [B

    .line 7
    .line 8
    iput-object v0, p0, Lt8/c;->a:[B

    .line 9
    .line 10
    new-instance v0, Lw7/p;

    .line 11
    .line 12
    const v1, 0x8000

    .line 13
    .line 14
    .line 15
    new-array v1, v1, [B

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-direct {v0, v2, v1}, Lw7/p;-><init>(I[B)V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Lt8/c;->b:Lw7/p;

    .line 22
    .line 23
    iput-boolean v2, p0, Lt8/c;->c:Z

    .line 24
    .line 25
    new-instance v0, Lo8/s;

    .line 26
    .line 27
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Lt8/c;->d:Lo8/s;

    .line 31
    .line 32
    iput v2, p0, Lt8/c;->g:I

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final a(Lo8/p;)Z
    .locals 4

    .line 1
    const/4 p0, 0x0

    .line 2
    invoke-static {p1, p0}, Lo8/b;->s(Lo8/p;Z)Lt7/c0;

    .line 3
    .line 4
    .line 5
    new-instance v0, Lw7/p;

    .line 6
    .line 7
    const/4 v1, 0x4

    .line 8
    invoke-direct {v0, v1}, Lw7/p;-><init>(I)V

    .line 9
    .line 10
    .line 11
    iget-object v2, v0, Lw7/p;->a:[B

    .line 12
    .line 13
    check-cast p1, Lo8/l;

    .line 14
    .line 15
    invoke-virtual {p1, v2, p0, v1, p0}, Lo8/l;->b([BIIZ)Z

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Lw7/p;->y()J

    .line 19
    .line 20
    .line 21
    move-result-wide v0

    .line 22
    const-wide/32 v2, 0x664c6143

    .line 23
    .line 24
    .line 25
    cmp-long p1, v0, v2

    .line 26
    .line 27
    if-nez p1, :cond_0

    .line 28
    .line 29
    const/4 p0, 0x1

    .line 30
    :cond_0
    return p0
.end method

.method public final b()V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Lo8/q;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lt8/c;->e:Lo8/q;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    const/4 v1, 0x1

    .line 5
    invoke-interface {p1, v0, v1}, Lo8/q;->q(II)Lo8/i0;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iput-object v0, p0, Lt8/c;->f:Lo8/i0;

    .line 10
    .line 11
    invoke-interface {p1}, Lo8/q;->m()V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final d(JJ)V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long p1, p1, v0

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    if-nez p1, :cond_0

    .line 7
    .line 8
    iput p2, p0, Lt8/c;->g:I

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    iget-object p1, p0, Lt8/c;->l:Lt8/b;

    .line 12
    .line 13
    if-eqz p1, :cond_1

    .line 14
    .line 15
    invoke-virtual {p1, p3, p4}, Lo8/j;->B(J)V

    .line 16
    .line 17
    .line 18
    :cond_1
    :goto_0
    cmp-long p1, p3, v0

    .line 19
    .line 20
    if-nez p1, :cond_2

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_2
    const-wide/16 v0, -0x1

    .line 24
    .line 25
    :goto_1
    iput-wide v0, p0, Lt8/c;->n:J

    .line 26
    .line 27
    iput p2, p0, Lt8/c;->m:I

    .line 28
    .line 29
    iget-object p0, p0, Lt8/c;->b:Lw7/p;

    .line 30
    .line 31
    invoke-virtual {p0, p2}, Lw7/p;->F(I)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public final h(Lo8/p;Lo8/s;)I
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v2, v0, Lt8/c;->g:I

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    const/4 v4, 0x0

    .line 9
    if-eqz v2, :cond_28

    .line 10
    .line 11
    iget-object v5, v0, Lt8/c;->a:[B

    .line 12
    .line 13
    const/4 v6, 0x2

    .line 14
    if-eq v2, v3, :cond_27

    .line 15
    .line 16
    const/4 v7, 0x0

    .line 17
    const/4 v8, 0x4

    .line 18
    const/4 v9, 0x3

    .line 19
    if-eq v2, v6, :cond_25

    .line 20
    .line 21
    const/4 v10, 0x7

    .line 22
    const/4 v11, 0x6

    .line 23
    if-eq v2, v9, :cond_1c

    .line 24
    .line 25
    const-wide/16 v12, 0x0

    .line 26
    .line 27
    const-wide/16 v14, -0x1

    .line 28
    .line 29
    const/4 v5, 0x5

    .line 30
    if-eq v2, v8, :cond_16

    .line 31
    .line 32
    if-ne v2, v5, :cond_15

    .line 33
    .line 34
    iget-object v2, v0, Lt8/c;->f:Lo8/i0;

    .line 35
    .line 36
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    iget-object v2, v0, Lt8/c;->i:Lo8/u;

    .line 40
    .line 41
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    iget-object v2, v0, Lt8/c;->l:Lt8/b;

    .line 45
    .line 46
    if-eqz v2, :cond_0

    .line 47
    .line 48
    iget-object v5, v2, Lo8/j;->e:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v5, Lo8/f;

    .line 51
    .line 52
    if-eqz v5, :cond_0

    .line 53
    .line 54
    move-object/from16 v5, p2

    .line 55
    .line 56
    invoke-virtual {v2, v1, v5}, Lo8/j;->u(Lo8/p;Lo8/s;)I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    return v0

    .line 61
    :cond_0
    iget-wide v8, v0, Lt8/c;->n:J

    .line 62
    .line 63
    cmp-long v2, v8, v14

    .line 64
    .line 65
    const/4 v5, -0x1

    .line 66
    if-nez v2, :cond_7

    .line 67
    .line 68
    iget-object v2, v0, Lt8/c;->i:Lo8/u;

    .line 69
    .line 70
    invoke-interface {v1}, Lo8/p;->e()V

    .line 71
    .line 72
    .line 73
    invoke-interface {v1, v3}, Lo8/p;->i(I)V

    .line 74
    .line 75
    .line 76
    new-array v8, v3, [B

    .line 77
    .line 78
    invoke-interface {v1, v8, v4, v3}, Lo8/p;->o([BII)V

    .line 79
    .line 80
    .line 81
    aget-byte v8, v8, v4

    .line 82
    .line 83
    and-int/2addr v8, v3

    .line 84
    if-ne v8, v3, :cond_1

    .line 85
    .line 86
    move v8, v3

    .line 87
    goto :goto_0

    .line 88
    :cond_1
    move v8, v4

    .line 89
    :goto_0
    invoke-interface {v1, v6}, Lo8/p;->i(I)V

    .line 90
    .line 91
    .line 92
    if-eqz v8, :cond_2

    .line 93
    .line 94
    goto :goto_1

    .line 95
    :cond_2
    move v10, v11

    .line 96
    :goto_1
    new-instance v6, Lw7/p;

    .line 97
    .line 98
    invoke-direct {v6, v10}, Lw7/p;-><init>(I)V

    .line 99
    .line 100
    .line 101
    iget-object v9, v6, Lw7/p;->a:[B

    .line 102
    .line 103
    move v11, v4

    .line 104
    :goto_2
    if-ge v11, v10, :cond_4

    .line 105
    .line 106
    sub-int v14, v10, v11

    .line 107
    .line 108
    invoke-interface {v1, v9, v11, v14}, Lo8/p;->k([BII)I

    .line 109
    .line 110
    .line 111
    move-result v14

    .line 112
    if-ne v14, v5, :cond_3

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_3
    add-int/2addr v11, v14

    .line 116
    goto :goto_2

    .line 117
    :cond_4
    :goto_3
    invoke-virtual {v6, v11}, Lw7/p;->H(I)V

    .line 118
    .line 119
    .line 120
    invoke-interface {v1}, Lo8/p;->e()V

    .line 121
    .line 122
    .line 123
    :try_start_0
    invoke-virtual {v6}, Lw7/p;->D()J

    .line 124
    .line 125
    .line 126
    move-result-wide v5
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 127
    if-eqz v8, :cond_5

    .line 128
    .line 129
    :goto_4
    move-wide v12, v5

    .line 130
    goto :goto_5

    .line 131
    :cond_5
    iget v1, v2, Lo8/u;->b:I

    .line 132
    .line 133
    int-to-long v1, v1

    .line 134
    mul-long/2addr v5, v1

    .line 135
    goto :goto_4

    .line 136
    :catch_0
    move v3, v4

    .line 137
    :goto_5
    if-eqz v3, :cond_6

    .line 138
    .line 139
    iput-wide v12, v0, Lt8/c;->n:J

    .line 140
    .line 141
    goto/16 :goto_d

    .line 142
    .line 143
    :cond_6
    invoke-static {v7, v7}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    throw v0

    .line 148
    :cond_7
    iget-object v2, v0, Lt8/c;->b:Lw7/p;

    .line 149
    .line 150
    iget v6, v2, Lw7/p;->c:I

    .line 151
    .line 152
    const-wide/32 v7, 0xf4240

    .line 153
    .line 154
    .line 155
    const v9, 0x8000

    .line 156
    .line 157
    .line 158
    if-ge v6, v9, :cond_a

    .line 159
    .line 160
    iget-object v10, v2, Lw7/p;->a:[B

    .line 161
    .line 162
    sub-int/2addr v9, v6

    .line 163
    invoke-interface {v1, v10, v6, v9}, Lt7/g;->read([BII)I

    .line 164
    .line 165
    .line 166
    move-result v1

    .line 167
    if-ne v1, v5, :cond_8

    .line 168
    .line 169
    goto :goto_6

    .line 170
    :cond_8
    move v3, v4

    .line 171
    :goto_6
    if-nez v3, :cond_9

    .line 172
    .line 173
    add-int/2addr v6, v1

    .line 174
    invoke-virtual {v2, v6}, Lw7/p;->H(I)V

    .line 175
    .line 176
    .line 177
    goto :goto_7

    .line 178
    :cond_9
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 179
    .line 180
    .line 181
    move-result v1

    .line 182
    if-nez v1, :cond_b

    .line 183
    .line 184
    iget-wide v1, v0, Lt8/c;->n:J

    .line 185
    .line 186
    mul-long/2addr v1, v7

    .line 187
    iget-object v3, v0, Lt8/c;->i:Lo8/u;

    .line 188
    .line 189
    sget-object v4, Lw7/w;->a:Ljava/lang/String;

    .line 190
    .line 191
    iget v3, v3, Lo8/u;->e:I

    .line 192
    .line 193
    int-to-long v3, v3

    .line 194
    div-long v7, v1, v3

    .line 195
    .line 196
    iget-object v6, v0, Lt8/c;->f:Lo8/i0;

    .line 197
    .line 198
    iget v10, v0, Lt8/c;->m:I

    .line 199
    .line 200
    const/4 v11, 0x0

    .line 201
    const/4 v12, 0x0

    .line 202
    const/4 v9, 0x1

    .line 203
    invoke-interface/range {v6 .. v12}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 204
    .line 205
    .line 206
    return v5

    .line 207
    :cond_a
    move v3, v4

    .line 208
    :cond_b
    :goto_7
    iget v1, v2, Lw7/p;->b:I

    .line 209
    .line 210
    iget v5, v0, Lt8/c;->m:I

    .line 211
    .line 212
    iget v6, v0, Lt8/c;->j:I

    .line 213
    .line 214
    if-ge v5, v6, :cond_c

    .line 215
    .line 216
    sub-int/2addr v6, v5

    .line 217
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 218
    .line 219
    .line 220
    move-result v5

    .line 221
    invoke-static {v6, v5}, Ljava/lang/Math;->min(II)I

    .line 222
    .line 223
    .line 224
    move-result v5

    .line 225
    invoke-virtual {v2, v5}, Lw7/p;->J(I)V

    .line 226
    .line 227
    .line 228
    :cond_c
    iget-object v5, v0, Lt8/c;->i:Lo8/u;

    .line 229
    .line 230
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 231
    .line 232
    .line 233
    iget v5, v2, Lw7/p;->b:I

    .line 234
    .line 235
    :goto_8
    iget v6, v2, Lw7/p;->c:I

    .line 236
    .line 237
    const/16 v9, 0x10

    .line 238
    .line 239
    sub-int/2addr v6, v9

    .line 240
    iget-object v10, v0, Lt8/c;->d:Lo8/s;

    .line 241
    .line 242
    if-gt v5, v6, :cond_e

    .line 243
    .line 244
    invoke-virtual {v2, v5}, Lw7/p;->I(I)V

    .line 245
    .line 246
    .line 247
    iget-object v6, v0, Lt8/c;->i:Lo8/u;

    .line 248
    .line 249
    iget v11, v0, Lt8/c;->k:I

    .line 250
    .line 251
    invoke-static {v2, v6, v11, v10}, Lo8/b;->b(Lw7/p;Lo8/u;ILo8/s;)Z

    .line 252
    .line 253
    .line 254
    move-result v6

    .line 255
    if-eqz v6, :cond_d

    .line 256
    .line 257
    invoke-virtual {v2, v5}, Lw7/p;->I(I)V

    .line 258
    .line 259
    .line 260
    iget-wide v5, v10, Lo8/s;->a:J

    .line 261
    .line 262
    goto :goto_c

    .line 263
    :cond_d
    add-int/lit8 v5, v5, 0x1

    .line 264
    .line 265
    goto :goto_8

    .line 266
    :cond_e
    if-eqz v3, :cond_12

    .line 267
    .line 268
    :goto_9
    iget v3, v2, Lw7/p;->c:I

    .line 269
    .line 270
    iget v6, v0, Lt8/c;->j:I

    .line 271
    .line 272
    sub-int v6, v3, v6

    .line 273
    .line 274
    if-gt v5, v6, :cond_11

    .line 275
    .line 276
    invoke-virtual {v2, v5}, Lw7/p;->I(I)V

    .line 277
    .line 278
    .line 279
    :try_start_1
    iget-object v3, v0, Lt8/c;->i:Lo8/u;

    .line 280
    .line 281
    iget v6, v0, Lt8/c;->k:I

    .line 282
    .line 283
    invoke-static {v2, v3, v6, v10}, Lo8/b;->b(Lw7/p;Lo8/u;ILo8/s;)Z

    .line 284
    .line 285
    .line 286
    move-result v3
    :try_end_1
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_1 .. :try_end_1} :catch_1

    .line 287
    goto :goto_a

    .line 288
    :catch_1
    move v3, v4

    .line 289
    :goto_a
    iget v6, v2, Lw7/p;->b:I

    .line 290
    .line 291
    iget v11, v2, Lw7/p;->c:I

    .line 292
    .line 293
    if-le v6, v11, :cond_f

    .line 294
    .line 295
    move v3, v4

    .line 296
    :cond_f
    if-eqz v3, :cond_10

    .line 297
    .line 298
    invoke-virtual {v2, v5}, Lw7/p;->I(I)V

    .line 299
    .line 300
    .line 301
    iget-wide v5, v10, Lo8/s;->a:J

    .line 302
    .line 303
    goto :goto_c

    .line 304
    :cond_10
    add-int/lit8 v5, v5, 0x1

    .line 305
    .line 306
    goto :goto_9

    .line 307
    :cond_11
    invoke-virtual {v2, v3}, Lw7/p;->I(I)V

    .line 308
    .line 309
    .line 310
    goto :goto_b

    .line 311
    :cond_12
    invoke-virtual {v2, v5}, Lw7/p;->I(I)V

    .line 312
    .line 313
    .line 314
    :goto_b
    move-wide v5, v14

    .line 315
    :goto_c
    iget v3, v2, Lw7/p;->b:I

    .line 316
    .line 317
    sub-int/2addr v3, v1

    .line 318
    invoke-virtual {v2, v1}, Lw7/p;->I(I)V

    .line 319
    .line 320
    .line 321
    iget-object v1, v0, Lt8/c;->f:Lo8/i0;

    .line 322
    .line 323
    invoke-interface {v1, v2, v3, v4}, Lo8/i0;->a(Lw7/p;II)V

    .line 324
    .line 325
    .line 326
    iget v1, v0, Lt8/c;->m:I

    .line 327
    .line 328
    add-int/2addr v1, v3

    .line 329
    iput v1, v0, Lt8/c;->m:I

    .line 330
    .line 331
    cmp-long v3, v5, v14

    .line 332
    .line 333
    if-eqz v3, :cond_13

    .line 334
    .line 335
    iget-wide v10, v0, Lt8/c;->n:J

    .line 336
    .line 337
    mul-long/2addr v10, v7

    .line 338
    iget-object v3, v0, Lt8/c;->i:Lo8/u;

    .line 339
    .line 340
    sget-object v7, Lw7/w;->a:Ljava/lang/String;

    .line 341
    .line 342
    iget v3, v3, Lo8/u;->e:I

    .line 343
    .line 344
    int-to-long v7, v3

    .line 345
    div-long v17, v10, v7

    .line 346
    .line 347
    iget-object v3, v0, Lt8/c;->f:Lo8/i0;

    .line 348
    .line 349
    const/16 v21, 0x0

    .line 350
    .line 351
    const/16 v22, 0x0

    .line 352
    .line 353
    const/16 v19, 0x1

    .line 354
    .line 355
    move/from16 v20, v1

    .line 356
    .line 357
    move-object/from16 v16, v3

    .line 358
    .line 359
    invoke-interface/range {v16 .. v22}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 360
    .line 361
    .line 362
    iput v4, v0, Lt8/c;->m:I

    .line 363
    .line 364
    iput-wide v5, v0, Lt8/c;->n:J

    .line 365
    .line 366
    :cond_13
    iget-object v0, v2, Lw7/p;->a:[B

    .line 367
    .line 368
    array-length v0, v0

    .line 369
    iget v1, v2, Lw7/p;->c:I

    .line 370
    .line 371
    sub-int/2addr v0, v1

    .line 372
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 373
    .line 374
    .line 375
    move-result v1

    .line 376
    if-ge v1, v9, :cond_14

    .line 377
    .line 378
    if-ge v0, v9, :cond_14

    .line 379
    .line 380
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 381
    .line 382
    .line 383
    move-result v0

    .line 384
    iget-object v1, v2, Lw7/p;->a:[B

    .line 385
    .line 386
    iget v3, v2, Lw7/p;->b:I

    .line 387
    .line 388
    invoke-static {v1, v3, v1, v4, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 389
    .line 390
    .line 391
    invoke-virtual {v2, v4}, Lw7/p;->I(I)V

    .line 392
    .line 393
    .line 394
    invoke-virtual {v2, v0}, Lw7/p;->H(I)V

    .line 395
    .line 396
    .line 397
    :cond_14
    :goto_d
    return v4

    .line 398
    :cond_15
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 399
    .line 400
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 401
    .line 402
    .line 403
    throw v0

    .line 404
    :cond_16
    invoke-interface {v1}, Lo8/p;->e()V

    .line 405
    .line 406
    .line 407
    new-instance v2, Lw7/p;

    .line 408
    .line 409
    invoke-direct {v2, v6}, Lw7/p;-><init>(I)V

    .line 410
    .line 411
    .line 412
    iget-object v3, v2, Lw7/p;->a:[B

    .line 413
    .line 414
    invoke-interface {v1, v3, v4, v6}, Lo8/p;->o([BII)V

    .line 415
    .line 416
    .line 417
    invoke-virtual {v2}, Lw7/p;->C()I

    .line 418
    .line 419
    .line 420
    move-result v2

    .line 421
    shr-int/lit8 v3, v2, 0x2

    .line 422
    .line 423
    const/16 v8, 0x3ffe

    .line 424
    .line 425
    if-ne v3, v8, :cond_1b

    .line 426
    .line 427
    invoke-interface {v1}, Lo8/p;->e()V

    .line 428
    .line 429
    .line 430
    iput v2, v0, Lt8/c;->k:I

    .line 431
    .line 432
    iget-object v2, v0, Lt8/c;->e:Lo8/q;

    .line 433
    .line 434
    sget-object v3, Lw7/w;->a:Ljava/lang/String;

    .line 435
    .line 436
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 437
    .line 438
    .line 439
    move-result-wide v7

    .line 440
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 441
    .line 442
    .line 443
    move-result-wide v25

    .line 444
    iget-object v1, v0, Lt8/c;->i:Lo8/u;

    .line 445
    .line 446
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 447
    .line 448
    .line 449
    iget-object v1, v0, Lt8/c;->i:Lo8/u;

    .line 450
    .line 451
    iget-object v3, v1, Lo8/u;->k:Lb81/c;

    .line 452
    .line 453
    if-eqz v3, :cond_17

    .line 454
    .line 455
    iget-object v3, v3, Lb81/c;->e:Ljava/lang/Object;

    .line 456
    .line 457
    check-cast v3, [J

    .line 458
    .line 459
    array-length v3, v3

    .line 460
    if-lez v3, :cond_17

    .line 461
    .line 462
    new-instance v3, Lo8/t;

    .line 463
    .line 464
    invoke-direct {v3, v1, v7, v8, v4}, Lo8/t;-><init>(Ljava/lang/Object;JI)V

    .line 465
    .line 466
    .line 467
    move/from16 v30, v4

    .line 468
    .line 469
    goto/16 :goto_11

    .line 470
    .line 471
    :cond_17
    cmp-long v3, v25, v14

    .line 472
    .line 473
    if-eqz v3, :cond_1a

    .line 474
    .line 475
    iget-wide v9, v1, Lo8/u;->j:J

    .line 476
    .line 477
    cmp-long v3, v9, v12

    .line 478
    .line 479
    if-lez v3, :cond_1a

    .line 480
    .line 481
    new-instance v16, Lt8/b;

    .line 482
    .line 483
    iget v3, v0, Lt8/c;->k:I

    .line 484
    .line 485
    iget v9, v1, Lo8/u;->c:I

    .line 486
    .line 487
    new-instance v10, Lrx/b;

    .line 488
    .line 489
    invoke-direct {v10, v1, v6}, Lrx/b;-><init>(Ljava/lang/Object;I)V

    .line 490
    .line 491
    .line 492
    new-instance v6, Lt8/a;

    .line 493
    .line 494
    invoke-direct {v6, v1, v3}, Lt8/a;-><init>(Lo8/u;I)V

    .line 495
    .line 496
    .line 497
    invoke-virtual {v1}, Lo8/u;->b()J

    .line 498
    .line 499
    .line 500
    move-result-wide v19

    .line 501
    iget-wide v12, v1, Lo8/u;->j:J

    .line 502
    .line 503
    iget v3, v1, Lo8/u;->d:I

    .line 504
    .line 505
    if-lez v3, :cond_18

    .line 506
    .line 507
    int-to-long v14, v3

    .line 508
    move/from16 v30, v4

    .line 509
    .line 510
    int-to-long v4, v9

    .line 511
    add-long/2addr v14, v4

    .line 512
    const-wide/16 v3, 0x2

    .line 513
    .line 514
    div-long/2addr v14, v3

    .line 515
    const-wide/16 v3, 0x1

    .line 516
    .line 517
    add-long/2addr v14, v3

    .line 518
    :goto_e
    move-wide/from16 v27, v14

    .line 519
    .line 520
    goto :goto_10

    .line 521
    :cond_18
    move/from16 v30, v4

    .line 522
    .line 523
    iget v3, v1, Lo8/u;->a:I

    .line 524
    .line 525
    iget v4, v1, Lo8/u;->b:I

    .line 526
    .line 527
    if-ne v3, v4, :cond_19

    .line 528
    .line 529
    if-lez v3, :cond_19

    .line 530
    .line 531
    int-to-long v3, v3

    .line 532
    goto :goto_f

    .line 533
    :cond_19
    const-wide/16 v3, 0x1000

    .line 534
    .line 535
    :goto_f
    iget v5, v1, Lo8/u;->g:I

    .line 536
    .line 537
    int-to-long v14, v5

    .line 538
    mul-long/2addr v3, v14

    .line 539
    iget v1, v1, Lo8/u;->h:I

    .line 540
    .line 541
    int-to-long v14, v1

    .line 542
    mul-long/2addr v3, v14

    .line 543
    const-wide/16 v14, 0x8

    .line 544
    .line 545
    div-long/2addr v3, v14

    .line 546
    const-wide/16 v14, 0x40

    .line 547
    .line 548
    add-long/2addr v14, v3

    .line 549
    goto :goto_e

    .line 550
    :goto_10
    invoke-static {v11, v9}, Ljava/lang/Math;->max(II)I

    .line 551
    .line 552
    .line 553
    move-result v29

    .line 554
    move-object/from16 v18, v6

    .line 555
    .line 556
    move-wide/from16 v23, v7

    .line 557
    .line 558
    move-object/from16 v17, v10

    .line 559
    .line 560
    move-wide/from16 v21, v12

    .line 561
    .line 562
    invoke-direct/range {v16 .. v29}, Lo8/j;-><init>(Lo8/g;Lo8/i;JJJJJI)V

    .line 563
    .line 564
    .line 565
    move-object/from16 v1, v16

    .line 566
    .line 567
    iput-object v1, v0, Lt8/c;->l:Lt8/b;

    .line 568
    .line 569
    iget-object v1, v1, Lo8/j;->c:Ljava/lang/Object;

    .line 570
    .line 571
    move-object v3, v1

    .line 572
    check-cast v3, Lo8/e;

    .line 573
    .line 574
    goto :goto_11

    .line 575
    :cond_1a
    move/from16 v30, v4

    .line 576
    .line 577
    new-instance v3, Lo8/t;

    .line 578
    .line 579
    invoke-virtual {v1}, Lo8/u;->b()J

    .line 580
    .line 581
    .line 582
    move-result-wide v4

    .line 583
    invoke-direct {v3, v4, v5}, Lo8/t;-><init>(J)V

    .line 584
    .line 585
    .line 586
    :goto_11
    invoke-interface {v2, v3}, Lo8/q;->c(Lo8/c0;)V

    .line 587
    .line 588
    .line 589
    const/4 v1, 0x5

    .line 590
    iput v1, v0, Lt8/c;->g:I

    .line 591
    .line 592
    return v30

    .line 593
    :cond_1b
    invoke-interface {v1}, Lo8/p;->e()V

    .line 594
    .line 595
    .line 596
    const-string v0, "First frame does not start with sync code."

    .line 597
    .line 598
    invoke-static {v7, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 599
    .line 600
    .line 601
    move-result-object v0

    .line 602
    throw v0

    .line 603
    :cond_1c
    move/from16 v30, v4

    .line 604
    .line 605
    iget-object v2, v0, Lt8/c;->i:Lo8/u;

    .line 606
    .line 607
    move/from16 v3, v30

    .line 608
    .line 609
    :goto_12
    if-nez v3, :cond_24

    .line 610
    .line 611
    invoke-interface {v1}, Lo8/p;->e()V

    .line 612
    .line 613
    .line 614
    new-instance v3, Lm9/f;

    .line 615
    .line 616
    new-array v4, v8, [B

    .line 617
    .line 618
    invoke-direct {v3, v8, v4}, Lm9/f;-><init>(I[B)V

    .line 619
    .line 620
    .line 621
    move/from16 v6, v30

    .line 622
    .line 623
    invoke-interface {v1, v4, v6, v8}, Lo8/p;->o([BII)V

    .line 624
    .line 625
    .line 626
    invoke-virtual {v3}, Lm9/f;->h()Z

    .line 627
    .line 628
    .line 629
    move-result v4

    .line 630
    invoke-virtual {v3, v10}, Lm9/f;->i(I)I

    .line 631
    .line 632
    .line 633
    move-result v7

    .line 634
    const/16 v12, 0x18

    .line 635
    .line 636
    invoke-virtual {v3, v12}, Lm9/f;->i(I)I

    .line 637
    .line 638
    .line 639
    move-result v3

    .line 640
    add-int/2addr v3, v8

    .line 641
    if-nez v7, :cond_1d

    .line 642
    .line 643
    const/16 v2, 0x26

    .line 644
    .line 645
    new-array v3, v2, [B

    .line 646
    .line 647
    invoke-interface {v1, v3, v6, v2}, Lo8/p;->readFully([BII)V

    .line 648
    .line 649
    .line 650
    new-instance v2, Lo8/u;

    .line 651
    .line 652
    invoke-direct {v2, v8, v3}, Lo8/u;-><init>(I[B)V

    .line 653
    .line 654
    .line 655
    goto/16 :goto_18

    .line 656
    .line 657
    :cond_1d
    if-eqz v2, :cond_23

    .line 658
    .line 659
    iget-object v12, v2, Lo8/u;->l:Lt7/c0;

    .line 660
    .line 661
    if-ne v7, v9, :cond_1e

    .line 662
    .line 663
    new-instance v7, Lw7/p;

    .line 664
    .line 665
    invoke-direct {v7, v3}, Lw7/p;-><init>(I)V

    .line 666
    .line 667
    .line 668
    iget-object v12, v7, Lw7/p;->a:[B

    .line 669
    .line 670
    invoke-interface {v1, v12, v6, v3}, Lo8/p;->readFully([BII)V

    .line 671
    .line 672
    .line 673
    invoke-static {v7}, Lo8/b;->u(Lw7/p;)Lb81/c;

    .line 674
    .line 675
    .line 676
    move-result-object v23

    .line 677
    new-instance v13, Lo8/u;

    .line 678
    .line 679
    iget v14, v2, Lo8/u;->a:I

    .line 680
    .line 681
    iget v15, v2, Lo8/u;->b:I

    .line 682
    .line 683
    iget v3, v2, Lo8/u;->c:I

    .line 684
    .line 685
    iget v6, v2, Lo8/u;->d:I

    .line 686
    .line 687
    iget v7, v2, Lo8/u;->e:I

    .line 688
    .line 689
    iget v12, v2, Lo8/u;->g:I

    .line 690
    .line 691
    iget v10, v2, Lo8/u;->h:I

    .line 692
    .line 693
    move/from16 v20, v10

    .line 694
    .line 695
    iget-wide v9, v2, Lo8/u;->j:J

    .line 696
    .line 697
    iget-object v2, v2, Lo8/u;->l:Lt7/c0;

    .line 698
    .line 699
    move-object/from16 v24, v2

    .line 700
    .line 701
    move/from16 v16, v3

    .line 702
    .line 703
    move/from16 v17, v6

    .line 704
    .line 705
    move/from16 v18, v7

    .line 706
    .line 707
    move-wide/from16 v21, v9

    .line 708
    .line 709
    move/from16 v19, v12

    .line 710
    .line 711
    invoke-direct/range {v13 .. v24}, Lo8/u;-><init>(IIIIIIIJLb81/c;Lt7/c0;)V

    .line 712
    .line 713
    .line 714
    move-object v2, v13

    .line 715
    goto/16 :goto_18

    .line 716
    .line 717
    :cond_1e
    if-ne v7, v8, :cond_20

    .line 718
    .line 719
    new-instance v6, Lw7/p;

    .line 720
    .line 721
    invoke-direct {v6, v3}, Lw7/p;-><init>(I)V

    .line 722
    .line 723
    .line 724
    iget-object v7, v6, Lw7/p;->a:[B

    .line 725
    .line 726
    const/4 v9, 0x0

    .line 727
    invoke-interface {v1, v7, v9, v3}, Lo8/p;->readFully([BII)V

    .line 728
    .line 729
    .line 730
    invoke-virtual {v6, v8}, Lw7/p;->J(I)V

    .line 731
    .line 732
    .line 733
    invoke-static {v6, v9, v9}, Lo8/b;->v(Lw7/p;ZZ)Lhu/q;

    .line 734
    .line 735
    .line 736
    move-result-object v3

    .line 737
    iget-object v3, v3, Lhu/q;->e:Ljava/lang/Object;

    .line 738
    .line 739
    check-cast v3, [Ljava/lang/String;

    .line 740
    .line 741
    invoke-static {v3}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 742
    .line 743
    .line 744
    move-result-object v3

    .line 745
    invoke-static {v3}, Lo8/b;->r(Ljava/util/List;)Lt7/c0;

    .line 746
    .line 747
    .line 748
    move-result-object v3

    .line 749
    if-nez v12, :cond_1f

    .line 750
    .line 751
    :goto_13
    move-object/from16 v23, v3

    .line 752
    .line 753
    goto :goto_14

    .line 754
    :cond_1f
    invoke-virtual {v12, v3}, Lt7/c0;->b(Lt7/c0;)Lt7/c0;

    .line 755
    .line 756
    .line 757
    move-result-object v3

    .line 758
    goto :goto_13

    .line 759
    :goto_14
    new-instance v12, Lo8/u;

    .line 760
    .line 761
    iget v13, v2, Lo8/u;->a:I

    .line 762
    .line 763
    iget v14, v2, Lo8/u;->b:I

    .line 764
    .line 765
    iget v15, v2, Lo8/u;->c:I

    .line 766
    .line 767
    iget v3, v2, Lo8/u;->d:I

    .line 768
    .line 769
    iget v6, v2, Lo8/u;->e:I

    .line 770
    .line 771
    iget v7, v2, Lo8/u;->g:I

    .line 772
    .line 773
    iget v9, v2, Lo8/u;->h:I

    .line 774
    .line 775
    move/from16 v19, v9

    .line 776
    .line 777
    iget-wide v8, v2, Lo8/u;->j:J

    .line 778
    .line 779
    iget-object v2, v2, Lo8/u;->k:Lb81/c;

    .line 780
    .line 781
    move-object/from16 v22, v2

    .line 782
    .line 783
    move/from16 v16, v3

    .line 784
    .line 785
    move/from16 v17, v6

    .line 786
    .line 787
    move/from16 v18, v7

    .line 788
    .line 789
    move-wide/from16 v20, v8

    .line 790
    .line 791
    invoke-direct/range {v12 .. v23}, Lo8/u;-><init>(IIIIIIIJLb81/c;Lt7/c0;)V

    .line 792
    .line 793
    .line 794
    :goto_15
    move-object v2, v12

    .line 795
    goto :goto_18

    .line 796
    :cond_20
    if-ne v7, v11, :cond_22

    .line 797
    .line 798
    new-instance v6, Lw7/p;

    .line 799
    .line 800
    invoke-direct {v6, v3}, Lw7/p;-><init>(I)V

    .line 801
    .line 802
    .line 803
    iget-object v7, v6, Lw7/p;->a:[B

    .line 804
    .line 805
    const/4 v9, 0x0

    .line 806
    invoke-interface {v1, v7, v9, v3}, Lo8/p;->readFully([BII)V

    .line 807
    .line 808
    .line 809
    const/4 v10, 0x4

    .line 810
    invoke-virtual {v6, v10}, Lw7/p;->J(I)V

    .line 811
    .line 812
    .line 813
    invoke-static {v6}, La9/a;->d(Lw7/p;)La9/a;

    .line 814
    .line 815
    .line 816
    move-result-object v3

    .line 817
    invoke-static {v3}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 818
    .line 819
    .line 820
    move-result-object v3

    .line 821
    new-instance v6, Lt7/c0;

    .line 822
    .line 823
    invoke-direct {v6, v3}, Lt7/c0;-><init>(Ljava/util/List;)V

    .line 824
    .line 825
    .line 826
    if-nez v12, :cond_21

    .line 827
    .line 828
    :goto_16
    move-object/from16 v23, v6

    .line 829
    .line 830
    goto :goto_17

    .line 831
    :cond_21
    invoke-virtual {v12, v6}, Lt7/c0;->b(Lt7/c0;)Lt7/c0;

    .line 832
    .line 833
    .line 834
    move-result-object v6

    .line 835
    goto :goto_16

    .line 836
    :goto_17
    new-instance v12, Lo8/u;

    .line 837
    .line 838
    iget v13, v2, Lo8/u;->a:I

    .line 839
    .line 840
    iget v14, v2, Lo8/u;->b:I

    .line 841
    .line 842
    iget v15, v2, Lo8/u;->c:I

    .line 843
    .line 844
    iget v3, v2, Lo8/u;->d:I

    .line 845
    .line 846
    iget v6, v2, Lo8/u;->e:I

    .line 847
    .line 848
    iget v7, v2, Lo8/u;->g:I

    .line 849
    .line 850
    iget v8, v2, Lo8/u;->h:I

    .line 851
    .line 852
    iget-wide v10, v2, Lo8/u;->j:J

    .line 853
    .line 854
    iget-object v2, v2, Lo8/u;->k:Lb81/c;

    .line 855
    .line 856
    move-object/from16 v22, v2

    .line 857
    .line 858
    move/from16 v16, v3

    .line 859
    .line 860
    move/from16 v17, v6

    .line 861
    .line 862
    move/from16 v18, v7

    .line 863
    .line 864
    move/from16 v19, v8

    .line 865
    .line 866
    move-wide/from16 v20, v10

    .line 867
    .line 868
    invoke-direct/range {v12 .. v23}, Lo8/u;-><init>(IIIIIIIJLb81/c;Lt7/c0;)V

    .line 869
    .line 870
    .line 871
    goto :goto_15

    .line 872
    :cond_22
    invoke-interface {v1, v3}, Lo8/p;->n(I)V

    .line 873
    .line 874
    .line 875
    :goto_18
    sget-object v3, Lw7/w;->a:Ljava/lang/String;

    .line 876
    .line 877
    iput-object v2, v0, Lt8/c;->i:Lo8/u;

    .line 878
    .line 879
    move v3, v4

    .line 880
    const/4 v8, 0x4

    .line 881
    const/4 v9, 0x3

    .line 882
    const/4 v10, 0x7

    .line 883
    const/4 v11, 0x6

    .line 884
    const/16 v30, 0x0

    .line 885
    .line 886
    goto/16 :goto_12

    .line 887
    .line 888
    :cond_23
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 889
    .line 890
    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 891
    .line 892
    .line 893
    throw v0

    .line 894
    :cond_24
    iget-object v1, v0, Lt8/c;->i:Lo8/u;

    .line 895
    .line 896
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 897
    .line 898
    .line 899
    iget-object v1, v0, Lt8/c;->i:Lo8/u;

    .line 900
    .line 901
    iget v1, v1, Lo8/u;->c:I

    .line 902
    .line 903
    const/4 v9, 0x6

    .line 904
    invoke-static {v1, v9}, Ljava/lang/Math;->max(II)I

    .line 905
    .line 906
    .line 907
    move-result v1

    .line 908
    iput v1, v0, Lt8/c;->j:I

    .line 909
    .line 910
    iget-object v1, v0, Lt8/c;->i:Lo8/u;

    .line 911
    .line 912
    iget-object v2, v0, Lt8/c;->h:Lt7/c0;

    .line 913
    .line 914
    invoke-virtual {v1, v5, v2}, Lo8/u;->c([BLt7/c0;)Lt7/o;

    .line 915
    .line 916
    .line 917
    move-result-object v1

    .line 918
    iget-object v2, v0, Lt8/c;->f:Lo8/i0;

    .line 919
    .line 920
    invoke-virtual {v1}, Lt7/o;->a()Lt7/n;

    .line 921
    .line 922
    .line 923
    move-result-object v1

    .line 924
    const-string v3, "audio/flac"

    .line 925
    .line 926
    invoke-static {v3}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 927
    .line 928
    .line 929
    move-result-object v3

    .line 930
    iput-object v3, v1, Lt7/n;->l:Ljava/lang/String;

    .line 931
    .line 932
    invoke-static {v1, v2}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 933
    .line 934
    .line 935
    iget-object v1, v0, Lt8/c;->f:Lo8/i0;

    .line 936
    .line 937
    iget-object v2, v0, Lt8/c;->i:Lo8/u;

    .line 938
    .line 939
    invoke-virtual {v2}, Lo8/u;->b()J

    .line 940
    .line 941
    .line 942
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 943
    .line 944
    .line 945
    const/4 v10, 0x4

    .line 946
    iput v10, v0, Lt8/c;->g:I

    .line 947
    .line 948
    const/4 v9, 0x0

    .line 949
    return v9

    .line 950
    :cond_25
    move v9, v4

    .line 951
    move v10, v8

    .line 952
    new-instance v2, Lw7/p;

    .line 953
    .line 954
    invoke-direct {v2, v10}, Lw7/p;-><init>(I)V

    .line 955
    .line 956
    .line 957
    iget-object v3, v2, Lw7/p;->a:[B

    .line 958
    .line 959
    invoke-interface {v1, v3, v9, v10}, Lo8/p;->readFully([BII)V

    .line 960
    .line 961
    .line 962
    invoke-virtual {v2}, Lw7/p;->y()J

    .line 963
    .line 964
    .line 965
    move-result-wide v1

    .line 966
    const-wide/32 v3, 0x664c6143

    .line 967
    .line 968
    .line 969
    cmp-long v1, v1, v3

    .line 970
    .line 971
    if-nez v1, :cond_26

    .line 972
    .line 973
    const/4 v1, 0x3

    .line 974
    iput v1, v0, Lt8/c;->g:I

    .line 975
    .line 976
    return v9

    .line 977
    :cond_26
    const-string v0, "Failed to read FLAC stream marker."

    .line 978
    .line 979
    invoke-static {v7, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 980
    .line 981
    .line 982
    move-result-object v0

    .line 983
    throw v0

    .line 984
    :cond_27
    move v9, v4

    .line 985
    array-length v2, v5

    .line 986
    invoke-interface {v1, v5, v9, v2}, Lo8/p;->o([BII)V

    .line 987
    .line 988
    .line 989
    invoke-interface {v1}, Lo8/p;->e()V

    .line 990
    .line 991
    .line 992
    iput v6, v0, Lt8/c;->g:I

    .line 993
    .line 994
    return v9

    .line 995
    :cond_28
    iget-boolean v2, v0, Lt8/c;->c:Z

    .line 996
    .line 997
    xor-int/2addr v2, v3

    .line 998
    invoke-interface {v1}, Lo8/p;->e()V

    .line 999
    .line 1000
    .line 1001
    invoke-interface {v1}, Lo8/p;->h()J

    .line 1002
    .line 1003
    .line 1004
    move-result-wide v4

    .line 1005
    invoke-static {v1, v2}, Lo8/b;->s(Lo8/p;Z)Lt7/c0;

    .line 1006
    .line 1007
    .line 1008
    move-result-object v2

    .line 1009
    invoke-interface {v1}, Lo8/p;->h()J

    .line 1010
    .line 1011
    .line 1012
    move-result-wide v6

    .line 1013
    sub-long/2addr v6, v4

    .line 1014
    long-to-int v4, v6

    .line 1015
    invoke-interface {v1, v4}, Lo8/p;->n(I)V

    .line 1016
    .line 1017
    .line 1018
    iput-object v2, v0, Lt8/c;->h:Lt7/c0;

    .line 1019
    .line 1020
    iput v3, v0, Lt8/c;->g:I

    .line 1021
    .line 1022
    const/16 v30, 0x0

    .line 1023
    .line 1024
    return v30
.end method
