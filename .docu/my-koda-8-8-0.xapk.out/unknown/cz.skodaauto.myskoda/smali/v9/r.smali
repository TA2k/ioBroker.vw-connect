.class public final Lv9/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv9/h;


# instance fields
.field public final a:Lv9/c0;

.field public b:Ljava/lang/String;

.field public c:Lo8/i0;

.field public d:Lv9/q;

.field public e:Z

.field public final f:[Z

.field public final g:La8/n0;

.field public final h:La8/n0;

.field public final i:La8/n0;

.field public final j:La8/n0;

.field public final k:La8/n0;

.field public l:J

.field public m:J

.field public final n:Lw7/p;


# direct methods
.method public constructor <init>(Lv9/c0;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv9/r;->a:Lv9/c0;

    .line 5
    .line 6
    const/4 p1, 0x3

    .line 7
    new-array p1, p1, [Z

    .line 8
    .line 9
    iput-object p1, p0, Lv9/r;->f:[Z

    .line 10
    .line 11
    new-instance p1, La8/n0;

    .line 12
    .line 13
    const/16 v0, 0x20

    .line 14
    .line 15
    invoke-direct {p1, v0}, La8/n0;-><init>(I)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lv9/r;->g:La8/n0;

    .line 19
    .line 20
    new-instance p1, La8/n0;

    .line 21
    .line 22
    const/16 v0, 0x21

    .line 23
    .line 24
    invoke-direct {p1, v0}, La8/n0;-><init>(I)V

    .line 25
    .line 26
    .line 27
    iput-object p1, p0, Lv9/r;->h:La8/n0;

    .line 28
    .line 29
    new-instance p1, La8/n0;

    .line 30
    .line 31
    const/16 v0, 0x22

    .line 32
    .line 33
    invoke-direct {p1, v0}, La8/n0;-><init>(I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, p0, Lv9/r;->i:La8/n0;

    .line 37
    .line 38
    new-instance p1, La8/n0;

    .line 39
    .line 40
    const/16 v0, 0x27

    .line 41
    .line 42
    invoke-direct {p1, v0}, La8/n0;-><init>(I)V

    .line 43
    .line 44
    .line 45
    iput-object p1, p0, Lv9/r;->j:La8/n0;

    .line 46
    .line 47
    new-instance p1, La8/n0;

    .line 48
    .line 49
    const/16 v0, 0x28

    .line 50
    .line 51
    invoke-direct {p1, v0}, La8/n0;-><init>(I)V

    .line 52
    .line 53
    .line 54
    iput-object p1, p0, Lv9/r;->k:La8/n0;

    .line 55
    .line 56
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 57
    .line 58
    .line 59
    .line 60
    .line 61
    iput-wide v0, p0, Lv9/r;->m:J

    .line 62
    .line 63
    new-instance p1, Lw7/p;

    .line 64
    .line 65
    invoke-direct {p1}, Lw7/p;-><init>()V

    .line 66
    .line 67
    .line 68
    iput-object p1, p0, Lv9/r;->n:Lw7/p;

    .line 69
    .line 70
    return-void
.end method


# virtual methods
.method public final a(JIIJ)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p4

    .line 4
    .line 5
    move-wide/from16 v2, p5

    .line 6
    .line 7
    iget-object v4, v0, Lv9/r;->a:Lv9/c0;

    .line 8
    .line 9
    iget-object v4, v4, Lv9/c0;->d:Lca/j;

    .line 10
    .line 11
    iget-object v5, v0, Lv9/r;->d:Lv9/q;

    .line 12
    .line 13
    iget-boolean v6, v0, Lv9/r;->e:Z

    .line 14
    .line 15
    iget-boolean v7, v5, Lv9/q;->j:Z

    .line 16
    .line 17
    const/4 v8, 0x0

    .line 18
    const/4 v9, 0x1

    .line 19
    if-eqz v7, :cond_0

    .line 20
    .line 21
    iget-boolean v7, v5, Lv9/q;->g:Z

    .line 22
    .line 23
    if-eqz v7, :cond_0

    .line 24
    .line 25
    iget-boolean v6, v5, Lv9/q;->c:Z

    .line 26
    .line 27
    iput-boolean v6, v5, Lv9/q;->m:Z

    .line 28
    .line 29
    iput-boolean v8, v5, Lv9/q;->j:Z

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    iget-boolean v7, v5, Lv9/q;->h:Z

    .line 33
    .line 34
    if-nez v7, :cond_1

    .line 35
    .line 36
    iget-boolean v7, v5, Lv9/q;->g:Z

    .line 37
    .line 38
    if-eqz v7, :cond_3

    .line 39
    .line 40
    :cond_1
    if-eqz v6, :cond_2

    .line 41
    .line 42
    iget-boolean v6, v5, Lv9/q;->i:Z

    .line 43
    .line 44
    if-eqz v6, :cond_2

    .line 45
    .line 46
    iget-wide v6, v5, Lv9/q;->b:J

    .line 47
    .line 48
    sub-long v6, p1, v6

    .line 49
    .line 50
    long-to-int v6, v6

    .line 51
    add-int v6, p3, v6

    .line 52
    .line 53
    invoke-virtual {v5, v6}, Lv9/q;->a(I)V

    .line 54
    .line 55
    .line 56
    :cond_2
    iget-wide v6, v5, Lv9/q;->b:J

    .line 57
    .line 58
    iput-wide v6, v5, Lv9/q;->k:J

    .line 59
    .line 60
    iget-wide v6, v5, Lv9/q;->e:J

    .line 61
    .line 62
    iput-wide v6, v5, Lv9/q;->l:J

    .line 63
    .line 64
    iget-boolean v6, v5, Lv9/q;->c:Z

    .line 65
    .line 66
    iput-boolean v6, v5, Lv9/q;->m:Z

    .line 67
    .line 68
    iput-boolean v9, v5, Lv9/q;->i:Z

    .line 69
    .line 70
    :cond_3
    :goto_0
    iget-boolean v5, v0, Lv9/r;->e:Z

    .line 71
    .line 72
    if-nez v5, :cond_6

    .line 73
    .line 74
    iget-object v5, v0, Lv9/r;->g:La8/n0;

    .line 75
    .line 76
    invoke-virtual {v5, v1}, La8/n0;->e(I)Z

    .line 77
    .line 78
    .line 79
    iget-object v6, v0, Lv9/r;->h:La8/n0;

    .line 80
    .line 81
    invoke-virtual {v6, v1}, La8/n0;->e(I)Z

    .line 82
    .line 83
    .line 84
    iget-object v7, v0, Lv9/r;->i:La8/n0;

    .line 85
    .line 86
    invoke-virtual {v7, v1}, La8/n0;->e(I)Z

    .line 87
    .line 88
    .line 89
    iget-boolean v10, v5, La8/n0;->e:Z

    .line 90
    .line 91
    if-eqz v10, :cond_6

    .line 92
    .line 93
    iget-boolean v10, v6, La8/n0;->e:Z

    .line 94
    .line 95
    if-eqz v10, :cond_6

    .line 96
    .line 97
    iget-boolean v10, v7, La8/n0;->e:Z

    .line 98
    .line 99
    if-eqz v10, :cond_6

    .line 100
    .line 101
    iget-object v10, v0, Lv9/r;->b:Ljava/lang/String;

    .line 102
    .line 103
    iget v11, v5, La8/n0;->c:I

    .line 104
    .line 105
    iget v12, v6, La8/n0;->c:I

    .line 106
    .line 107
    add-int/2addr v12, v11

    .line 108
    iget v13, v7, La8/n0;->c:I

    .line 109
    .line 110
    add-int/2addr v12, v13

    .line 111
    new-array v12, v12, [B

    .line 112
    .line 113
    iget-object v13, v5, La8/n0;->f:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v13, [B

    .line 116
    .line 117
    invoke-static {v13, v8, v12, v8, v11}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 118
    .line 119
    .line 120
    iget-object v11, v6, La8/n0;->f:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v11, [B

    .line 123
    .line 124
    iget v13, v5, La8/n0;->c:I

    .line 125
    .line 126
    iget v14, v6, La8/n0;->c:I

    .line 127
    .line 128
    invoke-static {v11, v8, v12, v13, v14}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 129
    .line 130
    .line 131
    iget-object v11, v7, La8/n0;->f:Ljava/lang/Object;

    .line 132
    .line 133
    check-cast v11, [B

    .line 134
    .line 135
    iget v5, v5, La8/n0;->c:I

    .line 136
    .line 137
    iget v13, v6, La8/n0;->c:I

    .line 138
    .line 139
    add-int/2addr v5, v13

    .line 140
    iget v7, v7, La8/n0;->c:I

    .line 141
    .line 142
    invoke-static {v11, v8, v12, v5, v7}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 143
    .line 144
    .line 145
    iget-object v5, v6, La8/n0;->f:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v5, [B

    .line 148
    .line 149
    iget v6, v6, La8/n0;->c:I

    .line 150
    .line 151
    const/4 v7, 0x3

    .line 152
    const/4 v8, 0x0

    .line 153
    invoke-static {v5, v7, v6, v8}, Lx7/n;->h([BIILun/a;)Lx7/j;

    .line 154
    .line 155
    .line 156
    move-result-object v5

    .line 157
    iget-object v6, v5, Lx7/j;->b:Lx7/h;

    .line 158
    .line 159
    if-eqz v6, :cond_4

    .line 160
    .line 161
    iget v13, v6, Lx7/h;->a:I

    .line 162
    .line 163
    iget-boolean v14, v6, Lx7/h;->b:Z

    .line 164
    .line 165
    iget v15, v6, Lx7/h;->c:I

    .line 166
    .line 167
    iget v7, v6, Lx7/h;->d:I

    .line 168
    .line 169
    iget-object v8, v6, Lx7/h;->e:[I

    .line 170
    .line 171
    iget v6, v6, Lx7/h;->f:I

    .line 172
    .line 173
    move/from16 v18, v6

    .line 174
    .line 175
    move/from16 v16, v7

    .line 176
    .line 177
    move-object/from16 v17, v8

    .line 178
    .line 179
    invoke-static/range {v13 .. v18}, Lw7/c;->a(IZII[II)Ljava/lang/String;

    .line 180
    .line 181
    .line 182
    move-result-object v8

    .line 183
    :cond_4
    new-instance v6, Lt7/n;

    .line 184
    .line 185
    invoke-direct {v6}, Lt7/n;-><init>()V

    .line 186
    .line 187
    .line 188
    iput-object v10, v6, Lt7/n;->a:Ljava/lang/String;

    .line 189
    .line 190
    const-string v7, "video/mp2t"

    .line 191
    .line 192
    invoke-static {v7}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 193
    .line 194
    .line 195
    move-result-object v7

    .line 196
    iput-object v7, v6, Lt7/n;->l:Ljava/lang/String;

    .line 197
    .line 198
    const-string v7, "video/hevc"

    .line 199
    .line 200
    invoke-static {v7}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object v7

    .line 204
    iput-object v7, v6, Lt7/n;->m:Ljava/lang/String;

    .line 205
    .line 206
    iput-object v8, v6, Lt7/n;->j:Ljava/lang/String;

    .line 207
    .line 208
    iget v7, v5, Lx7/j;->e:I

    .line 209
    .line 210
    iput v7, v6, Lt7/n;->t:I

    .line 211
    .line 212
    iget v7, v5, Lx7/j;->f:I

    .line 213
    .line 214
    iput v7, v6, Lt7/n;->u:I

    .line 215
    .line 216
    iget v7, v5, Lx7/j;->g:I

    .line 217
    .line 218
    iput v7, v6, Lt7/n;->v:I

    .line 219
    .line 220
    iget v7, v5, Lx7/j;->h:I

    .line 221
    .line 222
    iput v7, v6, Lt7/n;->w:I

    .line 223
    .line 224
    iget v14, v5, Lx7/j;->k:I

    .line 225
    .line 226
    iget v15, v5, Lx7/j;->l:I

    .line 227
    .line 228
    iget v7, v5, Lx7/j;->m:I

    .line 229
    .line 230
    iget v8, v5, Lx7/j;->c:I

    .line 231
    .line 232
    add-int/lit8 v17, v8, 0x8

    .line 233
    .line 234
    iget v8, v5, Lx7/j;->d:I

    .line 235
    .line 236
    add-int/lit8 v18, v8, 0x8

    .line 237
    .line 238
    new-instance v13, Lt7/f;

    .line 239
    .line 240
    const/16 v19, 0x0

    .line 241
    .line 242
    move/from16 v16, v7

    .line 243
    .line 244
    invoke-direct/range {v13 .. v19}, Lt7/f;-><init>(IIIII[B)V

    .line 245
    .line 246
    .line 247
    iput-object v13, v6, Lt7/n;->C:Lt7/f;

    .line 248
    .line 249
    iget v7, v5, Lx7/j;->i:F

    .line 250
    .line 251
    iput v7, v6, Lt7/n;->z:F

    .line 252
    .line 253
    iget v7, v5, Lx7/j;->j:I

    .line 254
    .line 255
    iput v7, v6, Lt7/n;->o:I

    .line 256
    .line 257
    iget v5, v5, Lx7/j;->a:I

    .line 258
    .line 259
    add-int/2addr v5, v9

    .line 260
    iput v5, v6, Lt7/n;->D:I

    .line 261
    .line 262
    invoke-static {v12}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 263
    .line 264
    .line 265
    move-result-object v5

    .line 266
    iput-object v5, v6, Lt7/n;->p:Ljava/util/List;

    .line 267
    .line 268
    new-instance v5, Lt7/o;

    .line 269
    .line 270
    invoke-direct {v5, v6}, Lt7/o;-><init>(Lt7/n;)V

    .line 271
    .line 272
    .line 273
    iget-object v6, v0, Lv9/r;->c:Lo8/i0;

    .line 274
    .line 275
    invoke-interface {v6, v5}, Lo8/i0;->c(Lt7/o;)V

    .line 276
    .line 277
    .line 278
    const/4 v6, -0x1

    .line 279
    iget v5, v5, Lt7/o;->p:I

    .line 280
    .line 281
    if-eq v5, v6, :cond_5

    .line 282
    .line 283
    invoke-virtual {v4, v5}, Lca/j;->m(I)V

    .line 284
    .line 285
    .line 286
    iput-boolean v9, v0, Lv9/r;->e:Z

    .line 287
    .line 288
    goto :goto_1

    .line 289
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 290
    .line 291
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 292
    .line 293
    .line 294
    throw v0

    .line 295
    :cond_6
    :goto_1
    iget-object v5, v0, Lv9/r;->j:La8/n0;

    .line 296
    .line 297
    invoke-virtual {v5, v1}, La8/n0;->e(I)Z

    .line 298
    .line 299
    .line 300
    move-result v6

    .line 301
    const/4 v7, 0x5

    .line 302
    iget-object v8, v0, Lv9/r;->n:Lw7/p;

    .line 303
    .line 304
    if-eqz v6, :cond_7

    .line 305
    .line 306
    iget-object v6, v5, La8/n0;->f:Ljava/lang/Object;

    .line 307
    .line 308
    check-cast v6, [B

    .line 309
    .line 310
    iget v9, v5, La8/n0;->c:I

    .line 311
    .line 312
    invoke-static {v9, v6}, Lx7/n;->m(I[B)I

    .line 313
    .line 314
    .line 315
    move-result v6

    .line 316
    iget-object v5, v5, La8/n0;->f:Ljava/lang/Object;

    .line 317
    .line 318
    check-cast v5, [B

    .line 319
    .line 320
    invoke-virtual {v8, v6, v5}, Lw7/p;->G(I[B)V

    .line 321
    .line 322
    .line 323
    invoke-virtual {v8, v7}, Lw7/p;->J(I)V

    .line 324
    .line 325
    .line 326
    invoke-virtual {v4, v2, v3, v8}, Lca/j;->a(JLw7/p;)V

    .line 327
    .line 328
    .line 329
    :cond_7
    iget-object v0, v0, Lv9/r;->k:La8/n0;

    .line 330
    .line 331
    invoke-virtual {v0, v1}, La8/n0;->e(I)Z

    .line 332
    .line 333
    .line 334
    move-result v1

    .line 335
    if-eqz v1, :cond_8

    .line 336
    .line 337
    iget-object v1, v0, La8/n0;->f:Ljava/lang/Object;

    .line 338
    .line 339
    check-cast v1, [B

    .line 340
    .line 341
    iget v5, v0, La8/n0;->c:I

    .line 342
    .line 343
    invoke-static {v5, v1}, Lx7/n;->m(I[B)I

    .line 344
    .line 345
    .line 346
    move-result v1

    .line 347
    iget-object v0, v0, La8/n0;->f:Ljava/lang/Object;

    .line 348
    .line 349
    check-cast v0, [B

    .line 350
    .line 351
    invoke-virtual {v8, v1, v0}, Lw7/p;->G(I[B)V

    .line 352
    .line 353
    .line 354
    invoke-virtual {v8, v7}, Lw7/p;->J(I)V

    .line 355
    .line 356
    .line 357
    invoke-virtual {v4, v2, v3, v8}, Lca/j;->a(JLw7/p;)V

    .line 358
    .line 359
    .line 360
    :cond_8
    return-void
.end method

.method public final b(Lw7/p;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v7, p1

    .line 4
    .line 5
    iget-object v1, v0, Lv9/r;->c:Lo8/i0;

    .line 6
    .line 7
    invoke-static {v1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 11
    .line 12
    :goto_0
    invoke-virtual {v7}, Lw7/p;->a()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-lez v1, :cond_5

    .line 17
    .line 18
    iget v1, v7, Lw7/p;->b:I

    .line 19
    .line 20
    iget v8, v7, Lw7/p;->c:I

    .line 21
    .line 22
    iget-object v9, v7, Lw7/p;->a:[B

    .line 23
    .line 24
    iget-wide v2, v0, Lv9/r;->l:J

    .line 25
    .line 26
    invoke-virtual {v7}, Lw7/p;->a()I

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    int-to-long v4, v4

    .line 31
    add-long/2addr v2, v4

    .line 32
    iput-wide v2, v0, Lv9/r;->l:J

    .line 33
    .line 34
    iget-object v2, v0, Lv9/r;->c:Lo8/i0;

    .line 35
    .line 36
    invoke-virtual {v7}, Lw7/p;->a()I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    const/4 v10, 0x0

    .line 41
    invoke-interface {v2, v7, v3, v10}, Lo8/i0;->a(Lw7/p;II)V

    .line 42
    .line 43
    .line 44
    :goto_1
    if-ge v1, v8, :cond_4

    .line 45
    .line 46
    iget-object v2, v0, Lv9/r;->f:[Z

    .line 47
    .line 48
    invoke-static {v9, v1, v8, v2}, Lx7/n;->b([BII[Z)I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-ne v2, v8, :cond_0

    .line 53
    .line 54
    invoke-virtual {v0, v9, v1, v8}, Lv9/r;->g([BII)V

    .line 55
    .line 56
    .line 57
    return-void

    .line 58
    :cond_0
    add-int/lit8 v3, v2, 0x3

    .line 59
    .line 60
    aget-byte v3, v9, v3

    .line 61
    .line 62
    and-int/lit8 v3, v3, 0x7e

    .line 63
    .line 64
    shr-int/lit8 v11, v3, 0x1

    .line 65
    .line 66
    if-lez v2, :cond_1

    .line 67
    .line 68
    add-int/lit8 v3, v2, -0x1

    .line 69
    .line 70
    aget-byte v3, v9, v3

    .line 71
    .line 72
    if-nez v3, :cond_1

    .line 73
    .line 74
    add-int/lit8 v2, v2, -0x1

    .line 75
    .line 76
    const/4 v3, 0x4

    .line 77
    :goto_2
    move v12, v2

    .line 78
    move v13, v3

    .line 79
    goto :goto_3

    .line 80
    :cond_1
    const/4 v3, 0x3

    .line 81
    goto :goto_2

    .line 82
    :goto_3
    sub-int v2, v12, v1

    .line 83
    .line 84
    if-lez v2, :cond_2

    .line 85
    .line 86
    invoke-virtual {v0, v9, v1, v12}, Lv9/r;->g([BII)V

    .line 87
    .line 88
    .line 89
    :cond_2
    sub-int v3, v8, v12

    .line 90
    .line 91
    iget-wide v4, v0, Lv9/r;->l:J

    .line 92
    .line 93
    int-to-long v14, v3

    .line 94
    sub-long/2addr v4, v14

    .line 95
    if-gez v2, :cond_3

    .line 96
    .line 97
    neg-int v1, v2

    .line 98
    :goto_4
    move-wide v14, v4

    .line 99
    goto :goto_5

    .line 100
    :cond_3
    move v1, v10

    .line 101
    goto :goto_4

    .line 102
    :goto_5
    iget-wide v5, v0, Lv9/r;->m:J

    .line 103
    .line 104
    move v4, v1

    .line 105
    move-wide v1, v14

    .line 106
    invoke-virtual/range {v0 .. v6}, Lv9/r;->a(JIIJ)V

    .line 107
    .line 108
    .line 109
    iget-wide v5, v0, Lv9/r;->m:J

    .line 110
    .line 111
    move v4, v11

    .line 112
    invoke-virtual/range {v0 .. v6}, Lv9/r;->h(JIIJ)V

    .line 113
    .line 114
    .line 115
    add-int v1, v12, v13

    .line 116
    .line 117
    move-object/from16 v0, p0

    .line 118
    .line 119
    goto :goto_1

    .line 120
    :cond_4
    move-object/from16 v0, p0

    .line 121
    .line 122
    goto :goto_0

    .line 123
    :cond_5
    return-void
.end method

.method public final c()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lv9/r;->l:J

    .line 4
    .line 5
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    iput-wide v0, p0, Lv9/r;->m:J

    .line 11
    .line 12
    iget-object v0, p0, Lv9/r;->f:[Z

    .line 13
    .line 14
    invoke-static {v0}, Lx7/n;->a([Z)V

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lv9/r;->g:La8/n0;

    .line 18
    .line 19
    invoke-virtual {v0}, La8/n0;->g()V

    .line 20
    .line 21
    .line 22
    iget-object v0, p0, Lv9/r;->h:La8/n0;

    .line 23
    .line 24
    invoke-virtual {v0}, La8/n0;->g()V

    .line 25
    .line 26
    .line 27
    iget-object v0, p0, Lv9/r;->i:La8/n0;

    .line 28
    .line 29
    invoke-virtual {v0}, La8/n0;->g()V

    .line 30
    .line 31
    .line 32
    iget-object v0, p0, Lv9/r;->j:La8/n0;

    .line 33
    .line 34
    invoke-virtual {v0}, La8/n0;->g()V

    .line 35
    .line 36
    .line 37
    iget-object v0, p0, Lv9/r;->k:La8/n0;

    .line 38
    .line 39
    invoke-virtual {v0}, La8/n0;->g()V

    .line 40
    .line 41
    .line 42
    iget-object v0, p0, Lv9/r;->a:Lv9/c0;

    .line 43
    .line 44
    iget-object v0, v0, Lv9/c0;->d:Lca/j;

    .line 45
    .line 46
    const/4 v1, 0x0

    .line 47
    invoke-virtual {v0, v1}, Lca/j;->d(I)V

    .line 48
    .line 49
    .line 50
    iget-object p0, p0, Lv9/r;->d:Lv9/q;

    .line 51
    .line 52
    if-eqz p0, :cond_0

    .line 53
    .line 54
    iput-boolean v1, p0, Lv9/q;->f:Z

    .line 55
    .line 56
    iput-boolean v1, p0, Lv9/q;->g:Z

    .line 57
    .line 58
    iput-boolean v1, p0, Lv9/q;->h:Z

    .line 59
    .line 60
    iput-boolean v1, p0, Lv9/q;->i:Z

    .line 61
    .line 62
    iput-boolean v1, p0, Lv9/q;->j:Z

    .line 63
    .line 64
    :cond_0
    return-void
.end method

.method public final d(Lo8/q;Lh11/h;)V
    .locals 2

    .line 1
    invoke-virtual {p2}, Lh11/h;->d()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 5
    .line 6
    .line 7
    iget-object v0, p2, Lh11/h;->h:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Ljava/lang/String;

    .line 10
    .line 11
    iput-object v0, p0, Lv9/r;->b:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 14
    .line 15
    .line 16
    iget v0, p2, Lh11/h;->f:I

    .line 17
    .line 18
    const/4 v1, 0x2

    .line 19
    invoke-interface {p1, v0, v1}, Lo8/q;->q(II)Lo8/i0;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    iput-object v0, p0, Lv9/r;->c:Lo8/i0;

    .line 24
    .line 25
    new-instance v1, Lv9/q;

    .line 26
    .line 27
    invoke-direct {v1, v0}, Lv9/q;-><init>(Lo8/i0;)V

    .line 28
    .line 29
    .line 30
    iput-object v1, p0, Lv9/r;->d:Lv9/q;

    .line 31
    .line 32
    iget-object p0, p0, Lv9/r;->a:Lv9/c0;

    .line 33
    .line 34
    invoke-virtual {p0, p1, p2}, Lv9/c0;->b(Lo8/q;Lh11/h;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public final e(Z)V
    .locals 7

    .line 1
    iget-object v1, p0, Lv9/r;->c:Lo8/i0;

    .line 2
    .line 3
    invoke-static {v1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    iget-object v1, p0, Lv9/r;->a:Lv9/c0;

    .line 11
    .line 12
    iget-object v1, v1, Lv9/c0;->d:Lca/j;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    invoke-virtual {v1, v2}, Lca/j;->d(I)V

    .line 16
    .line 17
    .line 18
    iget-wide v1, p0, Lv9/r;->l:J

    .line 19
    .line 20
    const/4 v4, 0x0

    .line 21
    iget-wide v5, p0, Lv9/r;->m:J

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    move-object v0, p0

    .line 25
    invoke-virtual/range {v0 .. v6}, Lv9/r;->a(JIIJ)V

    .line 26
    .line 27
    .line 28
    iget-wide v1, p0, Lv9/r;->l:J

    .line 29
    .line 30
    const/16 v4, 0x30

    .line 31
    .line 32
    iget-wide v5, p0, Lv9/r;->m:J

    .line 33
    .line 34
    invoke-virtual/range {v0 .. v6}, Lv9/r;->h(JIIJ)V

    .line 35
    .line 36
    .line 37
    :cond_0
    return-void
.end method

.method public final f(IJ)V
    .locals 0

    .line 1
    iput-wide p2, p0, Lv9/r;->m:J

    .line 2
    .line 3
    return-void
.end method

.method public final g([BII)V
    .locals 3

    .line 1
    iget-object v0, p0, Lv9/r;->d:Lv9/q;

    .line 2
    .line 3
    iget-boolean v1, v0, Lv9/q;->f:Z

    .line 4
    .line 5
    if-eqz v1, :cond_2

    .line 6
    .line 7
    add-int/lit8 v1, p2, 0x2

    .line 8
    .line 9
    iget v2, v0, Lv9/q;->d:I

    .line 10
    .line 11
    sub-int/2addr v1, v2

    .line 12
    if-ge v1, p3, :cond_1

    .line 13
    .line 14
    aget-byte v1, p1, v1

    .line 15
    .line 16
    and-int/lit16 v1, v1, 0x80

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v1, v2

    .line 24
    :goto_0
    iput-boolean v1, v0, Lv9/q;->g:Z

    .line 25
    .line 26
    iput-boolean v2, v0, Lv9/q;->f:Z

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    sub-int v1, p3, p2

    .line 30
    .line 31
    add-int/2addr v1, v2

    .line 32
    iput v1, v0, Lv9/q;->d:I

    .line 33
    .line 34
    :cond_2
    :goto_1
    iget-boolean v0, p0, Lv9/r;->e:Z

    .line 35
    .line 36
    if-nez v0, :cond_3

    .line 37
    .line 38
    iget-object v0, p0, Lv9/r;->g:La8/n0;

    .line 39
    .line 40
    invoke-virtual {v0, p1, p2, p3}, La8/n0;->a([BII)V

    .line 41
    .line 42
    .line 43
    iget-object v0, p0, Lv9/r;->h:La8/n0;

    .line 44
    .line 45
    invoke-virtual {v0, p1, p2, p3}, La8/n0;->a([BII)V

    .line 46
    .line 47
    .line 48
    iget-object v0, p0, Lv9/r;->i:La8/n0;

    .line 49
    .line 50
    invoke-virtual {v0, p1, p2, p3}, La8/n0;->a([BII)V

    .line 51
    .line 52
    .line 53
    :cond_3
    iget-object v0, p0, Lv9/r;->j:La8/n0;

    .line 54
    .line 55
    invoke-virtual {v0, p1, p2, p3}, La8/n0;->a([BII)V

    .line 56
    .line 57
    .line 58
    iget-object p0, p0, Lv9/r;->k:La8/n0;

    .line 59
    .line 60
    invoke-virtual {p0, p1, p2, p3}, La8/n0;->a([BII)V

    .line 61
    .line 62
    .line 63
    return-void
.end method

.method public final h(JIIJ)V
    .locals 3

    .line 1
    iget-object v0, p0, Lv9/r;->d:Lv9/q;

    .line 2
    .line 3
    iget-boolean v1, p0, Lv9/r;->e:Z

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    iput-boolean v2, v0, Lv9/q;->g:Z

    .line 7
    .line 8
    iput-boolean v2, v0, Lv9/q;->h:Z

    .line 9
    .line 10
    iput-wide p5, v0, Lv9/q;->e:J

    .line 11
    .line 12
    iput v2, v0, Lv9/q;->d:I

    .line 13
    .line 14
    iput-wide p1, v0, Lv9/q;->b:J

    .line 15
    .line 16
    const/4 p1, 0x1

    .line 17
    const/16 p2, 0x20

    .line 18
    .line 19
    if-lt p4, p2, :cond_5

    .line 20
    .line 21
    const/16 p5, 0x28

    .line 22
    .line 23
    if-ne p4, p5, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    iget-boolean p5, v0, Lv9/q;->i:Z

    .line 27
    .line 28
    if-eqz p5, :cond_2

    .line 29
    .line 30
    iget-boolean p5, v0, Lv9/q;->j:Z

    .line 31
    .line 32
    if-nez p5, :cond_2

    .line 33
    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    invoke-virtual {v0, p3}, Lv9/q;->a(I)V

    .line 37
    .line 38
    .line 39
    :cond_1
    iput-boolean v2, v0, Lv9/q;->i:Z

    .line 40
    .line 41
    :cond_2
    if-gt p2, p4, :cond_3

    .line 42
    .line 43
    const/16 p2, 0x23

    .line 44
    .line 45
    if-le p4, p2, :cond_4

    .line 46
    .line 47
    :cond_3
    const/16 p2, 0x27

    .line 48
    .line 49
    if-ne p4, p2, :cond_5

    .line 50
    .line 51
    :cond_4
    iget-boolean p2, v0, Lv9/q;->j:Z

    .line 52
    .line 53
    xor-int/2addr p2, p1

    .line 54
    iput-boolean p2, v0, Lv9/q;->h:Z

    .line 55
    .line 56
    iput-boolean p1, v0, Lv9/q;->j:Z

    .line 57
    .line 58
    :cond_5
    :goto_0
    const/16 p2, 0x10

    .line 59
    .line 60
    if-lt p4, p2, :cond_6

    .line 61
    .line 62
    const/16 p2, 0x15

    .line 63
    .line 64
    if-gt p4, p2, :cond_6

    .line 65
    .line 66
    move p2, p1

    .line 67
    goto :goto_1

    .line 68
    :cond_6
    move p2, v2

    .line 69
    :goto_1
    iput-boolean p2, v0, Lv9/q;->c:Z

    .line 70
    .line 71
    if-nez p2, :cond_7

    .line 72
    .line 73
    const/16 p2, 0x9

    .line 74
    .line 75
    if-gt p4, p2, :cond_8

    .line 76
    .line 77
    :cond_7
    move v2, p1

    .line 78
    :cond_8
    iput-boolean v2, v0, Lv9/q;->f:Z

    .line 79
    .line 80
    iget-boolean p1, p0, Lv9/r;->e:Z

    .line 81
    .line 82
    if-nez p1, :cond_9

    .line 83
    .line 84
    iget-object p1, p0, Lv9/r;->g:La8/n0;

    .line 85
    .line 86
    invoke-virtual {p1, p4}, La8/n0;->h(I)V

    .line 87
    .line 88
    .line 89
    iget-object p1, p0, Lv9/r;->h:La8/n0;

    .line 90
    .line 91
    invoke-virtual {p1, p4}, La8/n0;->h(I)V

    .line 92
    .line 93
    .line 94
    iget-object p1, p0, Lv9/r;->i:La8/n0;

    .line 95
    .line 96
    invoke-virtual {p1, p4}, La8/n0;->h(I)V

    .line 97
    .line 98
    .line 99
    :cond_9
    iget-object p1, p0, Lv9/r;->j:La8/n0;

    .line 100
    .line 101
    invoke-virtual {p1, p4}, La8/n0;->h(I)V

    .line 102
    .line 103
    .line 104
    iget-object p0, p0, Lv9/r;->k:La8/n0;

    .line 105
    .line 106
    invoke-virtual {p0, p4}, La8/n0;->h(I)V

    .line 107
    .line 108
    .line 109
    return-void
.end method
