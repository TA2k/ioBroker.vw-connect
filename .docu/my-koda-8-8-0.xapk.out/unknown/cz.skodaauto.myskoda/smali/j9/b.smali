.class public final Lj9/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lj9/h;


# instance fields
.field public final d:Lj9/g;

.field public final e:J

.field public final f:J

.field public final g:Lj9/j;

.field public h:I

.field public i:J

.field public j:J

.field public k:J

.field public l:J

.field public m:J

.field public n:J

.field public o:J


# direct methods
.method public constructor <init>(Lj9/j;JJJJZ)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-wide/16 v0, 0x0

    .line 5
    .line 6
    cmp-long v0, p2, v0

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-ltz v0, :cond_0

    .line 10
    .line 11
    cmp-long v0, p4, p2

    .line 12
    .line 13
    if-lez v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v0, v1

    .line 18
    :goto_0
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lj9/b;->g:Lj9/j;

    .line 22
    .line 23
    iput-wide p2, p0, Lj9/b;->e:J

    .line 24
    .line 25
    iput-wide p4, p0, Lj9/b;->f:J

    .line 26
    .line 27
    sub-long/2addr p4, p2

    .line 28
    cmp-long p1, p6, p4

    .line 29
    .line 30
    if-eqz p1, :cond_2

    .line 31
    .line 32
    if-eqz p10, :cond_1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    iput v1, p0, Lj9/b;->h:I

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    :goto_1
    iput-wide p8, p0, Lj9/b;->i:J

    .line 39
    .line 40
    const/4 p1, 0x4

    .line 41
    iput p1, p0, Lj9/b;->h:I

    .line 42
    .line 43
    :goto_2
    new-instance p1, Lj9/g;

    .line 44
    .line 45
    invoke-direct {p1}, Lj9/g;-><init>()V

    .line 46
    .line 47
    .line 48
    iput-object p1, p0, Lj9/b;->d:Lj9/g;

    .line 49
    .line 50
    return-void
.end method


# virtual methods
.method public final k(Lo8/p;)J
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v2, v0, Lj9/b;->h:I

    .line 6
    .line 7
    iget-wide v5, v0, Lj9/b;->f:J

    .line 8
    .line 9
    const/4 v7, 0x0

    .line 10
    iget-object v8, v0, Lj9/b;->d:Lj9/g;

    .line 11
    .line 12
    const/4 v9, 0x1

    .line 13
    const-wide/16 v10, -0x1

    .line 14
    .line 15
    const/4 v12, 0x4

    .line 16
    if-eqz v2, :cond_d

    .line 17
    .line 18
    if-eq v2, v9, :cond_c

    .line 19
    .line 20
    const/4 v5, 0x2

    .line 21
    const/4 v6, 0x3

    .line 22
    if-eq v2, v5, :cond_2

    .line 23
    .line 24
    if-eq v2, v6, :cond_1

    .line 25
    .line 26
    if-ne v2, v12, :cond_0

    .line 27
    .line 28
    return-wide v10

    .line 29
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 32
    .line 33
    .line 34
    throw v0

    .line 35
    :cond_1
    const-wide/16 v19, 0x2

    .line 36
    .line 37
    goto/16 :goto_4

    .line 38
    .line 39
    :cond_2
    const-wide/16 v15, 0x2

    .line 40
    .line 41
    iget-wide v13, v0, Lj9/b;->l:J

    .line 42
    .line 43
    const-wide/16 v17, 0x0

    .line 44
    .line 45
    iget-wide v3, v0, Lj9/b;->m:J

    .line 46
    .line 47
    cmp-long v2, v13, v3

    .line 48
    .line 49
    if-nez v2, :cond_3

    .line 50
    .line 51
    move-wide v4, v10

    .line 52
    :goto_0
    move-wide/from16 v19, v15

    .line 53
    .line 54
    goto/16 :goto_3

    .line 55
    .line 56
    :cond_3
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 57
    .line 58
    .line 59
    move-result-wide v2

    .line 60
    iget-wide v4, v0, Lj9/b;->m:J

    .line 61
    .line 62
    invoke-virtual {v8, v1, v4, v5}, Lj9/g;->b(Lo8/p;J)Z

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    if-nez v4, :cond_5

    .line 67
    .line 68
    iget-wide v4, v0, Lj9/b;->l:J

    .line 69
    .line 70
    cmp-long v2, v4, v2

    .line 71
    .line 72
    if-eqz v2, :cond_4

    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_4
    new-instance v0, Ljava/io/IOException;

    .line 76
    .line 77
    const-string v1, "No ogg page can be found."

    .line 78
    .line 79
    invoke-direct {v0, v1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw v0

    .line 83
    :cond_5
    invoke-virtual {v8, v1, v7}, Lj9/g;->a(Lo8/p;Z)Z

    .line 84
    .line 85
    .line 86
    invoke-interface {v1}, Lo8/p;->e()V

    .line 87
    .line 88
    .line 89
    iget-wide v4, v0, Lj9/b;->k:J

    .line 90
    .line 91
    iget-wide v13, v8, Lj9/g;->b:J

    .line 92
    .line 93
    sub-long/2addr v4, v13

    .line 94
    iget v9, v8, Lj9/g;->d:I

    .line 95
    .line 96
    move-wide/from16 v19, v15

    .line 97
    .line 98
    iget v15, v8, Lj9/g;->e:I

    .line 99
    .line 100
    add-int/2addr v9, v15

    .line 101
    cmp-long v15, v17, v4

    .line 102
    .line 103
    if-gtz v15, :cond_6

    .line 104
    .line 105
    const-wide/32 v15, 0x11940

    .line 106
    .line 107
    .line 108
    cmp-long v15, v4, v15

    .line 109
    .line 110
    if-gez v15, :cond_6

    .line 111
    .line 112
    move-wide v4, v10

    .line 113
    goto :goto_3

    .line 114
    :cond_6
    cmp-long v15, v4, v17

    .line 115
    .line 116
    if-gez v15, :cond_7

    .line 117
    .line 118
    iput-wide v2, v0, Lj9/b;->m:J

    .line 119
    .line 120
    iput-wide v13, v0, Lj9/b;->o:J

    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_7
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 124
    .line 125
    .line 126
    move-result-wide v2

    .line 127
    int-to-long v13, v9

    .line 128
    add-long/2addr v2, v13

    .line 129
    iput-wide v2, v0, Lj9/b;->l:J

    .line 130
    .line 131
    iget-wide v2, v8, Lj9/g;->b:J

    .line 132
    .line 133
    iput-wide v2, v0, Lj9/b;->n:J

    .line 134
    .line 135
    :goto_1
    iget-wide v2, v0, Lj9/b;->m:J

    .line 136
    .line 137
    iget-wide v13, v0, Lj9/b;->l:J

    .line 138
    .line 139
    sub-long/2addr v2, v13

    .line 140
    const-wide/32 v16, 0x186a0

    .line 141
    .line 142
    .line 143
    cmp-long v2, v2, v16

    .line 144
    .line 145
    if-gez v2, :cond_8

    .line 146
    .line 147
    iput-wide v13, v0, Lj9/b;->m:J

    .line 148
    .line 149
    move-wide v4, v13

    .line 150
    goto :goto_3

    .line 151
    :cond_8
    int-to-long v2, v9

    .line 152
    if-gtz v15, :cond_9

    .line 153
    .line 154
    move-wide/from16 v15, v19

    .line 155
    .line 156
    goto :goto_2

    .line 157
    :cond_9
    const-wide/16 v15, 0x1

    .line 158
    .line 159
    :goto_2
    mul-long/2addr v2, v15

    .line 160
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 161
    .line 162
    .line 163
    move-result-wide v15

    .line 164
    sub-long/2addr v15, v2

    .line 165
    iget-wide v2, v0, Lj9/b;->m:J

    .line 166
    .line 167
    const-wide/16 v17, 0x1

    .line 168
    .line 169
    iget-wide v13, v0, Lj9/b;->l:J

    .line 170
    .line 171
    sub-long v21, v2, v13

    .line 172
    .line 173
    mul-long v21, v21, v4

    .line 174
    .line 175
    iget-wide v4, v0, Lj9/b;->o:J

    .line 176
    .line 177
    move-wide/from16 v23, v13

    .line 178
    .line 179
    iget-wide v12, v0, Lj9/b;->n:J

    .line 180
    .line 181
    sub-long/2addr v4, v12

    .line 182
    div-long v21, v21, v4

    .line 183
    .line 184
    add-long v21, v21, v15

    .line 185
    .line 186
    sub-long v25, v2, v17

    .line 187
    .line 188
    invoke-static/range {v21 .. v26}, Lw7/w;->h(JJJ)J

    .line 189
    .line 190
    .line 191
    move-result-wide v4

    .line 192
    :goto_3
    cmp-long v2, v4, v10

    .line 193
    .line 194
    if-eqz v2, :cond_a

    .line 195
    .line 196
    return-wide v4

    .line 197
    :cond_a
    iput v6, v0, Lj9/b;->h:I

    .line 198
    .line 199
    :goto_4
    invoke-virtual {v8, v1, v10, v11}, Lj9/g;->b(Lo8/p;J)Z

    .line 200
    .line 201
    .line 202
    invoke-virtual {v8, v1, v7}, Lj9/g;->a(Lo8/p;Z)Z

    .line 203
    .line 204
    .line 205
    iget-wide v2, v8, Lj9/g;->b:J

    .line 206
    .line 207
    iget-wide v4, v0, Lj9/b;->k:J

    .line 208
    .line 209
    cmp-long v2, v2, v4

    .line 210
    .line 211
    if-lez v2, :cond_b

    .line 212
    .line 213
    invoke-interface {v1}, Lo8/p;->e()V

    .line 214
    .line 215
    .line 216
    const/4 v1, 0x4

    .line 217
    iput v1, v0, Lj9/b;->h:I

    .line 218
    .line 219
    iget-wide v0, v0, Lj9/b;->n:J

    .line 220
    .line 221
    add-long v0, v0, v19

    .line 222
    .line 223
    neg-long v0, v0

    .line 224
    return-wide v0

    .line 225
    :cond_b
    iget v2, v8, Lj9/g;->d:I

    .line 226
    .line 227
    iget v3, v8, Lj9/g;->e:I

    .line 228
    .line 229
    add-int/2addr v2, v3

    .line 230
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 231
    .line 232
    .line 233
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 234
    .line 235
    .line 236
    move-result-wide v2

    .line 237
    iput-wide v2, v0, Lj9/b;->l:J

    .line 238
    .line 239
    iget-wide v2, v8, Lj9/g;->b:J

    .line 240
    .line 241
    iput-wide v2, v0, Lj9/b;->n:J

    .line 242
    .line 243
    goto :goto_4

    .line 244
    :cond_c
    const-wide/16 v17, 0x0

    .line 245
    .line 246
    goto :goto_5

    .line 247
    :cond_d
    const-wide/16 v17, 0x0

    .line 248
    .line 249
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 250
    .line 251
    .line 252
    move-result-wide v2

    .line 253
    iput-wide v2, v0, Lj9/b;->j:J

    .line 254
    .line 255
    iput v9, v0, Lj9/b;->h:I

    .line 256
    .line 257
    const-wide/32 v12, 0xff1b

    .line 258
    .line 259
    .line 260
    sub-long v12, v5, v12

    .line 261
    .line 262
    cmp-long v2, v12, v2

    .line 263
    .line 264
    if-lez v2, :cond_e

    .line 265
    .line 266
    return-wide v12

    .line 267
    :cond_e
    :goto_5
    iput v7, v8, Lj9/g;->a:I

    .line 268
    .line 269
    move-wide/from16 v2, v17

    .line 270
    .line 271
    iput-wide v2, v8, Lj9/g;->b:J

    .line 272
    .line 273
    iput v7, v8, Lj9/g;->c:I

    .line 274
    .line 275
    iput v7, v8, Lj9/g;->d:I

    .line 276
    .line 277
    iput v7, v8, Lj9/g;->e:I

    .line 278
    .line 279
    invoke-virtual {v8, v1, v10, v11}, Lj9/g;->b(Lo8/p;J)Z

    .line 280
    .line 281
    .line 282
    move-result v2

    .line 283
    if-eqz v2, :cond_10

    .line 284
    .line 285
    invoke-virtual {v8, v1, v7}, Lj9/g;->a(Lo8/p;Z)Z

    .line 286
    .line 287
    .line 288
    iget v2, v8, Lj9/g;->d:I

    .line 289
    .line 290
    iget v3, v8, Lj9/g;->e:I

    .line 291
    .line 292
    add-int/2addr v2, v3

    .line 293
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 294
    .line 295
    .line 296
    iget-wide v2, v8, Lj9/g;->b:J

    .line 297
    .line 298
    :goto_6
    iget v4, v8, Lj9/g;->a:I

    .line 299
    .line 300
    const/4 v7, 0x4

    .line 301
    and-int/2addr v4, v7

    .line 302
    if-eq v4, v7, :cond_f

    .line 303
    .line 304
    invoke-virtual {v8, v1, v10, v11}, Lj9/g;->b(Lo8/p;J)Z

    .line 305
    .line 306
    .line 307
    move-result v4

    .line 308
    if-eqz v4, :cond_f

    .line 309
    .line 310
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 311
    .line 312
    .line 313
    move-result-wide v12

    .line 314
    cmp-long v4, v12, v5

    .line 315
    .line 316
    if-gez v4, :cond_f

    .line 317
    .line 318
    invoke-virtual {v8, v1, v9}, Lj9/g;->a(Lo8/p;Z)Z

    .line 319
    .line 320
    .line 321
    move-result v4

    .line 322
    if-eqz v4, :cond_f

    .line 323
    .line 324
    iget v4, v8, Lj9/g;->d:I

    .line 325
    .line 326
    iget v7, v8, Lj9/g;->e:I

    .line 327
    .line 328
    add-int/2addr v4, v7

    .line 329
    :try_start_0
    invoke-interface {v1, v4}, Lo8/p;->n(I)V
    :try_end_0
    .catch Ljava/io/EOFException; {:try_start_0 .. :try_end_0} :catch_0

    .line 330
    .line 331
    .line 332
    iget-wide v2, v8, Lj9/g;->b:J

    .line 333
    .line 334
    goto :goto_6

    .line 335
    :catch_0
    :cond_f
    iput-wide v2, v0, Lj9/b;->i:J

    .line 336
    .line 337
    const/4 v1, 0x4

    .line 338
    iput v1, v0, Lj9/b;->h:I

    .line 339
    .line 340
    iget-wide v0, v0, Lj9/b;->j:J

    .line 341
    .line 342
    return-wide v0

    .line 343
    :cond_10
    new-instance v0, Ljava/io/EOFException;

    .line 344
    .line 345
    invoke-direct {v0}, Ljava/io/EOFException;-><init>()V

    .line 346
    .line 347
    .line 348
    throw v0
.end method

.method public final m()Lo8/c0;
    .locals 4

    .line 1
    iget-wide v0, p0, Lj9/b;->i:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long v0, v0, v2

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    new-instance v0, Lj9/a;

    .line 10
    .line 11
    invoke-direct {v0, p0}, Lj9/a;-><init>(Lj9/b;)V

    .line 12
    .line 13
    .line 14
    return-object v0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return-object p0
.end method

.method public final q(J)V
    .locals 10

    .line 1
    iget-wide v0, p0, Lj9/b;->i:J

    .line 2
    .line 3
    const-wide/16 v2, 0x1

    .line 4
    .line 5
    sub-long v8, v0, v2

    .line 6
    .line 7
    const-wide/16 v6, 0x0

    .line 8
    .line 9
    move-wide v4, p1

    .line 10
    invoke-static/range {v4 .. v9}, Lw7/w;->h(JJJ)J

    .line 11
    .line 12
    .line 13
    move-result-wide p1

    .line 14
    iput-wide p1, p0, Lj9/b;->k:J

    .line 15
    .line 16
    const/4 p1, 0x2

    .line 17
    iput p1, p0, Lj9/b;->h:I

    .line 18
    .line 19
    iget-wide p1, p0, Lj9/b;->e:J

    .line 20
    .line 21
    iput-wide p1, p0, Lj9/b;->l:J

    .line 22
    .line 23
    iget-wide p1, p0, Lj9/b;->f:J

    .line 24
    .line 25
    iput-wide p1, p0, Lj9/b;->m:J

    .line 26
    .line 27
    const-wide/16 p1, 0x0

    .line 28
    .line 29
    iput-wide p1, p0, Lj9/b;->n:J

    .line 30
    .line 31
    iget-wide p1, p0, Lj9/b;->i:J

    .line 32
    .line 33
    iput-wide p1, p0, Lj9/b;->o:J

    .line 34
    .line 35
    return-void
.end method
