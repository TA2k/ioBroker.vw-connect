.class public final Lk1/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final a:Lx2/e;

.field public final b:Z


# direct methods
.method public constructor <init>(Lx2/e;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk1/p;->a:Lx2/e;

    .line 5
    .line 6
    iput-boolean p2, p0, Lk1/p;->b:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 16

    .line 1
    move-object/from16 v3, p1

    .line 2
    .line 3
    move-object/from16 v2, p2

    .line 4
    .line 5
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    sget-object v8, Lmx0/t;->d:Lmx0/t;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    invoke-static/range {p3 .. p4}, Lt4/a;->j(J)I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    invoke-static/range {p3 .. p4}, Lt4/a;->i(J)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    new-instance v2, Ldj/a;

    .line 22
    .line 23
    const/16 v4, 0xe

    .line 24
    .line 25
    invoke-direct {v2, v4}, Ldj/a;-><init>(I)V

    .line 26
    .line 27
    .line 28
    invoke-interface {v3, v0, v1, v8, v2}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    return-object v0

    .line 33
    :cond_0
    move-object/from16 v6, p0

    .line 34
    .line 35
    iget-boolean v0, v6, Lk1/p;->b:Z

    .line 36
    .line 37
    if-eqz v0, :cond_1

    .line 38
    .line 39
    move-wide/from16 v0, p3

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    const-wide v0, -0x1fffffffdL

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    and-long v0, p3, v0

    .line 48
    .line 49
    :goto_0
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    const/4 v5, 0x0

    .line 54
    const/4 v7, 0x1

    .line 55
    const/4 v9, 0x0

    .line 56
    if-ne v4, v7, :cond_8

    .line 57
    .line 58
    invoke-interface {v2, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    check-cast v2, Lt3/p0;

    .line 63
    .line 64
    invoke-interface {v2}, Lt3/p0;->l()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    instance-of v10, v4, Lk1/l;

    .line 69
    .line 70
    if-eqz v10, :cond_2

    .line 71
    .line 72
    move-object v5, v4

    .line 73
    check-cast v5, Lk1/l;

    .line 74
    .line 75
    :cond_2
    if-eqz v5, :cond_3

    .line 76
    .line 77
    iget-boolean v4, v5, Lk1/l;->s:Z

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_3
    move v4, v9

    .line 81
    :goto_1
    if-nez v4, :cond_4

    .line 82
    .line 83
    invoke-interface {v2, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    invoke-static/range {p3 .. p4}, Lt4/a;->j(J)I

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    iget v4, v0, Lt3/e1;->d:I

    .line 92
    .line 93
    invoke-static {v1, v4}, Ljava/lang/Math;->max(II)I

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    invoke-static/range {p3 .. p4}, Lt4/a;->i(J)I

    .line 98
    .line 99
    .line 100
    move-result v4

    .line 101
    iget v5, v0, Lt3/e1;->e:I

    .line 102
    .line 103
    invoke-static {v4, v5}, Ljava/lang/Math;->max(II)I

    .line 104
    .line 105
    .line 106
    move-result v4

    .line 107
    :goto_2
    move v5, v4

    .line 108
    move v4, v1

    .line 109
    move-object v1, v0

    .line 110
    goto :goto_5

    .line 111
    :cond_4
    invoke-static/range {p3 .. p4}, Lt4/a;->j(J)I

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    invoke-static/range {p3 .. p4}, Lt4/a;->i(J)I

    .line 116
    .line 117
    .line 118
    move-result v4

    .line 119
    invoke-static/range {p3 .. p4}, Lt4/a;->j(J)I

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    invoke-static/range {p3 .. p4}, Lt4/a;->i(J)I

    .line 124
    .line 125
    .line 126
    move-result v5

    .line 127
    if-ltz v0, :cond_5

    .line 128
    .line 129
    move v10, v7

    .line 130
    goto :goto_3

    .line 131
    :cond_5
    move v10, v9

    .line 132
    :goto_3
    if-ltz v5, :cond_6

    .line 133
    .line 134
    goto :goto_4

    .line 135
    :cond_6
    move v7, v9

    .line 136
    :goto_4
    and-int/2addr v7, v10

    .line 137
    if-nez v7, :cond_7

    .line 138
    .line 139
    const-string v7, "width and height must be >= 0"

    .line 140
    .line 141
    invoke-static {v7}, Lt4/i;->a(Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    :cond_7
    invoke-static {v0, v0, v5, v5}, Lt4/b;->h(IIII)J

    .line 145
    .line 146
    .line 147
    move-result-wide v9

    .line 148
    invoke-interface {v2, v9, v10}, Lt3/p0;->L(J)Lt3/e1;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    goto :goto_2

    .line 153
    :goto_5
    new-instance v0, Lk1/o;

    .line 154
    .line 155
    invoke-direct/range {v0 .. v6}, Lk1/o;-><init>(Lt3/e1;Lt3/p0;Lt3/s0;IILk1/p;)V

    .line 156
    .line 157
    .line 158
    invoke-interface {v3, v4, v5, v8, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    return-object v0

    .line 163
    :cond_8
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 164
    .line 165
    .line 166
    move-result v4

    .line 167
    new-array v4, v4, [Lt3/e1;

    .line 168
    .line 169
    move-object v6, v4

    .line 170
    new-instance v4, Lkotlin/jvm/internal/d0;

    .line 171
    .line 172
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 173
    .line 174
    .line 175
    invoke-static/range {p3 .. p4}, Lt4/a;->j(J)I

    .line 176
    .line 177
    .line 178
    move-result v10

    .line 179
    iput v10, v4, Lkotlin/jvm/internal/d0;->d:I

    .line 180
    .line 181
    move-object v10, v5

    .line 182
    new-instance v5, Lkotlin/jvm/internal/d0;

    .line 183
    .line 184
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 185
    .line 186
    .line 187
    invoke-static/range {p3 .. p4}, Lt4/a;->i(J)I

    .line 188
    .line 189
    .line 190
    move-result v11

    .line 191
    iput v11, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 192
    .line 193
    move-object v11, v2

    .line 194
    check-cast v11, Ljava/util/Collection;

    .line 195
    .line 196
    invoke-interface {v11}, Ljava/util/Collection;->size()I

    .line 197
    .line 198
    .line 199
    move-result v12

    .line 200
    move v13, v9

    .line 201
    move v14, v13

    .line 202
    :goto_6
    if-ge v13, v12, :cond_c

    .line 203
    .line 204
    invoke-interface {v2, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v15

    .line 208
    check-cast v15, Lt3/p0;

    .line 209
    .line 210
    invoke-interface {v15}, Lt3/p0;->l()Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v7

    .line 214
    instance-of v9, v7, Lk1/l;

    .line 215
    .line 216
    if-eqz v9, :cond_9

    .line 217
    .line 218
    check-cast v7, Lk1/l;

    .line 219
    .line 220
    goto :goto_7

    .line 221
    :cond_9
    move-object v7, v10

    .line 222
    :goto_7
    if-eqz v7, :cond_a

    .line 223
    .line 224
    iget-boolean v7, v7, Lk1/l;->s:Z

    .line 225
    .line 226
    goto :goto_8

    .line 227
    :cond_a
    const/4 v7, 0x0

    .line 228
    :goto_8
    if-nez v7, :cond_b

    .line 229
    .line 230
    invoke-interface {v15, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 231
    .line 232
    .line 233
    move-result-object v7

    .line 234
    aput-object v7, v6, v13

    .line 235
    .line 236
    iget v9, v4, Lkotlin/jvm/internal/d0;->d:I

    .line 237
    .line 238
    iget v15, v7, Lt3/e1;->d:I

    .line 239
    .line 240
    invoke-static {v9, v15}, Ljava/lang/Math;->max(II)I

    .line 241
    .line 242
    .line 243
    move-result v9

    .line 244
    iput v9, v4, Lkotlin/jvm/internal/d0;->d:I

    .line 245
    .line 246
    iget v9, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 247
    .line 248
    iget v7, v7, Lt3/e1;->e:I

    .line 249
    .line 250
    invoke-static {v9, v7}, Ljava/lang/Math;->max(II)I

    .line 251
    .line 252
    .line 253
    move-result v7

    .line 254
    iput v7, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 255
    .line 256
    goto :goto_9

    .line 257
    :cond_b
    const/4 v14, 0x1

    .line 258
    :goto_9
    add-int/lit8 v13, v13, 0x1

    .line 259
    .line 260
    const/4 v7, 0x1

    .line 261
    const/4 v9, 0x0

    .line 262
    goto :goto_6

    .line 263
    :cond_c
    if-eqz v14, :cond_12

    .line 264
    .line 265
    iget v0, v4, Lkotlin/jvm/internal/d0;->d:I

    .line 266
    .line 267
    const v1, 0x7fffffff

    .line 268
    .line 269
    .line 270
    if-eq v0, v1, :cond_d

    .line 271
    .line 272
    move v7, v0

    .line 273
    goto :goto_a

    .line 274
    :cond_d
    const/4 v7, 0x0

    .line 275
    :goto_a
    iget v9, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 276
    .line 277
    if-eq v9, v1, :cond_e

    .line 278
    .line 279
    move v1, v9

    .line 280
    goto :goto_b

    .line 281
    :cond_e
    const/4 v1, 0x0

    .line 282
    :goto_b
    invoke-static {v7, v0, v1, v9}, Lt4/b;->a(IIII)J

    .line 283
    .line 284
    .line 285
    move-result-wide v0

    .line 286
    invoke-interface {v11}, Ljava/util/Collection;->size()I

    .line 287
    .line 288
    .line 289
    move-result v7

    .line 290
    const/4 v9, 0x0

    .line 291
    :goto_c
    if-ge v9, v7, :cond_12

    .line 292
    .line 293
    invoke-interface {v2, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    move-result-object v11

    .line 297
    check-cast v11, Lt3/p0;

    .line 298
    .line 299
    invoke-interface {v11}, Lt3/p0;->l()Ljava/lang/Object;

    .line 300
    .line 301
    .line 302
    move-result-object v12

    .line 303
    instance-of v13, v12, Lk1/l;

    .line 304
    .line 305
    if-eqz v13, :cond_f

    .line 306
    .line 307
    check-cast v12, Lk1/l;

    .line 308
    .line 309
    goto :goto_d

    .line 310
    :cond_f
    move-object v12, v10

    .line 311
    :goto_d
    if-eqz v12, :cond_10

    .line 312
    .line 313
    iget-boolean v12, v12, Lk1/l;->s:Z

    .line 314
    .line 315
    goto :goto_e

    .line 316
    :cond_10
    const/4 v12, 0x0

    .line 317
    :goto_e
    if-eqz v12, :cond_11

    .line 318
    .line 319
    invoke-interface {v11, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 320
    .line 321
    .line 322
    move-result-object v11

    .line 323
    aput-object v11, v6, v9

    .line 324
    .line 325
    :cond_11
    add-int/lit8 v9, v9, 0x1

    .line 326
    .line 327
    goto :goto_c

    .line 328
    :cond_12
    iget v9, v4, Lkotlin/jvm/internal/d0;->d:I

    .line 329
    .line 330
    iget v10, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 331
    .line 332
    new-instance v0, Lbi/a;

    .line 333
    .line 334
    const/4 v7, 0x3

    .line 335
    move-object v1, v6

    .line 336
    move-object/from16 v6, p0

    .line 337
    .line 338
    invoke-direct/range {v0 .. v7}, Lbi/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 339
    .line 340
    .line 341
    invoke-interface {v3, v9, v10, v8, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 342
    .line 343
    .line 344
    move-result-object v0

    .line 345
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lk1/p;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lk1/p;

    .line 12
    .line 13
    iget-object v1, p0, Lk1/p;->a:Lx2/e;

    .line 14
    .line 15
    iget-object v3, p1, Lk1/p;->a:Lx2/e;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-boolean p0, p0, Lk1/p;->b:Z

    .line 25
    .line 26
    iget-boolean p1, p1, Lk1/p;->b:Z

    .line 27
    .line 28
    if-eq p0, p1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    return v0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lk1/p;->a:Lx2/e;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-boolean p0, p0, Lk1/p;->b:Z

    .line 10
    .line 11
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "BoxMeasurePolicy(alignment="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lk1/p;->a:Lx2/e;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", propagateMinConstraints="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean p0, p0, Lk1/p;->b:Z

    .line 19
    .line 20
    const/16 v1, 0x29

    .line 21
    .line 22
    invoke-static {v0, p0, v1}, Lf2/m0;->l(Ljava/lang/StringBuilder;ZC)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
