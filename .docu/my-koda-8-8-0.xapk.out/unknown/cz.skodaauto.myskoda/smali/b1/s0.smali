.class public final Lb1/s0;
.super Lb1/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:J

.field public B:Lx2/e;

.field public final C:Lb1/r0;

.field public final D:Lb1/r0;

.field public s:Lc1/w1;

.field public t:Lc1/q1;

.field public u:Lc1/q1;

.field public v:Lc1/q1;

.field public w:Lb1/t0;

.field public x:Lb1/u0;

.field public y:Lay0/a;

.field public z:Lb1/j0;


# direct methods
.method public constructor <init>(Lc1/w1;Lc1/q1;Lc1/q1;Lc1/q1;Lb1/t0;Lb1/u0;Lay0/a;Lb1/j0;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lb1/z0;-><init>(I)V

    .line 3
    .line 4
    .line 5
    iput-object p1, p0, Lb1/s0;->s:Lc1/w1;

    .line 6
    .line 7
    iput-object p2, p0, Lb1/s0;->t:Lc1/q1;

    .line 8
    .line 9
    iput-object p3, p0, Lb1/s0;->u:Lc1/q1;

    .line 10
    .line 11
    iput-object p4, p0, Lb1/s0;->v:Lc1/q1;

    .line 12
    .line 13
    iput-object p5, p0, Lb1/s0;->w:Lb1/t0;

    .line 14
    .line 15
    iput-object p6, p0, Lb1/s0;->x:Lb1/u0;

    .line 16
    .line 17
    iput-object p7, p0, Lb1/s0;->y:Lay0/a;

    .line 18
    .line 19
    iput-object p8, p0, Lb1/s0;->z:Lb1/j0;

    .line 20
    .line 21
    sget-wide p1, Landroidx/compose/animation/c;->a:J

    .line 22
    .line 23
    iput-wide p1, p0, Lb1/s0;->A:J

    .line 24
    .line 25
    const/4 p1, 0x0

    .line 26
    const/16 p2, 0xf

    .line 27
    .line 28
    invoke-static {p1, p1, p2}, Lt4/b;->b(III)J

    .line 29
    .line 30
    .line 31
    new-instance p1, Lb1/r0;

    .line 32
    .line 33
    const/4 p2, 0x0

    .line 34
    invoke-direct {p1, p0, p2}, Lb1/r0;-><init>(Lb1/s0;I)V

    .line 35
    .line 36
    .line 37
    iput-object p1, p0, Lb1/s0;->C:Lb1/r0;

    .line 38
    .line 39
    new-instance p1, Lb1/r0;

    .line 40
    .line 41
    const/4 p2, 0x1

    .line 42
    invoke-direct {p1, p0, p2}, Lb1/r0;-><init>(Lb1/s0;I)V

    .line 43
    .line 44
    .line 45
    iput-object p1, p0, Lb1/s0;->D:Lb1/r0;

    .line 46
    .line 47
    return-void
.end method


# virtual methods
.method public final P0()V
    .locals 2

    .line 1
    sget-wide v0, Landroidx/compose/animation/c;->a:J

    .line 2
    .line 3
    iput-wide v0, p0, Lb1/s0;->A:J

    .line 4
    .line 5
    return-void
.end method

.method public final Z0()Lx2/e;
    .locals 3

    .line 1
    iget-object v0, p0, Lb1/s0;->s:Lc1/w1;

    .line 2
    .line 3
    invoke-virtual {v0}, Lc1/w1;->f()Lc1/r1;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lb1/i0;->d:Lb1/i0;

    .line 8
    .line 9
    sget-object v2, Lb1/i0;->e:Lb1/i0;

    .line 10
    .line 11
    invoke-interface {v0, v1, v2}, Lc1/r1;->c(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    iget-object v0, p0, Lb1/s0;->w:Lb1/t0;

    .line 18
    .line 19
    iget-object v0, v0, Lb1/t0;->a:Lb1/i1;

    .line 20
    .line 21
    iget-object v0, v0, Lb1/i1;->c:Lb1/c0;

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    iget-object p0, v0, Lb1/c0;->a:Lx2/j;

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_0
    iget-object p0, p0, Lb1/s0;->x:Lb1/u0;

    .line 29
    .line 30
    iget-object p0, p0, Lb1/u0;->a:Lb1/i1;

    .line 31
    .line 32
    iget-object p0, p0, Lb1/i1;->c:Lb1/c0;

    .line 33
    .line 34
    if-eqz p0, :cond_3

    .line 35
    .line 36
    iget-object p0, p0, Lb1/c0;->a:Lx2/j;

    .line 37
    .line 38
    return-object p0

    .line 39
    :cond_1
    iget-object v0, p0, Lb1/s0;->x:Lb1/u0;

    .line 40
    .line 41
    iget-object v0, v0, Lb1/u0;->a:Lb1/i1;

    .line 42
    .line 43
    iget-object v0, v0, Lb1/i1;->c:Lb1/c0;

    .line 44
    .line 45
    if-eqz v0, :cond_2

    .line 46
    .line 47
    iget-object p0, v0, Lb1/c0;->a:Lx2/j;

    .line 48
    .line 49
    return-object p0

    .line 50
    :cond_2
    iget-object p0, p0, Lb1/s0;->w:Lb1/t0;

    .line 51
    .line 52
    iget-object p0, p0, Lb1/t0;->a:Lb1/i1;

    .line 53
    .line 54
    iget-object p0, p0, Lb1/i1;->c:Lb1/c0;

    .line 55
    .line 56
    if-eqz p0, :cond_3

    .line 57
    .line 58
    iget-object p0, p0, Lb1/c0;->a:Lx2/j;

    .line 59
    .line 60
    return-object p0

    .line 61
    :cond_3
    const/4 p0, 0x0

    .line 62
    return-object p0
.end method

.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lb1/s0;->s:Lc1/w1;

    .line 6
    .line 7
    iget-object v2, v2, Lc1/w1;->a:Lap0/o;

    .line 8
    .line 9
    invoke-virtual {v2}, Lap0/o;->D()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    iget-object v3, v0, Lb1/s0;->s:Lc1/w1;

    .line 14
    .line 15
    iget-object v3, v3, Lc1/w1;->d:Ll2/j1;

    .line 16
    .line 17
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    const/4 v4, 0x0

    .line 22
    if-ne v2, v3, :cond_0

    .line 23
    .line 24
    iput-object v4, v0, Lb1/s0;->B:Lx2/e;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    iget-object v2, v0, Lb1/s0;->B:Lx2/e;

    .line 28
    .line 29
    if-nez v2, :cond_2

    .line 30
    .line 31
    invoke-virtual {v0}, Lb1/s0;->Z0()Lx2/e;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    if-nez v2, :cond_1

    .line 36
    .line 37
    sget-object v2, Lx2/c;->d:Lx2/j;

    .line 38
    .line 39
    :cond_1
    iput-object v2, v0, Lb1/s0;->B:Lx2/e;

    .line 40
    .line 41
    :cond_2
    :goto_0
    invoke-interface {v1}, Lt3/t;->I()Z

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    sget-object v3, Lmx0/t;->d:Lmx0/t;

    .line 46
    .line 47
    const-wide v5, 0xffffffffL

    .line 48
    .line 49
    .line 50
    .line 51
    .line 52
    const/16 v7, 0x20

    .line 53
    .line 54
    if-eqz v2, :cond_3

    .line 55
    .line 56
    invoke-interface/range {p2 .. p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    iget v4, v2, Lt3/e1;->d:I

    .line 61
    .line 62
    iget v8, v2, Lt3/e1;->e:I

    .line 63
    .line 64
    int-to-long v9, v4

    .line 65
    shl-long/2addr v9, v7

    .line 66
    int-to-long v11, v8

    .line 67
    and-long/2addr v11, v5

    .line 68
    or-long v8, v9, v11

    .line 69
    .line 70
    iput-wide v8, v0, Lb1/s0;->A:J

    .line 71
    .line 72
    shr-long v10, v8, v7

    .line 73
    .line 74
    long-to-int v0, v10

    .line 75
    and-long v4, v8, v5

    .line 76
    .line 77
    long-to-int v4, v4

    .line 78
    new-instance v5, Lb1/y;

    .line 79
    .line 80
    const/4 v6, 0x1

    .line 81
    invoke-direct {v5, v2, v6}, Lb1/y;-><init>(Lt3/e1;I)V

    .line 82
    .line 83
    .line 84
    invoke-interface {v1, v0, v4, v3, v5}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    return-object v0

    .line 89
    :cond_3
    iget-object v2, v0, Lb1/s0;->y:Lay0/a;

    .line 90
    .line 91
    invoke-interface {v2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    check-cast v2, Ljava/lang/Boolean;

    .line 96
    .line 97
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    if-eqz v2, :cond_e

    .line 102
    .line 103
    iget-object v2, v0, Lb1/s0;->z:Lb1/j0;

    .line 104
    .line 105
    iget-object v8, v2, Lb1/j0;->a:Lc1/q1;

    .line 106
    .line 107
    iget-object v9, v2, Lb1/j0;->b:Lc1/q1;

    .line 108
    .line 109
    iget-object v10, v2, Lb1/j0;->c:Lc1/w1;

    .line 110
    .line 111
    iget-object v11, v2, Lb1/j0;->d:Lb1/t0;

    .line 112
    .line 113
    iget-object v12, v2, Lb1/j0;->e:Lb1/u0;

    .line 114
    .line 115
    iget-object v2, v2, Lb1/j0;->f:Lc1/q1;

    .line 116
    .line 117
    if-eqz v8, :cond_4

    .line 118
    .line 119
    new-instance v13, Lb1/k0;

    .line 120
    .line 121
    const/4 v14, 0x0

    .line 122
    invoke-direct {v13, v11, v12, v14}, Lb1/k0;-><init>(Lb1/t0;Lb1/u0;I)V

    .line 123
    .line 124
    .line 125
    new-instance v14, Lb1/k0;

    .line 126
    .line 127
    const/4 v15, 0x1

    .line 128
    invoke-direct {v14, v11, v12, v15}, Lb1/k0;-><init>(Lb1/t0;Lb1/u0;I)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v8, v13, v14}, Lc1/q1;->a(Lay0/k;Lay0/k;)Lc1/p1;

    .line 132
    .line 133
    .line 134
    move-result-object v8

    .line 135
    goto :goto_1

    .line 136
    :cond_4
    move-object v8, v4

    .line 137
    :goto_1
    if-eqz v9, :cond_5

    .line 138
    .line 139
    new-instance v13, Lb1/k0;

    .line 140
    .line 141
    const/4 v14, 0x2

    .line 142
    invoke-direct {v13, v11, v12, v14}, Lb1/k0;-><init>(Lb1/t0;Lb1/u0;I)V

    .line 143
    .line 144
    .line 145
    new-instance v14, Lb1/k0;

    .line 146
    .line 147
    const/4 v15, 0x3

    .line 148
    invoke-direct {v14, v11, v12, v15}, Lb1/k0;-><init>(Lb1/t0;Lb1/u0;I)V

    .line 149
    .line 150
    .line 151
    invoke-virtual {v9, v13, v14}, Lc1/q1;->a(Lay0/k;Lay0/k;)Lc1/p1;

    .line 152
    .line 153
    .line 154
    move-result-object v9

    .line 155
    goto :goto_2

    .line 156
    :cond_5
    move-object v9, v4

    .line 157
    :goto_2
    iget-object v10, v10, Lc1/w1;->a:Lap0/o;

    .line 158
    .line 159
    invoke-virtual {v10}, Lap0/o;->D()Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v10

    .line 163
    sget-object v13, Lb1/i0;->d:Lb1/i0;

    .line 164
    .line 165
    if-ne v10, v13, :cond_6

    .line 166
    .line 167
    iget-object v10, v12, Lb1/u0;->a:Lb1/i1;

    .line 168
    .line 169
    goto :goto_3

    .line 170
    :cond_6
    iget-object v10, v12, Lb1/u0;->a:Lb1/i1;

    .line 171
    .line 172
    :goto_3
    if-eqz v2, :cond_7

    .line 173
    .line 174
    sget-object v10, Lb1/c;->p:Lb1/c;

    .line 175
    .line 176
    new-instance v13, La3/g;

    .line 177
    .line 178
    const/4 v14, 0x3

    .line 179
    invoke-direct {v13, v4, v11, v12, v14}, La3/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v2, v10, v13}, Lc1/q1;->a(Lay0/k;Lay0/k;)Lc1/p1;

    .line 183
    .line 184
    .line 185
    move-result-object v2

    .line 186
    goto :goto_4

    .line 187
    :cond_7
    move-object v2, v4

    .line 188
    :goto_4
    new-instance v10, La3/g;

    .line 189
    .line 190
    const/4 v11, 0x2

    .line 191
    invoke-direct {v10, v8, v9, v2, v11}, La3/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 192
    .line 193
    .line 194
    invoke-interface/range {p2 .. p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 195
    .line 196
    .line 197
    move-result-object v11

    .line 198
    iget v2, v11, Lt3/e1;->d:I

    .line 199
    .line 200
    iget v8, v11, Lt3/e1;->e:I

    .line 201
    .line 202
    int-to-long v12, v2

    .line 203
    shl-long/2addr v12, v7

    .line 204
    int-to-long v8, v8

    .line 205
    and-long/2addr v8, v5

    .line 206
    or-long/2addr v8, v12

    .line 207
    iget-wide v12, v0, Lb1/s0;->A:J

    .line 208
    .line 209
    sget-wide v14, Landroidx/compose/animation/c;->a:J

    .line 210
    .line 211
    invoke-static {v12, v13, v14, v15}, Lt4/l;->a(JJ)Z

    .line 212
    .line 213
    .line 214
    move-result v2

    .line 215
    if-nez v2, :cond_8

    .line 216
    .line 217
    iget-wide v12, v0, Lb1/s0;->A:J

    .line 218
    .line 219
    goto :goto_5

    .line 220
    :cond_8
    move-wide v12, v8

    .line 221
    :goto_5
    iget-object v2, v0, Lb1/s0;->t:Lc1/q1;

    .line 222
    .line 223
    if-eqz v2, :cond_9

    .line 224
    .line 225
    new-instance v4, Lb1/q0;

    .line 226
    .line 227
    const/4 v14, 0x0

    .line 228
    invoke-direct {v4, v0, v12, v13, v14}, Lb1/q0;-><init>(Lb1/s0;JI)V

    .line 229
    .line 230
    .line 231
    iget-object v14, v0, Lb1/s0;->C:Lb1/r0;

    .line 232
    .line 233
    invoke-virtual {v2, v14, v4}, Lc1/q1;->a(Lay0/k;Lay0/k;)Lc1/p1;

    .line 234
    .line 235
    .line 236
    move-result-object v4

    .line 237
    :cond_9
    if-eqz v4, :cond_a

    .line 238
    .line 239
    invoke-virtual {v4}, Lc1/p1;->getValue()Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v2

    .line 243
    check-cast v2, Lt4/l;

    .line 244
    .line 245
    iget-wide v8, v2, Lt4/l;->a:J

    .line 246
    .line 247
    :cond_a
    move-wide/from16 v14, p3

    .line 248
    .line 249
    invoke-static {v14, v15, v8, v9}, Lt4/b;->d(JJ)J

    .line 250
    .line 251
    .line 252
    move-result-wide v17

    .line 253
    iget-object v2, v0, Lb1/s0;->u:Lc1/q1;

    .line 254
    .line 255
    const-wide/16 v8, 0x0

    .line 256
    .line 257
    if-eqz v2, :cond_b

    .line 258
    .line 259
    sget-object v4, Lb1/c;->v:Lb1/c;

    .line 260
    .line 261
    new-instance v14, Lb1/q0;

    .line 262
    .line 263
    const/4 v15, 0x1

    .line 264
    invoke-direct {v14, v0, v12, v13, v15}, Lb1/q0;-><init>(Lb1/s0;JI)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v2, v4, v14}, Lc1/q1;->a(Lay0/k;Lay0/k;)Lc1/p1;

    .line 268
    .line 269
    .line 270
    move-result-object v2

    .line 271
    invoke-virtual {v2}, Lc1/p1;->getValue()Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v2

    .line 275
    check-cast v2, Lt4/j;

    .line 276
    .line 277
    iget-wide v14, v2, Lt4/j;->a:J

    .line 278
    .line 279
    move-wide/from16 v20, v14

    .line 280
    .line 281
    goto :goto_6

    .line 282
    :cond_b
    move-wide/from16 v20, v8

    .line 283
    .line 284
    :goto_6
    iget-object v2, v0, Lb1/s0;->v:Lc1/q1;

    .line 285
    .line 286
    if-eqz v2, :cond_c

    .line 287
    .line 288
    new-instance v4, Lb1/q0;

    .line 289
    .line 290
    const/4 v14, 0x2

    .line 291
    invoke-direct {v4, v0, v12, v13, v14}, Lb1/q0;-><init>(Lb1/s0;JI)V

    .line 292
    .line 293
    .line 294
    iget-object v14, v0, Lb1/s0;->D:Lb1/r0;

    .line 295
    .line 296
    invoke-virtual {v2, v14, v4}, Lc1/q1;->a(Lay0/k;Lay0/k;)Lc1/p1;

    .line 297
    .line 298
    .line 299
    move-result-object v2

    .line 300
    invoke-virtual {v2}, Lc1/p1;->getValue()Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object v2

    .line 304
    check-cast v2, Lt4/j;

    .line 305
    .line 306
    iget-wide v14, v2, Lt4/j;->a:J

    .line 307
    .line 308
    goto :goto_7

    .line 309
    :cond_c
    move-wide v14, v8

    .line 310
    :goto_7
    iget-object v0, v0, Lb1/s0;->B:Lx2/e;

    .line 311
    .line 312
    if-eqz v0, :cond_d

    .line 313
    .line 314
    sget-object v19, Lt4/m;->d:Lt4/m;

    .line 315
    .line 316
    move-wide/from16 v22, v14

    .line 317
    .line 318
    move-wide v15, v12

    .line 319
    move-wide/from16 v12, v22

    .line 320
    .line 321
    move-object v14, v0

    .line 322
    invoke-interface/range {v14 .. v19}, Lx2/e;->a(JJLt4/m;)J

    .line 323
    .line 324
    .line 325
    move-result-wide v8

    .line 326
    goto :goto_8

    .line 327
    :cond_d
    move-wide v12, v14

    .line 328
    :goto_8
    invoke-static {v8, v9, v12, v13}, Lt4/j;->d(JJ)J

    .line 329
    .line 330
    .line 331
    move-result-wide v12

    .line 332
    shr-long v7, v17, v7

    .line 333
    .line 334
    long-to-int v0, v7

    .line 335
    and-long v4, v17, v5

    .line 336
    .line 337
    long-to-int v2, v4

    .line 338
    move-object/from16 v16, v10

    .line 339
    .line 340
    new-instance v10, Lb1/p0;

    .line 341
    .line 342
    move-wide/from16 v14, v20

    .line 343
    .line 344
    invoke-direct/range {v10 .. v16}, Lb1/p0;-><init>(Lt3/e1;JJLa3/g;)V

    .line 345
    .line 346
    .line 347
    invoke-interface {v1, v0, v2, v3, v10}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 348
    .line 349
    .line 350
    move-result-object v0

    .line 351
    return-object v0

    .line 352
    :cond_e
    move-wide/from16 v14, p3

    .line 353
    .line 354
    invoke-interface/range {p2 .. p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 355
    .line 356
    .line 357
    move-result-object v0

    .line 358
    iget v2, v0, Lt3/e1;->d:I

    .line 359
    .line 360
    iget v4, v0, Lt3/e1;->e:I

    .line 361
    .line 362
    new-instance v5, Lb1/y;

    .line 363
    .line 364
    const/4 v6, 0x2

    .line 365
    invoke-direct {v5, v0, v6}, Lb1/y;-><init>(Lt3/e1;I)V

    .line 366
    .line 367
    .line 368
    invoke-interface {v1, v2, v4, v3, v5}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 369
    .line 370
    .line 371
    move-result-object v0

    .line 372
    return-object v0
.end method
