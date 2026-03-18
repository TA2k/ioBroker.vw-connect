.class public final synthetic Li40/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:J


# direct methods
.method public synthetic constructor <init>(J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Li40/h0;->d:J

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 29

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    check-cast v0, Lk1/z0;

    .line 4
    .line 5
    move-object/from16 v1, p2

    .line 6
    .line 7
    check-cast v1, Ll2/o;

    .line 8
    .line 9
    move-object/from16 v2, p3

    .line 10
    .line 11
    check-cast v2, Ljava/lang/Integer;

    .line 12
    .line 13
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const-string v3, "paddingValues"

    .line 18
    .line 19
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    and-int/lit8 v3, v2, 0x6

    .line 23
    .line 24
    if-nez v3, :cond_1

    .line 25
    .line 26
    move-object v3, v1

    .line 27
    check-cast v3, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eqz v3, :cond_0

    .line 34
    .line 35
    const/4 v3, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 v3, 0x2

    .line 38
    :goto_0
    or-int/2addr v2, v3

    .line 39
    :cond_1
    and-int/lit8 v3, v2, 0x13

    .line 40
    .line 41
    const/16 v4, 0x12

    .line 42
    .line 43
    const/4 v5, 0x1

    .line 44
    const/4 v6, 0x0

    .line 45
    if-eq v3, v4, :cond_2

    .line 46
    .line 47
    move v3, v5

    .line 48
    goto :goto_1

    .line 49
    :cond_2
    move v3, v6

    .line 50
    :goto_1
    and-int/2addr v2, v5

    .line 51
    move-object v14, v1

    .line 52
    check-cast v14, Ll2/t;

    .line 53
    .line 54
    invoke-virtual {v14, v2, v3}, Ll2/t;->O(IZ)Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-eqz v1, :cond_6

    .line 59
    .line 60
    sget-object v1, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 61
    .line 62
    sget-object v2, Le3/j0;->a:Le3/i0;

    .line 63
    .line 64
    move-object/from16 v3, p0

    .line 65
    .line 66
    iget-wide v3, v3, Li40/h0;->d:J

    .line 67
    .line 68
    invoke-static {v1, v3, v4, v2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-static {v6, v5, v14}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    const/16 v3, 0xe

    .line 77
    .line 78
    invoke-static {v1, v2, v3}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 83
    .line 84
    invoke-virtual {v14, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v3

    .line 88
    check-cast v3, Lj91/c;

    .line 89
    .line 90
    iget v3, v3, Lj91/c;->k:F

    .line 91
    .line 92
    invoke-virtual {v14, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v4

    .line 96
    check-cast v4, Lj91/c;

    .line 97
    .line 98
    iget v4, v4, Lj91/c;->k:F

    .line 99
    .line 100
    invoke-interface {v0}, Lk1/z0;->d()F

    .line 101
    .line 102
    .line 103
    move-result v7

    .line 104
    invoke-interface {v0}, Lk1/z0;->c()F

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    invoke-virtual {v14, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v8

    .line 112
    check-cast v8, Lj91/c;

    .line 113
    .line 114
    iget v8, v8, Lj91/c;->e:F

    .line 115
    .line 116
    invoke-virtual {v14, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v9

    .line 120
    check-cast v9, Lj91/c;

    .line 121
    .line 122
    iget v9, v9, Lj91/c;->e:F

    .line 123
    .line 124
    sub-float/2addr v8, v9

    .line 125
    sub-float/2addr v0, v8

    .line 126
    invoke-static {v1, v3, v7, v4, v0}, Landroidx/compose/foundation/layout/a;->p(Lx2/s;FFFF)Lx2/s;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    sget-object v1, Lk1/j;->c:Lk1/e;

    .line 131
    .line 132
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 133
    .line 134
    invoke-static {v1, v3, v14, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    iget-wide v3, v14, Ll2/t;->T:J

    .line 139
    .line 140
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 141
    .line 142
    .line 143
    move-result v3

    .line 144
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 145
    .line 146
    .line 147
    move-result-object v4

    .line 148
    invoke-static {v14, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 153
    .line 154
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 155
    .line 156
    .line 157
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 158
    .line 159
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 160
    .line 161
    .line 162
    iget-boolean v8, v14, Ll2/t;->S:Z

    .line 163
    .line 164
    if-eqz v8, :cond_3

    .line 165
    .line 166
    invoke-virtual {v14, v7}, Ll2/t;->l(Lay0/a;)V

    .line 167
    .line 168
    .line 169
    goto :goto_2

    .line 170
    :cond_3
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 171
    .line 172
    .line 173
    :goto_2
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 174
    .line 175
    invoke-static {v7, v1, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 176
    .line 177
    .line 178
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 179
    .line 180
    invoke-static {v1, v4, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 181
    .line 182
    .line 183
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 184
    .line 185
    iget-boolean v4, v14, Ll2/t;->S:Z

    .line 186
    .line 187
    if-nez v4, :cond_4

    .line 188
    .line 189
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 194
    .line 195
    .line 196
    move-result-object v7

    .line 197
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v4

    .line 201
    if-nez v4, :cond_5

    .line 202
    .line 203
    :cond_4
    invoke-static {v3, v14, v3, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 204
    .line 205
    .line 206
    :cond_5
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 207
    .line 208
    invoke-static {v1, v0, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 209
    .line 210
    .line 211
    const/high16 v0, 0x3f800000    # 1.0f

    .line 212
    .line 213
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 214
    .line 215
    invoke-static {v1, v0}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 216
    .line 217
    .line 218
    move-result-object v9

    .line 219
    const v0, 0x7f080240

    .line 220
    .line 221
    .line 222
    invoke-static {v0, v6, v14}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 223
    .line 224
    .line 225
    move-result-object v7

    .line 226
    const/16 v15, 0x61b0

    .line 227
    .line 228
    const/16 v16, 0x68

    .line 229
    .line 230
    const/4 v8, 0x0

    .line 231
    const/4 v10, 0x0

    .line 232
    sget-object v11, Lt3/j;->d:Lt3/x0;

    .line 233
    .line 234
    const/4 v12, 0x0

    .line 235
    const/4 v13, 0x0

    .line 236
    invoke-static/range {v7 .. v16}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 237
    .line 238
    .line 239
    invoke-virtual {v14, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v0

    .line 243
    check-cast v0, Lj91/c;

    .line 244
    .line 245
    iget v0, v0, Lj91/c;->e:F

    .line 246
    .line 247
    const v3, 0x7f120c5c

    .line 248
    .line 249
    .line 250
    invoke-static {v1, v0, v14, v3, v14}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 251
    .line 252
    .line 253
    move-result-object v7

    .line 254
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 255
    .line 256
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v3

    .line 260
    check-cast v3, Lj91/f;

    .line 261
    .line 262
    invoke-virtual {v3}, Lj91/f;->i()Lg4/p0;

    .line 263
    .line 264
    .line 265
    move-result-object v8

    .line 266
    const/16 v27, 0x0

    .line 267
    .line 268
    const v28, 0xfffc

    .line 269
    .line 270
    .line 271
    const/4 v9, 0x0

    .line 272
    const-wide/16 v10, 0x0

    .line 273
    .line 274
    const-wide/16 v12, 0x0

    .line 275
    .line 276
    move-object/from16 v25, v14

    .line 277
    .line 278
    const/4 v14, 0x0

    .line 279
    const-wide/16 v15, 0x0

    .line 280
    .line 281
    const/16 v17, 0x0

    .line 282
    .line 283
    const/16 v18, 0x0

    .line 284
    .line 285
    const-wide/16 v19, 0x0

    .line 286
    .line 287
    const/16 v21, 0x0

    .line 288
    .line 289
    const/16 v22, 0x0

    .line 290
    .line 291
    const/16 v23, 0x0

    .line 292
    .line 293
    const/16 v24, 0x0

    .line 294
    .line 295
    const/16 v26, 0x0

    .line 296
    .line 297
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 298
    .line 299
    .line 300
    move-object/from16 v14, v25

    .line 301
    .line 302
    invoke-virtual {v14, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object v2

    .line 306
    check-cast v2, Lj91/c;

    .line 307
    .line 308
    iget v2, v2, Lj91/c;->d:F

    .line 309
    .line 310
    const v3, 0x7f120c5a

    .line 311
    .line 312
    .line 313
    invoke-static {v1, v2, v14, v3, v14}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 314
    .line 315
    .line 316
    move-result-object v7

    .line 317
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object v0

    .line 321
    check-cast v0, Lj91/f;

    .line 322
    .line 323
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 324
    .line 325
    .line 326
    move-result-object v8

    .line 327
    const/4 v14, 0x0

    .line 328
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 329
    .line 330
    .line 331
    move-object/from16 v14, v25

    .line 332
    .line 333
    invoke-virtual {v14, v5}, Ll2/t;->q(Z)V

    .line 334
    .line 335
    .line 336
    goto :goto_3

    .line 337
    :cond_6
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 338
    .line 339
    .line 340
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 341
    .line 342
    return-object v0
.end method
