.class public final synthetic Li40/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh40/e1;


# direct methods
.method public synthetic constructor <init>(Lh40/e1;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li40/u0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/u0;->e:Lh40/e1;

    return-void
.end method

.method public synthetic constructor <init>(Lh40/e1;I)V
    .locals 0

    .line 2
    const/4 p2, 0x0

    iput p2, p0, Li40/u0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/u0;->e:Lh40/e1;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li40/u0;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    iget-object v0, v0, Li40/u0;->e:Lh40/e1;

    .line 9
    .line 10
    packed-switch v1, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    move-object/from16 v1, p1

    .line 14
    .line 15
    check-cast v1, Ll2/o;

    .line 16
    .line 17
    move-object/from16 v4, p2

    .line 18
    .line 19
    check-cast v4, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    and-int/lit8 v5, v4, 0x3

    .line 26
    .line 27
    const/4 v6, 0x2

    .line 28
    const/4 v7, 0x0

    .line 29
    if-eq v5, v6, :cond_0

    .line 30
    .line 31
    move v5, v3

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    move v5, v7

    .line 34
    :goto_0
    and-int/2addr v4, v3

    .line 35
    move-object v13, v1

    .line 36
    check-cast v13, Ll2/t;

    .line 37
    .line 38
    invoke-virtual {v13, v4, v5}, Ll2/t;->O(IZ)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_7

    .line 43
    .line 44
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 45
    .line 46
    const/high16 v4, 0x3f800000    # 1.0f

    .line 47
    .line 48
    invoke-static {v1, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    const/16 v5, 0xc

    .line 53
    .line 54
    int-to-float v5, v5

    .line 55
    sget-object v6, Lj91/a;->a:Ll2/u2;

    .line 56
    .line 57
    invoke-virtual {v13, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v8

    .line 61
    check-cast v8, Lj91/c;

    .line 62
    .line 63
    iget v8, v8, Lj91/c;->d:F

    .line 64
    .line 65
    invoke-static {v1, v5, v8}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    sget-object v5, Lk1/j;->a:Lk1/c;

    .line 70
    .line 71
    invoke-virtual {v13, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v5

    .line 75
    check-cast v5, Lj91/c;

    .line 76
    .line 77
    iget v5, v5, Lj91/c;->d:F

    .line 78
    .line 79
    invoke-static {v5}, Lk1/j;->g(F)Lk1/h;

    .line 80
    .line 81
    .line 82
    move-result-object v5

    .line 83
    sget-object v6, Lx2/c;->n:Lx2/i;

    .line 84
    .line 85
    const/16 v8, 0x30

    .line 86
    .line 87
    invoke-static {v5, v6, v13, v8}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 88
    .line 89
    .line 90
    move-result-object v5

    .line 91
    iget-wide v8, v13, Ll2/t;->T:J

    .line 92
    .line 93
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 94
    .line 95
    .line 96
    move-result v6

    .line 97
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 98
    .line 99
    .line 100
    move-result-object v8

    .line 101
    invoke-static {v13, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 106
    .line 107
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 108
    .line 109
    .line 110
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 111
    .line 112
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 113
    .line 114
    .line 115
    iget-boolean v10, v13, Ll2/t;->S:Z

    .line 116
    .line 117
    if-eqz v10, :cond_1

    .line 118
    .line 119
    invoke-virtual {v13, v9}, Ll2/t;->l(Lay0/a;)V

    .line 120
    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_1
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 124
    .line 125
    .line 126
    :goto_1
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 127
    .line 128
    invoke-static {v9, v5, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 129
    .line 130
    .line 131
    sget-object v5, Lv3/j;->f:Lv3/h;

    .line 132
    .line 133
    invoke-static {v5, v8, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 134
    .line 135
    .line 136
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 137
    .line 138
    iget-boolean v8, v13, Ll2/t;->S:Z

    .line 139
    .line 140
    if-nez v8, :cond_2

    .line 141
    .line 142
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v8

    .line 146
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 147
    .line 148
    .line 149
    move-result-object v9

    .line 150
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v8

    .line 154
    if-nez v8, :cond_3

    .line 155
    .line 156
    :cond_2
    invoke-static {v6, v13, v6, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 157
    .line 158
    .line 159
    :cond_3
    sget-object v5, Lv3/j;->d:Lv3/h;

    .line 160
    .line 161
    invoke-static {v5, v1, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 162
    .line 163
    .line 164
    iget-object v1, v0, Lh40/e1;->h:Ljava/time/LocalDate;

    .line 165
    .line 166
    if-eqz v1, :cond_4

    .line 167
    .line 168
    const v1, -0x53d28e9a

    .line 169
    .line 170
    .line 171
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 172
    .line 173
    .line 174
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 175
    .line 176
    invoke-virtual {v13, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v1

    .line 180
    check-cast v1, Lj91/e;

    .line 181
    .line 182
    invoke-virtual {v1}, Lj91/e;->q()J

    .line 183
    .line 184
    .line 185
    move-result-wide v5

    .line 186
    :goto_2
    invoke-virtual {v13, v7}, Ll2/t;->q(Z)V

    .line 187
    .line 188
    .line 189
    move-wide v11, v5

    .line 190
    goto :goto_3

    .line 191
    :cond_4
    const v1, -0x53d28a58

    .line 192
    .line 193
    .line 194
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 195
    .line 196
    .line 197
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 198
    .line 199
    invoke-virtual {v13, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v1

    .line 203
    check-cast v1, Lj91/e;

    .line 204
    .line 205
    invoke-virtual {v1}, Lj91/e;->s()J

    .line 206
    .line 207
    .line 208
    move-result-wide v5

    .line 209
    goto :goto_2

    .line 210
    :goto_3
    iget-object v0, v0, Lh40/e1;->m:Ljava/lang/String;

    .line 211
    .line 212
    if-nez v0, :cond_5

    .line 213
    .line 214
    const v0, -0x53d27ec4

    .line 215
    .line 216
    .line 217
    const v1, 0x7f120c75

    .line 218
    .line 219
    .line 220
    invoke-static {v0, v1, v13, v13, v7}, Lvj/b;->g(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    :goto_4
    move-object v8, v0

    .line 225
    goto :goto_5

    .line 226
    :cond_5
    const v1, -0x53d281ac

    .line 227
    .line 228
    .line 229
    invoke-virtual {v13, v1}, Ll2/t;->Y(I)V

    .line 230
    .line 231
    .line 232
    invoke-virtual {v13, v7}, Ll2/t;->q(Z)V

    .line 233
    .line 234
    .line 235
    goto :goto_4

    .line 236
    :goto_5
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 237
    .line 238
    invoke-virtual {v13, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v0

    .line 242
    check-cast v0, Lj91/f;

    .line 243
    .line 244
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 245
    .line 246
    .line 247
    move-result-object v9

    .line 248
    float-to-double v0, v4

    .line 249
    const-wide/16 v5, 0x0

    .line 250
    .line 251
    cmpl-double v0, v0, v5

    .line 252
    .line 253
    if-lez v0, :cond_6

    .line 254
    .line 255
    goto :goto_6

    .line 256
    :cond_6
    const-string v0, "invalid weight; must be greater than zero"

    .line 257
    .line 258
    invoke-static {v0}, Ll1/a;->a(Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    :goto_6
    new-instance v10, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 262
    .line 263
    invoke-direct {v10, v4, v3}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 264
    .line 265
    .line 266
    const/16 v28, 0x0

    .line 267
    .line 268
    const v29, 0xfff0

    .line 269
    .line 270
    .line 271
    move-object/from16 v26, v13

    .line 272
    .line 273
    const-wide/16 v13, 0x0

    .line 274
    .line 275
    const/4 v15, 0x0

    .line 276
    const-wide/16 v16, 0x0

    .line 277
    .line 278
    const/16 v18, 0x0

    .line 279
    .line 280
    const/16 v19, 0x0

    .line 281
    .line 282
    const-wide/16 v20, 0x0

    .line 283
    .line 284
    const/16 v22, 0x0

    .line 285
    .line 286
    const/16 v23, 0x0

    .line 287
    .line 288
    const/16 v24, 0x0

    .line 289
    .line 290
    const/16 v25, 0x0

    .line 291
    .line 292
    const/16 v27, 0x0

    .line 293
    .line 294
    invoke-static/range {v8 .. v29}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 295
    .line 296
    .line 297
    move-object/from16 v13, v26

    .line 298
    .line 299
    const v0, 0x7f08033b

    .line 300
    .line 301
    .line 302
    invoke-static {v0, v7, v13}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 303
    .line 304
    .line 305
    move-result-object v8

    .line 306
    const/16 v14, 0x30

    .line 307
    .line 308
    const/4 v15, 0x4

    .line 309
    const/4 v9, 0x0

    .line 310
    const/4 v10, 0x0

    .line 311
    invoke-static/range {v8 .. v15}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 312
    .line 313
    .line 314
    invoke-virtual {v13, v3}, Ll2/t;->q(Z)V

    .line 315
    .line 316
    .line 317
    goto :goto_7

    .line 318
    :cond_7
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 319
    .line 320
    .line 321
    :goto_7
    return-object v2

    .line 322
    :pswitch_0
    move-object/from16 v1, p1

    .line 323
    .line 324
    check-cast v1, Ll2/o;

    .line 325
    .line 326
    move-object/from16 v4, p2

    .line 327
    .line 328
    check-cast v4, Ljava/lang/Integer;

    .line 329
    .line 330
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 331
    .line 332
    .line 333
    invoke-static {v3}, Ll2/b;->x(I)I

    .line 334
    .line 335
    .line 336
    move-result v3

    .line 337
    invoke-static {v0, v1, v3}, Li40/x0;->c(Lh40/e1;Ll2/o;I)V

    .line 338
    .line 339
    .line 340
    return-object v2

    .line 341
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
