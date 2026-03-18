.class public final synthetic Lha0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lga0/i;

.field public final synthetic f:Lay0/a;

.field public final synthetic g:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lga0/i;Lay0/a;Lay0/a;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lha0/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lha0/a;->e:Lga0/i;

    iput-object p2, p0, Lha0/a;->f:Lay0/a;

    iput-object p3, p0, Lha0/a;->g:Lay0/a;

    return-void
.end method

.method public synthetic constructor <init>(Lga0/i;Lay0/a;Lay0/a;I)V
    .locals 0

    .line 2
    const/4 p4, 0x0

    iput p4, p0, Lha0/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lha0/a;->e:Lga0/i;

    iput-object p2, p0, Lha0/a;->f:Lay0/a;

    iput-object p3, p0, Lha0/a;->g:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lha0/a;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x2

    .line 23
    const/4 v6, 0x1

    .line 24
    if-eq v3, v4, :cond_0

    .line 25
    .line 26
    move v3, v6

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v3, 0x0

    .line 29
    :goto_0
    and-int/2addr v2, v6

    .line 30
    check-cast v1, Ll2/t;

    .line 31
    .line 32
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    if-eqz v2, :cond_8

    .line 37
    .line 38
    sget-object v2, Lx2/c;->q:Lx2/h;

    .line 39
    .line 40
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 41
    .line 42
    const/high16 v4, 0x3f800000    # 1.0f

    .line 43
    .line 44
    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 45
    .line 46
    .line 47
    move-result-object v7

    .line 48
    sget-object v8, Lj91/a;->a:Ll2/u2;

    .line 49
    .line 50
    invoke-virtual {v1, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v9

    .line 54
    check-cast v9, Lj91/c;

    .line 55
    .line 56
    iget v9, v9, Lj91/c;->j:F

    .line 57
    .line 58
    invoke-static {v7, v9}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 59
    .line 60
    .line 61
    move-result-object v7

    .line 62
    sget-object v9, Lk1/j;->c:Lk1/e;

    .line 63
    .line 64
    const/16 v10, 0x30

    .line 65
    .line 66
    invoke-static {v9, v2, v1, v10}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    iget-wide v11, v1, Ll2/t;->T:J

    .line 71
    .line 72
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 73
    .line 74
    .line 75
    move-result v9

    .line 76
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 77
    .line 78
    .line 79
    move-result-object v11

    .line 80
    invoke-static {v1, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 81
    .line 82
    .line 83
    move-result-object v7

    .line 84
    sget-object v12, Lv3/k;->m1:Lv3/j;

    .line 85
    .line 86
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 90
    .line 91
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 92
    .line 93
    .line 94
    iget-boolean v13, v1, Ll2/t;->S:Z

    .line 95
    .line 96
    if-eqz v13, :cond_1

    .line 97
    .line 98
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    .line 99
    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_1
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 103
    .line 104
    .line 105
    :goto_1
    sget-object v13, Lv3/j;->g:Lv3/h;

    .line 106
    .line 107
    invoke-static {v13, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 108
    .line 109
    .line 110
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 111
    .line 112
    invoke-static {v2, v11, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 113
    .line 114
    .line 115
    sget-object v11, Lv3/j;->j:Lv3/h;

    .line 116
    .line 117
    iget-boolean v14, v1, Ll2/t;->S:Z

    .line 118
    .line 119
    if-nez v14, :cond_2

    .line 120
    .line 121
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v14

    .line 125
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 126
    .line 127
    .line 128
    move-result-object v15

    .line 129
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v14

    .line 133
    if-nez v14, :cond_3

    .line 134
    .line 135
    :cond_2
    invoke-static {v9, v1, v9, v11}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 136
    .line 137
    .line 138
    :cond_3
    sget-object v9, Lv3/j;->d:Lv3/h;

    .line 139
    .line 140
    invoke-static {v9, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 141
    .line 142
    .line 143
    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 144
    .line 145
    .line 146
    move-result-object v7

    .line 147
    sget-object v14, Lx2/c;->n:Lx2/i;

    .line 148
    .line 149
    sget-object v15, Lk1/j;->a:Lk1/c;

    .line 150
    .line 151
    invoke-static {v15, v14, v1, v10}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 152
    .line 153
    .line 154
    move-result-object v10

    .line 155
    iget-wide v14, v1, Ll2/t;->T:J

    .line 156
    .line 157
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 158
    .line 159
    .line 160
    move-result v14

    .line 161
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 162
    .line 163
    .line 164
    move-result-object v15

    .line 165
    invoke-static {v1, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 166
    .line 167
    .line 168
    move-result-object v7

    .line 169
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 170
    .line 171
    .line 172
    iget-boolean v5, v1, Ll2/t;->S:Z

    .line 173
    .line 174
    if-eqz v5, :cond_4

    .line 175
    .line 176
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    .line 177
    .line 178
    .line 179
    goto :goto_2

    .line 180
    :cond_4
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 181
    .line 182
    .line 183
    :goto_2
    invoke-static {v13, v10, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 184
    .line 185
    .line 186
    invoke-static {v2, v15, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 187
    .line 188
    .line 189
    iget-boolean v2, v1, Ll2/t;->S:Z

    .line 190
    .line 191
    if-nez v2, :cond_5

    .line 192
    .line 193
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v2

    .line 197
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 198
    .line 199
    .line 200
    move-result-object v5

    .line 201
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    move-result v2

    .line 205
    if-nez v2, :cond_6

    .line 206
    .line 207
    :cond_5
    invoke-static {v14, v1, v14, v11}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 208
    .line 209
    .line 210
    :cond_6
    invoke-static {v9, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 211
    .line 212
    .line 213
    const v2, 0x7f1214db

    .line 214
    .line 215
    .line 216
    invoke-static {v1, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v7

    .line 220
    float-to-double v9, v4

    .line 221
    const-wide/16 v11, 0x0

    .line 222
    .line 223
    cmpl-double v5, v9, v11

    .line 224
    .line 225
    if-lez v5, :cond_7

    .line 226
    .line 227
    goto :goto_3

    .line 228
    :cond_7
    const-string v5, "invalid weight; must be greater than zero"

    .line 229
    .line 230
    invoke-static {v5}, Ll1/a;->a(Ljava/lang/String;)V

    .line 231
    .line 232
    .line 233
    :goto_3
    new-instance v5, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 234
    .line 235
    invoke-direct {v5, v4, v6}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 236
    .line 237
    .line 238
    invoke-static {v5, v2}, Lxf0/i0;->M(Lx2/s;I)Lx2/s;

    .line 239
    .line 240
    .line 241
    move-result-object v9

    .line 242
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 243
    .line 244
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v2

    .line 248
    check-cast v2, Lj91/f;

    .line 249
    .line 250
    invoke-virtual {v2}, Lj91/f;->a()Lg4/p0;

    .line 251
    .line 252
    .line 253
    move-result-object v2

    .line 254
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 255
    .line 256
    invoke-virtual {v1, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v4

    .line 260
    check-cast v4, Lj91/e;

    .line 261
    .line 262
    invoke-virtual {v4}, Lj91/e;->s()J

    .line 263
    .line 264
    .line 265
    move-result-wide v10

    .line 266
    const/16 v27, 0x6180

    .line 267
    .line 268
    const v28, 0xaff0

    .line 269
    .line 270
    .line 271
    const-wide/16 v12, 0x0

    .line 272
    .line 273
    const/4 v14, 0x0

    .line 274
    const-wide/16 v15, 0x0

    .line 275
    .line 276
    const/16 v17, 0x0

    .line 277
    .line 278
    const/16 v18, 0x0

    .line 279
    .line 280
    const-wide/16 v19, 0x0

    .line 281
    .line 282
    const/16 v21, 0x2

    .line 283
    .line 284
    const/16 v22, 0x0

    .line 285
    .line 286
    const/16 v23, 0x1

    .line 287
    .line 288
    const/16 v24, 0x0

    .line 289
    .line 290
    const/16 v26, 0x0

    .line 291
    .line 292
    move-object/from16 v25, v1

    .line 293
    .line 294
    move-object v1, v8

    .line 295
    move-object v8, v2

    .line 296
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 297
    .line 298
    .line 299
    move-object/from16 v2, v25

    .line 300
    .line 301
    invoke-virtual {v2, v6}, Ll2/t;->q(Z)V

    .line 302
    .line 303
    .line 304
    invoke-virtual {v2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 305
    .line 306
    .line 307
    move-result-object v1

    .line 308
    check-cast v1, Lj91/c;

    .line 309
    .line 310
    iget v1, v1, Lj91/c;->c:F

    .line 311
    .line 312
    invoke-static {v3, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 313
    .line 314
    .line 315
    move-result-object v1

    .line 316
    invoke-static {v2, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 317
    .line 318
    .line 319
    iget-object v1, v0, Lha0/a;->e:Lga0/i;

    .line 320
    .line 321
    iget-object v3, v0, Lha0/a;->f:Lay0/a;

    .line 322
    .line 323
    iget-object v0, v0, Lha0/a;->g:Lay0/a;

    .line 324
    .line 325
    const/4 v4, 0x0

    .line 326
    invoke-static {v1, v3, v0, v2, v4}, Lha0/b;->a(Lga0/i;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 327
    .line 328
    .line 329
    invoke-virtual {v2, v6}, Ll2/t;->q(Z)V

    .line 330
    .line 331
    .line 332
    goto :goto_4

    .line 333
    :cond_8
    move-object v2, v1

    .line 334
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 335
    .line 336
    .line 337
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 338
    .line 339
    return-object v0

    .line 340
    :pswitch_0
    move-object/from16 v1, p1

    .line 341
    .line 342
    check-cast v1, Ll2/o;

    .line 343
    .line 344
    move-object/from16 v2, p2

    .line 345
    .line 346
    check-cast v2, Ljava/lang/Integer;

    .line 347
    .line 348
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 349
    .line 350
    .line 351
    const/4 v2, 0x1

    .line 352
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 353
    .line 354
    .line 355
    move-result v2

    .line 356
    iget-object v3, v0, Lha0/a;->e:Lga0/i;

    .line 357
    .line 358
    iget-object v4, v0, Lha0/a;->f:Lay0/a;

    .line 359
    .line 360
    iget-object v0, v0, Lha0/a;->g:Lay0/a;

    .line 361
    .line 362
    invoke-static {v3, v4, v0, v1, v2}, Lha0/b;->a(Lga0/i;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 363
    .line 364
    .line 365
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 366
    .line 367
    return-object v0

    .line 368
    nop

    .line 369
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
