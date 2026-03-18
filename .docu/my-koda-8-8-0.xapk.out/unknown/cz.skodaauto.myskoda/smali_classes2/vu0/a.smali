.class public final synthetic Lvu0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Luu0/r;


# direct methods
.method public synthetic constructor <init>(Luu0/r;I)V
    .locals 0

    .line 1
    const/4 p2, 0x3

    iput p2, p0, Lvu0/a;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lvu0/a;->e:Luu0/r;

    return-void
.end method

.method public synthetic constructor <init>(Luu0/r;IB)V
    .locals 0

    .line 2
    iput p2, p0, Lvu0/a;->d:I

    iput-object p1, p0, Lvu0/a;->e:Luu0/r;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lvu0/a;->d:I

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
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    iget-object v0, v0, Lvu0/a;->e:Luu0/r;

    .line 25
    .line 26
    invoke-static {v0, v1, v2}, Lvu0/g;->h(Luu0/r;Ll2/o;I)V

    .line 27
    .line 28
    .line 29
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object v0

    .line 32
    :pswitch_0
    move-object/from16 v1, p1

    .line 33
    .line 34
    check-cast v1, Ll2/o;

    .line 35
    .line 36
    move-object/from16 v2, p2

    .line 37
    .line 38
    check-cast v2, Ljava/lang/Integer;

    .line 39
    .line 40
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    and-int/lit8 v3, v2, 0x3

    .line 45
    .line 46
    const/4 v4, 0x2

    .line 47
    const/4 v5, 0x1

    .line 48
    const/4 v6, 0x0

    .line 49
    if-eq v3, v4, :cond_0

    .line 50
    .line 51
    move v3, v5

    .line 52
    goto :goto_0

    .line 53
    :cond_0
    move v3, v6

    .line 54
    :goto_0
    and-int/2addr v2, v5

    .line 55
    move-object v12, v1

    .line 56
    check-cast v12, Ll2/t;

    .line 57
    .line 58
    invoke-virtual {v12, v2, v3}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-eqz v1, :cond_2

    .line 63
    .line 64
    iget-object v0, v0, Lvu0/a;->e:Luu0/r;

    .line 65
    .line 66
    iget-boolean v0, v0, Luu0/r;->u:Z

    .line 67
    .line 68
    if-eqz v0, :cond_1

    .line 69
    .line 70
    const v0, -0x699b4124

    .line 71
    .line 72
    .line 73
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 74
    .line 75
    .line 76
    const/16 v0, 0x20

    .line 77
    .line 78
    int-to-float v0, v0

    .line 79
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 80
    .line 81
    invoke-static {v1, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    const-string v2, "guest_user_icon"

    .line 90
    .line 91
    invoke-static {v0, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 92
    .line 93
    .line 94
    move-result-object v9

    .line 95
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 96
    .line 97
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    check-cast v0, Lj91/e;

    .line 102
    .line 103
    invoke-virtual {v0}, Lj91/e;->s()J

    .line 104
    .line 105
    .line 106
    move-result-wide v10

    .line 107
    const v0, 0x7f0803d8

    .line 108
    .line 109
    .line 110
    invoke-static {v0, v6, v12}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 111
    .line 112
    .line 113
    move-result-object v7

    .line 114
    const/16 v13, 0x1b0

    .line 115
    .line 116
    const/4 v14, 0x0

    .line 117
    const/4 v8, 0x0

    .line 118
    invoke-static/range {v7 .. v14}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 119
    .line 120
    .line 121
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 122
    .line 123
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    check-cast v0, Lj91/c;

    .line 128
    .line 129
    iget v0, v0, Lj91/c;->b:F

    .line 130
    .line 131
    invoke-static {v1, v0, v12, v6}, Lvj/b;->C(Lx2/p;FLl2/t;Z)V

    .line 132
    .line 133
    .line 134
    goto :goto_1

    .line 135
    :cond_1
    const v0, -0x6a57bb11

    .line 136
    .line 137
    .line 138
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 142
    .line 143
    .line 144
    goto :goto_1

    .line 145
    :cond_2
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 146
    .line 147
    .line 148
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 149
    .line 150
    return-object v0

    .line 151
    :pswitch_1
    move-object/from16 v1, p1

    .line 152
    .line 153
    check-cast v1, Ll2/o;

    .line 154
    .line 155
    move-object/from16 v2, p2

    .line 156
    .line 157
    check-cast v2, Ljava/lang/Integer;

    .line 158
    .line 159
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 160
    .line 161
    .line 162
    move-result v2

    .line 163
    and-int/lit8 v3, v2, 0x3

    .line 164
    .line 165
    const/4 v4, 0x2

    .line 166
    const/4 v5, 0x1

    .line 167
    const/4 v6, 0x0

    .line 168
    if-eq v3, v4, :cond_3

    .line 169
    .line 170
    move v3, v5

    .line 171
    goto :goto_2

    .line 172
    :cond_3
    move v3, v6

    .line 173
    :goto_2
    and-int/2addr v2, v5

    .line 174
    move-object v14, v1

    .line 175
    check-cast v14, Ll2/t;

    .line 176
    .line 177
    invoke-virtual {v14, v2, v3}, Ll2/t;->O(IZ)Z

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    if-eqz v1, :cond_4

    .line 182
    .line 183
    const v1, 0x7f0802d4

    .line 184
    .line 185
    .line 186
    invoke-static {v1, v6, v14}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 187
    .line 188
    .line 189
    move-result-object v7

    .line 190
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 191
    .line 192
    invoke-virtual {v14, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v1

    .line 196
    check-cast v1, Lj91/e;

    .line 197
    .line 198
    invoke-virtual {v1}, Lj91/e;->q()J

    .line 199
    .line 200
    .line 201
    move-result-wide v1

    .line 202
    new-instance v13, Le3/m;

    .line 203
    .line 204
    const/4 v3, 0x5

    .line 205
    invoke-direct {v13, v1, v2, v3}, Le3/m;-><init>(JI)V

    .line 206
    .line 207
    .line 208
    sget-object v1, Lx2/c;->n:Lx2/i;

    .line 209
    .line 210
    new-instance v2, Landroidx/compose/foundation/layout/VerticalAlignElement;

    .line 211
    .line 212
    invoke-direct {v2, v1}, Landroidx/compose/foundation/layout/VerticalAlignElement;-><init>(Lx2/i;)V

    .line 213
    .line 214
    .line 215
    const-string v1, "notification_icon"

    .line 216
    .line 217
    invoke-static {v2, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 218
    .line 219
    .line 220
    move-result-object v1

    .line 221
    iget-object v0, v0, Lvu0/a;->e:Luu0/r;

    .line 222
    .line 223
    iget-boolean v0, v0, Luu0/r;->d:Z

    .line 224
    .line 225
    invoke-static {v1, v0}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 226
    .line 227
    .line 228
    move-result-object v9

    .line 229
    const/16 v15, 0x30

    .line 230
    .line 231
    const/16 v16, 0x38

    .line 232
    .line 233
    const/4 v8, 0x0

    .line 234
    const/4 v10, 0x0

    .line 235
    const/4 v11, 0x0

    .line 236
    const/4 v12, 0x0

    .line 237
    invoke-static/range {v7 .. v16}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 238
    .line 239
    .line 240
    goto :goto_3

    .line 241
    :cond_4
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 242
    .line 243
    .line 244
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 245
    .line 246
    return-object v0

    .line 247
    :pswitch_2
    move-object/from16 v1, p1

    .line 248
    .line 249
    check-cast v1, Ll2/o;

    .line 250
    .line 251
    move-object/from16 v2, p2

    .line 252
    .line 253
    check-cast v2, Ljava/lang/Integer;

    .line 254
    .line 255
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 256
    .line 257
    .line 258
    move-result v2

    .line 259
    and-int/lit8 v3, v2, 0x3

    .line 260
    .line 261
    const/4 v4, 0x2

    .line 262
    const/4 v5, 0x1

    .line 263
    const/4 v6, 0x0

    .line 264
    if-eq v3, v4, :cond_5

    .line 265
    .line 266
    move v3, v5

    .line 267
    goto :goto_4

    .line 268
    :cond_5
    move v3, v6

    .line 269
    :goto_4
    and-int/2addr v2, v5

    .line 270
    move-object v12, v1

    .line 271
    check-cast v12, Ll2/t;

    .line 272
    .line 273
    invoke-virtual {v12, v2, v3}, Ll2/t;->O(IZ)Z

    .line 274
    .line 275
    .line 276
    move-result v1

    .line 277
    if-eqz v1, :cond_7

    .line 278
    .line 279
    iget-object v0, v0, Lvu0/a;->e:Luu0/r;

    .line 280
    .line 281
    iget-boolean v0, v0, Luu0/r;->u:Z

    .line 282
    .line 283
    if-eqz v0, :cond_6

    .line 284
    .line 285
    const v0, 0x5aebc375

    .line 286
    .line 287
    .line 288
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 289
    .line 290
    .line 291
    const/16 v0, 0x18

    .line 292
    .line 293
    int-to-float v0, v0

    .line 294
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 295
    .line 296
    invoke-static {v1, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 297
    .line 298
    .line 299
    move-result-object v2

    .line 300
    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/d;->r(Lx2/s;F)Lx2/s;

    .line 301
    .line 302
    .line 303
    move-result-object v0

    .line 304
    const-string v2, "guest_user_icon"

    .line 305
    .line 306
    invoke-static {v0, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 307
    .line 308
    .line 309
    move-result-object v9

    .line 310
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 311
    .line 312
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 313
    .line 314
    .line 315
    move-result-object v0

    .line 316
    check-cast v0, Lj91/e;

    .line 317
    .line 318
    invoke-virtual {v0}, Lj91/e;->s()J

    .line 319
    .line 320
    .line 321
    move-result-wide v10

    .line 322
    const v0, 0x7f0803d8

    .line 323
    .line 324
    .line 325
    invoke-static {v0, v6, v12}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 326
    .line 327
    .line 328
    move-result-object v7

    .line 329
    const/16 v13, 0x1b0

    .line 330
    .line 331
    const/4 v14, 0x0

    .line 332
    const/4 v8, 0x0

    .line 333
    invoke-static/range {v7 .. v14}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 334
    .line 335
    .line 336
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 337
    .line 338
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    move-result-object v0

    .line 342
    check-cast v0, Lj91/c;

    .line 343
    .line 344
    iget v0, v0, Lj91/c;->b:F

    .line 345
    .line 346
    invoke-static {v1, v0, v12, v6}, Lvj/b;->C(Lx2/p;FLl2/t;Z)V

    .line 347
    .line 348
    .line 349
    goto :goto_5

    .line 350
    :cond_6
    const v0, 0x5a4e759c

    .line 351
    .line 352
    .line 353
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 354
    .line 355
    .line 356
    invoke-virtual {v12, v6}, Ll2/t;->q(Z)V

    .line 357
    .line 358
    .line 359
    goto :goto_5

    .line 360
    :cond_7
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 361
    .line 362
    .line 363
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 364
    .line 365
    return-object v0

    .line 366
    nop

    .line 367
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
