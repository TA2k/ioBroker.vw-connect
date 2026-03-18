.class public final synthetic Lmc/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lmc/r;

.field public final synthetic f:Lmc/p;


# direct methods
.method public synthetic constructor <init>(Lmc/r;Lmc/p;I)V
    .locals 0

    .line 1
    iput p3, p0, Lmc/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lmc/f;->e:Lmc/r;

    .line 4
    .line 5
    iput-object p2, p0, Lmc/f;->f:Lmc/p;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lmc/f;->d:I

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
    const/4 v5, 0x1

    .line 24
    if-eq v3, v4, :cond_0

    .line 25
    .line 26
    move v3, v5

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v3, 0x0

    .line 29
    :goto_0
    and-int/2addr v2, v5

    .line 30
    move-object v8, v1

    .line 31
    check-cast v8, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v8, v2, v3}, Ll2/t;->O(IZ)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_3

    .line 38
    .line 39
    invoke-static {v8}, Lzb/b;->u(Ll2/o;)Lzb/j;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    iget-object v11, v0, Lmc/f;->f:Lmc/p;

    .line 44
    .line 45
    iget-object v1, v11, Lmc/p;->o:Lyy0/l1;

    .line 46
    .line 47
    invoke-static {v1, v8}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    move-object v6, v1

    .line 56
    check-cast v6, Llc/q;

    .line 57
    .line 58
    invoke-virtual {v8, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    if-nez v1, :cond_1

    .line 67
    .line 68
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 69
    .line 70
    if-ne v2, v1, :cond_2

    .line 71
    .line 72
    :cond_1
    new-instance v9, Ll20/g;

    .line 73
    .line 74
    const/4 v15, 0x0

    .line 75
    const/16 v16, 0x8

    .line 76
    .line 77
    const/4 v10, 0x1

    .line 78
    const-class v12, Lmc/p;

    .line 79
    .line 80
    const-string v13, "onUiEvent"

    .line 81
    .line 82
    const-string v14, "onUiEvent(Lcariad/charging/multicharge/common/presentation/payment/AddOrReplacePaymentUiEvent;)V"

    .line 83
    .line 84
    invoke-direct/range {v9 .. v16}, Ll20/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v8, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    move-object v2, v9

    .line 91
    :cond_2
    check-cast v2, Lhy0/g;

    .line 92
    .line 93
    move-object v7, v2

    .line 94
    check-cast v7, Lay0/k;

    .line 95
    .line 96
    const/4 v9, 0x0

    .line 97
    iget-object v5, v0, Lmc/f;->e:Lmc/r;

    .line 98
    .line 99
    invoke-interface/range {v4 .. v9}, Lzb/j;->o(Lmc/r;Llc/q;Lay0/k;Ll2/o;I)V

    .line 100
    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_3
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 104
    .line 105
    .line 106
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 107
    .line 108
    return-object v0

    .line 109
    :pswitch_0
    move-object/from16 v1, p1

    .line 110
    .line 111
    check-cast v1, Ll2/o;

    .line 112
    .line 113
    move-object/from16 v2, p2

    .line 114
    .line 115
    check-cast v2, Ljava/lang/Integer;

    .line 116
    .line 117
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 118
    .line 119
    .line 120
    move-result v2

    .line 121
    and-int/lit8 v3, v2, 0x3

    .line 122
    .line 123
    const/4 v4, 0x2

    .line 124
    const/4 v5, 0x1

    .line 125
    if-eq v3, v4, :cond_4

    .line 126
    .line 127
    move v3, v5

    .line 128
    goto :goto_2

    .line 129
    :cond_4
    const/4 v3, 0x0

    .line 130
    :goto_2
    and-int/2addr v2, v5

    .line 131
    move-object v8, v1

    .line 132
    check-cast v8, Ll2/t;

    .line 133
    .line 134
    invoke-virtual {v8, v2, v3}, Ll2/t;->O(IZ)Z

    .line 135
    .line 136
    .line 137
    move-result v1

    .line 138
    if-eqz v1, :cond_7

    .line 139
    .line 140
    invoke-static {v8}, Lzb/b;->u(Ll2/o;)Lzb/j;

    .line 141
    .line 142
    .line 143
    move-result-object v4

    .line 144
    iget-object v11, v0, Lmc/f;->f:Lmc/p;

    .line 145
    .line 146
    iget-object v1, v11, Lmc/p;->o:Lyy0/l1;

    .line 147
    .line 148
    invoke-static {v1, v8}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    move-object v6, v1

    .line 157
    check-cast v6, Llc/q;

    .line 158
    .line 159
    invoke-virtual {v8, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v1

    .line 163
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v2

    .line 167
    if-nez v1, :cond_5

    .line 168
    .line 169
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 170
    .line 171
    if-ne v2, v1, :cond_6

    .line 172
    .line 173
    :cond_5
    new-instance v9, Ll20/g;

    .line 174
    .line 175
    const/4 v15, 0x0

    .line 176
    const/16 v16, 0x9

    .line 177
    .line 178
    const/4 v10, 0x1

    .line 179
    const-class v12, Lmc/p;

    .line 180
    .line 181
    const-string v13, "onUiEvent"

    .line 182
    .line 183
    const-string v14, "onUiEvent(Lcariad/charging/multicharge/common/presentation/payment/AddOrReplacePaymentUiEvent;)V"

    .line 184
    .line 185
    invoke-direct/range {v9 .. v16}, Ll20/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v8, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    move-object v2, v9

    .line 192
    :cond_6
    check-cast v2, Lhy0/g;

    .line 193
    .line 194
    move-object v7, v2

    .line 195
    check-cast v7, Lay0/k;

    .line 196
    .line 197
    const/4 v9, 0x0

    .line 198
    iget-object v5, v0, Lmc/f;->e:Lmc/r;

    .line 199
    .line 200
    invoke-interface/range {v4 .. v9}, Lzb/j;->o(Lmc/r;Llc/q;Lay0/k;Ll2/o;I)V

    .line 201
    .line 202
    .line 203
    goto :goto_3

    .line 204
    :cond_7
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 205
    .line 206
    .line 207
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 208
    .line 209
    return-object v0

    .line 210
    :pswitch_1
    move-object/from16 v1, p1

    .line 211
    .line 212
    check-cast v1, Ll2/o;

    .line 213
    .line 214
    move-object/from16 v2, p2

    .line 215
    .line 216
    check-cast v2, Ljava/lang/Integer;

    .line 217
    .line 218
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 219
    .line 220
    .line 221
    move-result v2

    .line 222
    and-int/lit8 v3, v2, 0x3

    .line 223
    .line 224
    const/4 v4, 0x2

    .line 225
    const/4 v5, 0x0

    .line 226
    const/4 v6, 0x1

    .line 227
    if-eq v3, v4, :cond_8

    .line 228
    .line 229
    move v3, v6

    .line 230
    goto :goto_4

    .line 231
    :cond_8
    move v3, v5

    .line 232
    :goto_4
    and-int/2addr v2, v6

    .line 233
    check-cast v1, Ll2/t;

    .line 234
    .line 235
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 236
    .line 237
    .line 238
    move-result v2

    .line 239
    if-eqz v2, :cond_c

    .line 240
    .line 241
    sget-wide v2, Le3/s;->e:J

    .line 242
    .line 243
    sget-object v4, Le3/j0;->a:Le3/i0;

    .line 244
    .line 245
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 246
    .line 247
    invoke-static {v7, v2, v3, v4}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 248
    .line 249
    .line 250
    move-result-object v2

    .line 251
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 252
    .line 253
    invoke-static {v3, v5}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 254
    .line 255
    .line 256
    move-result-object v3

    .line 257
    iget-wide v4, v1, Ll2/t;->T:J

    .line 258
    .line 259
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 260
    .line 261
    .line 262
    move-result v4

    .line 263
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 264
    .line 265
    .line 266
    move-result-object v5

    .line 267
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 268
    .line 269
    .line 270
    move-result-object v2

    .line 271
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 272
    .line 273
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 274
    .line 275
    .line 276
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 277
    .line 278
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 279
    .line 280
    .line 281
    iget-boolean v8, v1, Ll2/t;->S:Z

    .line 282
    .line 283
    if-eqz v8, :cond_9

    .line 284
    .line 285
    invoke-virtual {v1, v7}, Ll2/t;->l(Lay0/a;)V

    .line 286
    .line 287
    .line 288
    goto :goto_5

    .line 289
    :cond_9
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 290
    .line 291
    .line 292
    :goto_5
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 293
    .line 294
    invoke-static {v7, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 295
    .line 296
    .line 297
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 298
    .line 299
    invoke-static {v3, v5, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 300
    .line 301
    .line 302
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 303
    .line 304
    iget-boolean v5, v1, Ll2/t;->S:Z

    .line 305
    .line 306
    if-nez v5, :cond_a

    .line 307
    .line 308
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object v5

    .line 312
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 313
    .line 314
    .line 315
    move-result-object v7

    .line 316
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 317
    .line 318
    .line 319
    move-result v5

    .line 320
    if-nez v5, :cond_b

    .line 321
    .line 322
    :cond_a
    invoke-static {v4, v1, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 323
    .line 324
    .line 325
    :cond_b
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 326
    .line 327
    invoke-static {v3, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 328
    .line 329
    .line 330
    sget-object v2, Lzb/x;->d:Ll2/u2;

    .line 331
    .line 332
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 333
    .line 334
    invoke-virtual {v2, v3}, Ll2/u2;->a(Ljava/lang/Object;)Ll2/t1;

    .line 335
    .line 336
    .line 337
    move-result-object v2

    .line 338
    new-instance v3, Lmc/f;

    .line 339
    .line 340
    const/4 v4, 0x2

    .line 341
    iget-object v5, v0, Lmc/f;->e:Lmc/r;

    .line 342
    .line 343
    iget-object v0, v0, Lmc/f;->f:Lmc/p;

    .line 344
    .line 345
    invoke-direct {v3, v5, v0, v4}, Lmc/f;-><init>(Lmc/r;Lmc/p;I)V

    .line 346
    .line 347
    .line 348
    const v0, -0x4ed966d5

    .line 349
    .line 350
    .line 351
    invoke-static {v0, v1, v3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 352
    .line 353
    .line 354
    move-result-object v0

    .line 355
    const/16 v3, 0x38

    .line 356
    .line 357
    invoke-static {v2, v0, v1, v3}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 358
    .line 359
    .line 360
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 361
    .line 362
    .line 363
    goto :goto_6

    .line 364
    :cond_c
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 365
    .line 366
    .line 367
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 368
    .line 369
    return-object v0

    .line 370
    nop

    .line 371
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
