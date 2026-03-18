.class public final synthetic Lmg/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:J

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;JLl2/b1;Ll2/b1;Ll2/b1;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lmg/l;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lmg/l;->e:Ljava/lang/String;

    iput-wide p2, p0, Lmg/l;->f:J

    iput-object p4, p0, Lmg/l;->g:Ljava/lang/Object;

    iput-object p5, p0, Lmg/l;->h:Ljava/lang/Object;

    iput-object p6, p0, Lmg/l;->i:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lj3/f;JLjava/lang/String;Ljava/lang/String;I)V
    .locals 0

    .line 2
    const/4 p7, 0x1

    iput p7, p0, Lmg/l;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lmg/l;->e:Ljava/lang/String;

    iput-object p2, p0, Lmg/l;->g:Ljava/lang/Object;

    iput-wide p3, p0, Lmg/l;->f:J

    iput-object p5, p0, Lmg/l;->h:Ljava/lang/Object;

    iput-object p6, p0, Lmg/l;->i:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lmg/l;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lmg/l;->g:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v3, v1

    .line 11
    check-cast v3, Lj3/f;

    .line 12
    .line 13
    iget-object v1, v0, Lmg/l;->h:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v6, v1

    .line 16
    check-cast v6, Ljava/lang/String;

    .line 17
    .line 18
    iget-object v1, v0, Lmg/l;->i:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v7, v1

    .line 21
    check-cast v7, Ljava/lang/String;

    .line 22
    .line 23
    move-object/from16 v8, p1

    .line 24
    .line 25
    check-cast v8, Ll2/o;

    .line 26
    .line 27
    move-object/from16 v1, p2

    .line 28
    .line 29
    check-cast v1, Ljava/lang/Integer;

    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    const/16 v1, 0xc01

    .line 35
    .line 36
    invoke-static {v1}, Ll2/b;->x(I)I

    .line 37
    .line 38
    .line 39
    move-result v9

    .line 40
    iget-object v2, v0, Lmg/l;->e:Ljava/lang/String;

    .line 41
    .line 42
    iget-wide v4, v0, Lmg/l;->f:J

    .line 43
    .line 44
    invoke-static/range {v2 .. v9}, Llp/se;->f(Ljava/lang/String;Lj3/f;JLjava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 45
    .line 46
    .line 47
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object v0

    .line 50
    :pswitch_0
    iget-object v1, v0, Lmg/l;->g:Ljava/lang/Object;

    .line 51
    .line 52
    move-object v3, v1

    .line 53
    check-cast v3, Ll2/b1;

    .line 54
    .line 55
    iget-object v1, v0, Lmg/l;->h:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v1, Ll2/b1;

    .line 58
    .line 59
    iget-object v2, v0, Lmg/l;->i:Ljava/lang/Object;

    .line 60
    .line 61
    move-object v11, v2

    .line 62
    check-cast v11, Ll2/b1;

    .line 63
    .line 64
    move-object/from16 v12, p1

    .line 65
    .line 66
    check-cast v12, Lz9/w;

    .line 67
    .line 68
    move-object/from16 v2, p2

    .line 69
    .line 70
    check-cast v2, Lzb/v0;

    .line 71
    .line 72
    const-string v4, "<this>"

    .line 73
    .line 74
    invoke-static {v12, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    const-string v4, "navigator"

    .line 78
    .line 79
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    new-instance v9, Lh2/d6;

    .line 83
    .line 84
    const/4 v4, 0x4

    .line 85
    iget-wide v5, v0, Lmg/l;->f:J

    .line 86
    .line 87
    invoke-direct {v9, v2, v5, v6, v4}, Lh2/d6;-><init>(Ljava/lang/Object;JI)V

    .line 88
    .line 89
    .line 90
    new-instance v4, Ll20/f;

    .line 91
    .line 92
    const/16 v5, 0x15

    .line 93
    .line 94
    invoke-direct {v4, v5}, Ll20/f;-><init>(I)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v2, v4}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 98
    .line 99
    .line 100
    move-result-object v5

    .line 101
    new-instance v4, Leh/c;

    .line 102
    .line 103
    const/16 v6, 0x17

    .line 104
    .line 105
    invoke-direct {v4, v11, v6}, Leh/c;-><init>(Ll2/b1;I)V

    .line 106
    .line 107
    .line 108
    invoke-virtual {v2, v4}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 109
    .line 110
    .line 111
    move-result-object v6

    .line 112
    new-instance v4, Leh/c;

    .line 113
    .line 114
    const/16 v7, 0x18

    .line 115
    .line 116
    invoke-direct {v4, v3, v7}, Leh/c;-><init>(Ll2/b1;I)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v2, v4}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 120
    .line 121
    .line 122
    move-result-object v4

    .line 123
    new-instance v7, Lmg/i;

    .line 124
    .line 125
    const/16 v8, 0xc

    .line 126
    .line 127
    invoke-direct {v7, v8}, Lmg/i;-><init>(I)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v2, v7}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 131
    .line 132
    .line 133
    move-result-object v7

    .line 134
    new-instance v8, Leh/c;

    .line 135
    .line 136
    const/16 v10, 0x19

    .line 137
    .line 138
    invoke-direct {v8, v1, v10}, Leh/c;-><init>(Ll2/b1;I)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v2, v8}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 142
    .line 143
    .line 144
    move-result-object v8

    .line 145
    new-instance v10, Ll20/f;

    .line 146
    .line 147
    const/16 v13, 0x13

    .line 148
    .line 149
    invoke-direct {v10, v13}, Ll20/f;-><init>(I)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v2, v10}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 153
    .line 154
    .line 155
    move-result-object v10

    .line 156
    new-instance v13, Ll20/f;

    .line 157
    .line 158
    const/16 v14, 0x14

    .line 159
    .line 160
    invoke-direct {v13, v14}, Ll20/f;-><init>(I)V

    .line 161
    .line 162
    .line 163
    new-instance v14, Ly1/i;

    .line 164
    .line 165
    const/16 v15, 0x11

    .line 166
    .line 167
    invoke-direct {v14, v2, v15}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 168
    .line 169
    .line 170
    new-instance v15, Lmg/i;

    .line 171
    .line 172
    move-object/from16 v16, v1

    .line 173
    .line 174
    const/16 v1, 0xd

    .line 175
    .line 176
    invoke-direct {v15, v1}, Lmg/i;-><init>(I)V

    .line 177
    .line 178
    .line 179
    invoke-virtual {v2, v15}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 180
    .line 181
    .line 182
    move-result-object v1

    .line 183
    new-instance v15, Leh/c;

    .line 184
    .line 185
    move-object/from16 p1, v1

    .line 186
    .line 187
    const/16 v1, 0x1a

    .line 188
    .line 189
    invoke-direct {v15, v3, v1}, Leh/c;-><init>(Ll2/b1;I)V

    .line 190
    .line 191
    .line 192
    invoke-virtual {v2, v15}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 193
    .line 194
    .line 195
    move-result-object v1

    .line 196
    new-instance v2, Lz9/w;

    .line 197
    .line 198
    iget-object v15, v12, Lz9/w;->g:Lz9/k0;

    .line 199
    .line 200
    move-object/from16 p2, v5

    .line 201
    .line 202
    const-string v5, "/tariff_upgrade_follow_up_selection"

    .line 203
    .line 204
    move-object/from16 v26, v6

    .line 205
    .line 206
    const-string v6, "/tariff_upgrade_or_follow_flow"

    .line 207
    .line 208
    invoke-direct {v2, v15, v5, v6}, Lz9/w;-><init>(Lz9/k0;Ljava/lang/String;Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    new-instance v5, Lmg/e;

    .line 212
    .line 213
    const/4 v6, 0x1

    .line 214
    iget-object v0, v0, Lmg/l;->e:Ljava/lang/String;

    .line 215
    .line 216
    invoke-direct {v5, v0, v4, v6}, Lmg/e;-><init>(Ljava/lang/String;Lxh/e;I)V

    .line 217
    .line 218
    .line 219
    new-instance v4, Lt2/b;

    .line 220
    .line 221
    const v6, -0x15bcf5c5

    .line 222
    .line 223
    .line 224
    const/4 v15, 0x1

    .line 225
    invoke-direct {v4, v5, v15, v6}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 226
    .line 227
    .line 228
    const/16 v25, 0xfe

    .line 229
    .line 230
    const/16 v19, 0x0

    .line 231
    .line 232
    const/16 v20, 0x0

    .line 233
    .line 234
    const/16 v21, 0x0

    .line 235
    .line 236
    const/16 v22, 0x0

    .line 237
    .line 238
    const/16 v23, 0x0

    .line 239
    .line 240
    const-string v18, "/tariff_upgrade_follow_up_selection"

    .line 241
    .line 242
    move-object/from16 v17, v2

    .line 243
    .line 244
    move-object/from16 v24, v4

    .line 245
    .line 246
    invoke-static/range {v17 .. v25}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 247
    .line 248
    .line 249
    new-instance v2, Lmg/f;

    .line 250
    .line 251
    invoke-direct {v2, v3, v7, v10, v9}, Lmg/f;-><init>(Ll2/b1;Lyj/b;Lxh/e;Lh2/d6;)V

    .line 252
    .line 253
    .line 254
    new-instance v4, Lt2/b;

    .line 255
    .line 256
    const/4 v5, 0x1

    .line 257
    const v6, 0x4b44d024    # 1.289834E7f

    .line 258
    .line 259
    .line 260
    invoke-direct {v4, v2, v5, v6}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 261
    .line 262
    .line 263
    const-string v18, "/tariff_upgrade_follow_up_details"

    .line 264
    .line 265
    move-object/from16 v24, v4

    .line 266
    .line 267
    invoke-static/range {v17 .. v25}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 268
    .line 269
    .line 270
    new-instance v2, Leh/e;

    .line 271
    .line 272
    move-object/from16 v5, p2

    .line 273
    .line 274
    move-object v7, v0

    .line 275
    move-object v4, v8

    .line 276
    move-object/from16 v6, v26

    .line 277
    .line 278
    move-object/from16 v8, p1

    .line 279
    .line 280
    invoke-direct/range {v2 .. v10}, Leh/e;-><init>(Ll2/b1;Lxh/e;Lxh/e;Lxh/e;Ljava/lang/String;Lyj/b;Lh2/d6;Lxh/e;)V

    .line 281
    .line 282
    .line 283
    new-instance v0, Lt2/b;

    .line 284
    .line 285
    const/4 v4, 0x1

    .line 286
    const v5, 0x46bf9bc3

    .line 287
    .line 288
    .line 289
    invoke-direct {v0, v2, v4, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 290
    .line 291
    .line 292
    const-string v18, "/tariff_upgrade_follow_up_confirmation"

    .line 293
    .line 294
    move-object/from16 v24, v0

    .line 295
    .line 296
    invoke-static/range {v17 .. v25}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 297
    .line 298
    .line 299
    new-instance v0, Llf/a;

    .line 300
    .line 301
    const/4 v2, 0x1

    .line 302
    invoke-direct {v0, v1, v14, v2}, Llf/a;-><init>(Lxh/e;Ly1/i;I)V

    .line 303
    .line 304
    .line 305
    new-instance v1, Lt2/b;

    .line 306
    .line 307
    const v4, 0x423a6762

    .line 308
    .line 309
    .line 310
    invoke-direct {v1, v0, v2, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 311
    .line 312
    .line 313
    const-string v18, "/payment/edit"

    .line 314
    .line 315
    move-object/from16 v24, v1

    .line 316
    .line 317
    invoke-static/range {v17 .. v25}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 318
    .line 319
    .line 320
    new-instance v2, Leh/l;

    .line 321
    .line 322
    const/4 v7, 0x3

    .line 323
    const/4 v5, 0x0

    .line 324
    move-object v6, v3

    .line 325
    move-object v3, v14

    .line 326
    move-object/from16 v4, v16

    .line 327
    .line 328
    invoke-direct/range {v2 .. v7}, Leh/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;I)V

    .line 329
    .line 330
    .line 331
    new-instance v0, Lt2/b;

    .line 332
    .line 333
    const/4 v1, 0x1

    .line 334
    const v4, 0x3db53301

    .line 335
    .line 336
    .line 337
    invoke-direct {v0, v2, v1, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 338
    .line 339
    .line 340
    const-string v18, "/tariff_upgrade_follow_up_success"

    .line 341
    .line 342
    move-object/from16 v24, v0

    .line 343
    .line 344
    invoke-static/range {v17 .. v25}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 345
    .line 346
    .line 347
    new-instance v0, Leh/f;

    .line 348
    .line 349
    const/4 v1, 0x3

    .line 350
    invoke-direct {v0, v11, v1}, Leh/f;-><init>(Ll2/b1;I)V

    .line 351
    .line 352
    .line 353
    new-instance v1, Lt2/b;

    .line 354
    .line 355
    const/4 v2, 0x1

    .line 356
    const v4, 0x392ffea0

    .line 357
    .line 358
    .line 359
    invoke-direct {v1, v0, v2, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 360
    .line 361
    .line 362
    const-string v18, "/document"

    .line 363
    .line 364
    move-object/from16 v24, v1

    .line 365
    .line 366
    invoke-static/range {v17 .. v25}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 367
    .line 368
    .line 369
    const-string v0, "/webview"

    .line 370
    .line 371
    const-string v1, "url"

    .line 372
    .line 373
    invoke-static {v0, v1}, Lzb/b;->E(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 374
    .line 375
    .line 376
    move-result-object v18

    .line 377
    invoke-static {v0, v1}, Lzb/b;->D(Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;

    .line 378
    .line 379
    .line 380
    move-result-object v19

    .line 381
    sget-object v24, Lzb/b;->e:Lt2/b;

    .line 382
    .line 383
    const/16 v25, 0xfc

    .line 384
    .line 385
    invoke-static/range {v17 .. v25}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 386
    .line 387
    .line 388
    const-string v0, "/pdfDownload"

    .line 389
    .line 390
    const-string v1, "id"

    .line 391
    .line 392
    invoke-static {v0, v1}, Lzb/b;->E(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 393
    .line 394
    .line 395
    move-result-object v18

    .line 396
    invoke-static {v0, v1}, Lzb/b;->D(Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;

    .line 397
    .line 398
    .line 399
    move-result-object v19

    .line 400
    new-instance v0, Ldl/h;

    .line 401
    .line 402
    const/4 v1, 0x5

    .line 403
    invoke-direct {v0, v1, v3, v13}, Ldl/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 404
    .line 405
    .line 406
    new-instance v1, Lt2/b;

    .line 407
    .line 408
    const v3, -0x4cb69fe4

    .line 409
    .line 410
    .line 411
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 412
    .line 413
    .line 414
    move-object/from16 v24, v1

    .line 415
    .line 416
    invoke-static/range {v17 .. v25}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 417
    .line 418
    .line 419
    iget-object v0, v12, Lz9/w;->k:Ljava/util/ArrayList;

    .line 420
    .line 421
    invoke-virtual/range {v17 .. v17}, Lz9/w;->a()Lz9/u;

    .line 422
    .line 423
    .line 424
    move-result-object v1

    .line 425
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 426
    .line 427
    .line 428
    goto/16 :goto_0

    .line 429
    .line 430
    nop

    .line 431
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
