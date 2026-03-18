.class public final Lb2/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/compose/ui/input/pointer/PointerInputEventHandler;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb2/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lb2/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Lp3/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v10, p2

    .line 6
    .line 7
    iget v2, v0, Lb2/b;->d:I

    .line 8
    .line 9
    const/4 v3, 0x2

    .line 10
    const/4 v4, 0x1

    .line 11
    const/4 v5, 0x0

    .line 12
    const/4 v6, 0x0

    .line 13
    iget-object v0, v0, Lb2/b;->e:Ljava/lang/Object;

    .line 14
    .line 15
    sget-object v11, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    packed-switch v2, :pswitch_data_0

    .line 18
    .line 19
    .line 20
    new-instance v12, Ly21/d;

    .line 21
    .line 22
    move-object v14, v0

    .line 23
    check-cast v14, Lz1/e;

    .line 24
    .line 25
    const/16 v18, 0x0

    .line 26
    .line 27
    const/16 v19, 0xb

    .line 28
    .line 29
    const/4 v13, 0x1

    .line 30
    const-class v15, Lz1/e;

    .line 31
    .line 32
    const-string v16, "tryShowContextMenu"

    .line 33
    .line 34
    const-string v17, "tryShowContextMenu-k-4lQ0M(J)V"

    .line 35
    .line 36
    invoke-direct/range {v12 .. v19}, Ly21/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 37
    .line 38
    .line 39
    new-instance v0, Le2/a0;

    .line 40
    .line 41
    invoke-direct {v0, v12, v6, v3}, Le2/a0;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 42
    .line 43
    .line 44
    invoke-static {v1, v0, v10}, Lg1/h3;->c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 49
    .line 50
    if-ne v0, v1, :cond_0

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_0
    move-object v0, v11

    .line 54
    :goto_0
    if-ne v0, v1, :cond_1

    .line 55
    .line 56
    move-object v11, v0

    .line 57
    :cond_1
    return-object v11

    .line 58
    :pswitch_0
    new-instance v2, Lna/e;

    .line 59
    .line 60
    check-cast v0, Lp1/v;

    .line 61
    .line 62
    const/16 v3, 0xe

    .line 63
    .line 64
    invoke-direct {v2, v3, v1, v0, v6}, Lna/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 65
    .line 66
    .line 67
    invoke-static {v2, v10}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 72
    .line 73
    if-ne v0, v1, :cond_2

    .line 74
    .line 75
    move-object v11, v0

    .line 76
    :cond_2
    return-object v11

    .line 77
    :pswitch_1
    check-cast v0, Li91/l1;

    .line 78
    .line 79
    new-instance v13, Li40/e1;

    .line 80
    .line 81
    const/4 v2, 0x5

    .line 82
    invoke-direct {v13, v0, v2}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 83
    .line 84
    .line 85
    new-instance v15, Li91/i;

    .line 86
    .line 87
    invoke-direct {v15, v0, v5}, Li91/i;-><init>(Li91/l1;I)V

    .line 88
    .line 89
    .line 90
    new-instance v2, Li91/i;

    .line 91
    .line 92
    invoke-direct {v2, v0, v4}, Li91/i;-><init>(Li91/l1;I)V

    .line 93
    .line 94
    .line 95
    new-instance v14, Li40/k0;

    .line 96
    .line 97
    const/16 v3, 0x15

    .line 98
    .line 99
    invoke-direct {v14, v3, v0, v1}, Li40/k0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    sget v0, Lg1/w0;->a:F

    .line 103
    .line 104
    new-instance v12, Lg1/s0;

    .line 105
    .line 106
    const/16 v17, 0x0

    .line 107
    .line 108
    const/16 v18, 0x1

    .line 109
    .line 110
    move-object/from16 v16, v2

    .line 111
    .line 112
    invoke-direct/range {v12 .. v18}, Lg1/s0;-><init>(Lay0/k;Lay0/n;Lay0/a;Lay0/a;Lkotlin/coroutines/Continuation;I)V

    .line 113
    .line 114
    .line 115
    invoke-static {v1, v12, v10}, Lg1/h3;->c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 120
    .line 121
    if-ne v0, v1, :cond_3

    .line 122
    .line 123
    goto :goto_1

    .line 124
    :cond_3
    move-object v0, v11

    .line 125
    :goto_1
    if-ne v0, v1, :cond_4

    .line 126
    .line 127
    move-object v11, v0

    .line 128
    :cond_4
    return-object v11

    .line 129
    :pswitch_2
    new-instance v2, Lh2/p9;

    .line 130
    .line 131
    check-cast v0, Lh2/s9;

    .line 132
    .line 133
    invoke-direct {v2, v0, v6}, Lh2/p9;-><init>(Lh2/s9;Lkotlin/coroutines/Continuation;)V

    .line 134
    .line 135
    .line 136
    new-instance v4, Lh2/c9;

    .line 137
    .line 138
    invoke-direct {v4, v0, v3}, Lh2/c9;-><init>(Lh2/s9;I)V

    .line 139
    .line 140
    .line 141
    const/4 v0, 0x3

    .line 142
    invoke-static {v1, v2, v4, v10, v0}, Lg1/g3;->e(Lp3/x;Lay0/o;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 147
    .line 148
    if-ne v0, v1, :cond_5

    .line 149
    .line 150
    move-object v11, v0

    .line 151
    :cond_5
    return-object v11

    .line 152
    :pswitch_3
    new-instance v2, Ld6/t0;

    .line 153
    .line 154
    check-cast v0, Lb71/o;

    .line 155
    .line 156
    invoke-direct {v2, v0, v6, v3}, Ld6/t0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 157
    .line 158
    .line 159
    invoke-static {v1, v2, v10}, Lg1/h3;->c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 164
    .line 165
    if-ne v0, v1, :cond_6

    .line 166
    .line 167
    move-object v11, v0

    .line 168
    :cond_6
    return-object v11

    .line 169
    :pswitch_4
    new-instance v2, Lh6/j;

    .line 170
    .line 171
    invoke-direct {v2}, Lh6/j;-><init>()V

    .line 172
    .line 173
    .line 174
    new-instance v3, Lkotlin/jvm/internal/e0;

    .line 175
    .line 176
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 177
    .line 178
    .line 179
    check-cast v0, Lg1/d1;

    .line 180
    .line 181
    invoke-static {v0}, Lv3/f;->w(Lv3/m;)Lv3/f1;

    .line 182
    .line 183
    .line 184
    move-result-object v6

    .line 185
    const-wide/16 v7, 0x0

    .line 186
    .line 187
    invoke-virtual {v6, v7, v8}, Lv3/f1;->K(J)J

    .line 188
    .line 189
    .line 190
    move-result-wide v6

    .line 191
    iput-wide v6, v3, Lkotlin/jvm/internal/e0;->d:J

    .line 192
    .line 193
    new-instance v6, Lf30/h;

    .line 194
    .line 195
    invoke-direct {v6, v4, v0, v2}, Lf30/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    new-instance v7, Laa/o;

    .line 199
    .line 200
    const/16 v8, 0x11

    .line 201
    .line 202
    invoke-direct {v7, v2, v1, v0, v8}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 203
    .line 204
    .line 205
    new-instance v8, Lg1/x0;

    .line 206
    .line 207
    invoke-direct {v8, v0, v5}, Lg1/x0;-><init>(Lg1/d1;I)V

    .line 208
    .line 209
    .line 210
    move-object v5, v6

    .line 211
    new-instance v6, Lg1/x0;

    .line 212
    .line 213
    invoke-direct {v6, v0, v4}, Lg1/x0;-><init>(Lg1/d1;I)V

    .line 214
    .line 215
    .line 216
    move-object v4, v7

    .line 217
    new-instance v7, Lf20/f;

    .line 218
    .line 219
    const/4 v9, 0x6

    .line 220
    invoke-direct {v7, v0, v3, v2, v9}, Lf20/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 221
    .line 222
    .line 223
    move-object v2, v0

    .line 224
    new-instance v0, Lg1/y0;

    .line 225
    .line 226
    move-object v3, v5

    .line 227
    move-object v5, v8

    .line 228
    const/4 v8, 0x0

    .line 229
    const/4 v9, 0x0

    .line 230
    invoke-direct/range {v0 .. v9}, Lg1/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 231
    .line 232
    .line 233
    invoke-static {v0, v10}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 238
    .line 239
    if-ne v0, v1, :cond_7

    .line 240
    .line 241
    move-object v11, v0

    .line 242
    :cond_7
    return-object v11

    .line 243
    :pswitch_5
    check-cast v0, Lt1/w0;

    .line 244
    .line 245
    new-instance v2, Lqh/a;

    .line 246
    .line 247
    const/4 v3, 0x4

    .line 248
    invoke-direct {v2, v3, v1, v0, v6}, Lqh/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 249
    .line 250
    .line 251
    invoke-static {v2, v10}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v0

    .line 255
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 256
    .line 257
    if-ne v0, v1, :cond_8

    .line 258
    .line 259
    goto :goto_2

    .line 260
    :cond_8
    move-object v0, v11

    .line 261
    :goto_2
    if-ne v0, v1, :cond_9

    .line 262
    .line 263
    move-object v11, v0

    .line 264
    :cond_9
    return-object v11

    .line 265
    :pswitch_6
    new-instance v2, Le2/a0;

    .line 266
    .line 267
    check-cast v0, Lay0/k;

    .line 268
    .line 269
    invoke-direct {v2, v0, v6, v5}, Le2/a0;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 270
    .line 271
    .line 272
    move-object v0, v1

    .line 273
    check-cast v0, Lp3/j0;

    .line 274
    .line 275
    invoke-virtual {v0, v2, v10}, Lp3/j0;->X0(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object v0

    .line 279
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 280
    .line 281
    if-ne v0, v1, :cond_a

    .line 282
    .line 283
    move-object v11, v0

    .line 284
    :cond_a
    return-object v11

    .line 285
    :pswitch_7
    check-cast v0, Le1/a0;

    .line 286
    .line 287
    new-instance v3, Le1/z;

    .line 288
    .line 289
    const/4 v1, 0x0

    .line 290
    invoke-direct {v3, v0, v1}, Le1/z;-><init>(Le1/a0;Lkotlin/coroutines/Continuation;)V

    .line 291
    .line 292
    .line 293
    new-instance v4, La2/e;

    .line 294
    .line 295
    const/16 v2, 0x1a

    .line 296
    .line 297
    invoke-direct {v4, v0, v2}, La2/e;-><init>(Ljava/lang/Object;I)V

    .line 298
    .line 299
    .line 300
    move-object v2, v1

    .line 301
    move-object/from16 v0, p1

    .line 302
    .line 303
    move-object v5, v10

    .line 304
    invoke-static/range {v0 .. v5}, Lg1/g3;->d(Lp3/x;Lay0/k;Lay0/k;Lay0/o;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 305
    .line 306
    .line 307
    move-result-object v0

    .line 308
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 309
    .line 310
    if-ne v0, v1, :cond_b

    .line 311
    .line 312
    move-object v11, v0

    .line 313
    :cond_b
    return-object v11

    .line 314
    :pswitch_8
    new-instance v2, Ld6/t0;

    .line 315
    .line 316
    check-cast v0, Le1/j;

    .line 317
    .line 318
    invoke-direct {v2, v0, v6, v4}, Ld6/t0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 319
    .line 320
    .line 321
    invoke-static {v1, v2, v10}, Lg1/h3;->c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object v0

    .line 325
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 326
    .line 327
    if-ne v0, v1, :cond_c

    .line 328
    .line 329
    move-object v11, v0

    .line 330
    :cond_c
    return-object v11

    .line 331
    :pswitch_9
    new-instance v2, Lb2/a;

    .line 332
    .line 333
    check-cast v0, Lb2/c;

    .line 334
    .line 335
    invoke-direct {v2, v0, v6, v5}, Lb2/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 336
    .line 337
    .line 338
    invoke-static {v1, v2, v10}, Lg1/h3;->c(Lp3/x;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    move-result-object v0

    .line 342
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 343
    .line 344
    if-ne v0, v1, :cond_d

    .line 345
    .line 346
    move-object v11, v0

    .line 347
    :cond_d
    return-object v11

    .line 348
    nop

    .line 349
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
