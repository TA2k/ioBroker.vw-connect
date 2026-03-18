.class public final La2/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ll2/b1;Lh2/nb;Lk1/z0;Lay0/n;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, La2/i;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La2/i;->e:Ll2/b1;

    iput-object p2, p0, La2/i;->f:Ljava/lang/Object;

    iput-object p3, p0, La2/i;->g:Ljava/lang/Object;

    iput-object p4, p0, La2/i;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lx2/s;Ll2/b1;Lt2/b;La2/d;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, La2/i;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La2/i;->f:Ljava/lang/Object;

    iput-object p2, p0, La2/i;->e:Ll2/b1;

    iput-object p3, p0, La2/i;->g:Ljava/lang/Object;

    iput-object p4, p0, La2/i;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, La2/i;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, v0, La2/i;->h:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v4, v0, La2/i;->g:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v5, v0, La2/i;->f:Ljava/lang/Object;

    .line 12
    .line 13
    const/4 v6, 0x2

    .line 14
    const/4 v7, 0x1

    .line 15
    const/4 v8, 0x0

    .line 16
    packed-switch v1, :pswitch_data_0

    .line 17
    .line 18
    .line 19
    move-object/from16 v1, p1

    .line 20
    .line 21
    check-cast v1, Ll2/o;

    .line 22
    .line 23
    move-object/from16 v9, p2

    .line 24
    .line 25
    check-cast v9, Ljava/lang/Number;

    .line 26
    .line 27
    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    .line 28
    .line 29
    .line 30
    move-result v9

    .line 31
    and-int/lit8 v10, v9, 0x3

    .line 32
    .line 33
    if-eq v10, v6, :cond_0

    .line 34
    .line 35
    move v6, v7

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    move v6, v8

    .line 38
    :goto_0
    and-int/2addr v9, v7

    .line 39
    check-cast v1, Ll2/t;

    .line 40
    .line 41
    invoke-virtual {v1, v9, v6}, Ll2/t;->O(IZ)Z

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    if-eqz v6, :cond_4

    .line 46
    .line 47
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 48
    .line 49
    const-string v9, "Container"

    .line 50
    .line 51
    invoke-static {v6, v9}, Landroidx/compose/ui/layout/a;->c(Lx2/s;Ljava/lang/Object;)Lx2/s;

    .line 52
    .line 53
    .line 54
    move-result-object v6

    .line 55
    new-instance v9, Lhz0/o;

    .line 56
    .line 57
    const/4 v10, 0x0

    .line 58
    const/16 v11, 0xb

    .line 59
    .line 60
    const-class v12, Ll2/b1;

    .line 61
    .line 62
    iget-object v13, v0, La2/i;->e:Ll2/b1;

    .line 63
    .line 64
    const-string v14, "value"

    .line 65
    .line 66
    const-string v15, "getValue()Ljava/lang/Object;"

    .line 67
    .line 68
    invoke-direct/range {v9 .. v15}, Lhz0/o;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    check-cast v5, Lh2/nb;

    .line 72
    .line 73
    invoke-static {v5}, Li2/h1;->c(Lh2/nb;)Lx2/d;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    check-cast v4, Lk1/z0;

    .line 78
    .line 79
    sget v5, Lh2/c7;->a:F

    .line 80
    .line 81
    new-instance v5, Laa/o;

    .line 82
    .line 83
    const/16 v10, 0x17

    .line 84
    .line 85
    invoke-direct {v5, v9, v4, v0, v10}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 86
    .line 87
    .line 88
    invoke-static {v6, v5}, Landroidx/compose/ui/draw/a;->c(Lx2/s;Lay0/k;)Lx2/s;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    check-cast v3, Lay0/n;

    .line 93
    .line 94
    sget-object v4, Lx2/c;->d:Lx2/j;

    .line 95
    .line 96
    invoke-static {v4, v7}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 97
    .line 98
    .line 99
    move-result-object v4

    .line 100
    iget-wide v5, v1, Ll2/t;->T:J

    .line 101
    .line 102
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 103
    .line 104
    .line 105
    move-result v5

    .line 106
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 107
    .line 108
    .line 109
    move-result-object v6

    .line 110
    invoke-static {v1, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    sget-object v9, Lv3/k;->m1:Lv3/j;

    .line 115
    .line 116
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 117
    .line 118
    .line 119
    sget-object v9, Lv3/j;->b:Lv3/i;

    .line 120
    .line 121
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 122
    .line 123
    .line 124
    iget-boolean v10, v1, Ll2/t;->S:Z

    .line 125
    .line 126
    if-eqz v10, :cond_1

    .line 127
    .line 128
    invoke-virtual {v1, v9}, Ll2/t;->l(Lay0/a;)V

    .line 129
    .line 130
    .line 131
    goto :goto_1

    .line 132
    :cond_1
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 133
    .line 134
    .line 135
    :goto_1
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 136
    .line 137
    invoke-static {v9, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 138
    .line 139
    .line 140
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 141
    .line 142
    invoke-static {v4, v6, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 143
    .line 144
    .line 145
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 146
    .line 147
    iget-boolean v6, v1, Ll2/t;->S:Z

    .line 148
    .line 149
    if-nez v6, :cond_2

    .line 150
    .line 151
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v6

    .line 155
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 156
    .line 157
    .line 158
    move-result-object v9

    .line 159
    invoke-static {v6, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v6

    .line 163
    if-nez v6, :cond_3

    .line 164
    .line 165
    :cond_2
    invoke-static {v5, v1, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 166
    .line 167
    .line 168
    :cond_3
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 169
    .line 170
    invoke-static {v4, v0, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 171
    .line 172
    .line 173
    invoke-static {v8, v3, v1, v7}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 174
    .line 175
    .line 176
    goto :goto_2

    .line 177
    :cond_4
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 178
    .line 179
    .line 180
    :goto_2
    return-object v2

    .line 181
    :pswitch_0
    move-object/from16 v1, p1

    .line 182
    .line 183
    check-cast v1, Ll2/o;

    .line 184
    .line 185
    move-object/from16 v9, p2

    .line 186
    .line 187
    check-cast v9, Ljava/lang/Number;

    .line 188
    .line 189
    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    .line 190
    .line 191
    .line 192
    move-result v9

    .line 193
    and-int/lit8 v10, v9, 0x3

    .line 194
    .line 195
    if-eq v10, v6, :cond_5

    .line 196
    .line 197
    move v6, v7

    .line 198
    goto :goto_3

    .line 199
    :cond_5
    move v6, v8

    .line 200
    :goto_3
    and-int/2addr v9, v7

    .line 201
    check-cast v1, Ll2/t;

    .line 202
    .line 203
    invoke-virtual {v1, v9, v6}, Ll2/t;->O(IZ)Z

    .line 204
    .line 205
    .line 206
    move-result v6

    .line 207
    if-eqz v6, :cond_b

    .line 208
    .line 209
    check-cast v5, Lx2/s;

    .line 210
    .line 211
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v6

    .line 215
    iget-object v0, v0, La2/i;->e:Ll2/b1;

    .line 216
    .line 217
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 218
    .line 219
    if-ne v6, v9, :cond_6

    .line 220
    .line 221
    new-instance v6, La2/g;

    .line 222
    .line 223
    invoke-direct {v6, v0, v8}, La2/g;-><init>(Ll2/b1;I)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {v1, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    :cond_6
    check-cast v6, Lay0/k;

    .line 230
    .line 231
    invoke-static {v5, v6}, Landroidx/compose/ui/layout/a;->d(Lx2/s;Lay0/k;)Lx2/s;

    .line 232
    .line 233
    .line 234
    move-result-object v5

    .line 235
    check-cast v4, Lt2/b;

    .line 236
    .line 237
    check-cast v3, La2/d;

    .line 238
    .line 239
    sget-object v6, Lx2/c;->d:Lx2/j;

    .line 240
    .line 241
    invoke-static {v6, v7}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 242
    .line 243
    .line 244
    move-result-object v6

    .line 245
    iget-wide v10, v1, Ll2/t;->T:J

    .line 246
    .line 247
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 248
    .line 249
    .line 250
    move-result v10

    .line 251
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 252
    .line 253
    .line 254
    move-result-object v11

    .line 255
    invoke-static {v1, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 256
    .line 257
    .line 258
    move-result-object v5

    .line 259
    sget-object v12, Lv3/k;->m1:Lv3/j;

    .line 260
    .line 261
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 262
    .line 263
    .line 264
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 265
    .line 266
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 267
    .line 268
    .line 269
    iget-boolean v13, v1, Ll2/t;->S:Z

    .line 270
    .line 271
    if-eqz v13, :cond_7

    .line 272
    .line 273
    invoke-virtual {v1, v12}, Ll2/t;->l(Lay0/a;)V

    .line 274
    .line 275
    .line 276
    goto :goto_4

    .line 277
    :cond_7
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 278
    .line 279
    .line 280
    :goto_4
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 281
    .line 282
    invoke-static {v12, v6, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 283
    .line 284
    .line 285
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 286
    .line 287
    invoke-static {v6, v11, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 288
    .line 289
    .line 290
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 291
    .line 292
    iget-boolean v11, v1, Ll2/t;->S:Z

    .line 293
    .line 294
    if-nez v11, :cond_8

    .line 295
    .line 296
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v11

    .line 300
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 301
    .line 302
    .line 303
    move-result-object v12

    .line 304
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 305
    .line 306
    .line 307
    move-result v11

    .line 308
    if-nez v11, :cond_9

    .line 309
    .line 310
    :cond_8
    invoke-static {v10, v1, v10, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 311
    .line 312
    .line 313
    :cond_9
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 314
    .line 315
    invoke-static {v6, v5, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 316
    .line 317
    .line 318
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 319
    .line 320
    .line 321
    move-result-object v5

    .line 322
    invoke-virtual {v4, v1, v5}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 323
    .line 324
    .line 325
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v4

    .line 329
    if-ne v4, v9, :cond_a

    .line 330
    .line 331
    new-instance v4, La2/h;

    .line 332
    .line 333
    invoke-direct {v4, v0, v8}, La2/h;-><init>(Ll2/b1;I)V

    .line 334
    .line 335
    .line 336
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 337
    .line 338
    .line 339
    :cond_a
    check-cast v4, Lay0/a;

    .line 340
    .line 341
    const/4 v0, 0x6

    .line 342
    invoke-virtual {v3, v4, v1, v0}, La2/d;->b(Lay0/a;Ll2/o;I)V

    .line 343
    .line 344
    .line 345
    invoke-virtual {v1, v7}, Ll2/t;->q(Z)V

    .line 346
    .line 347
    .line 348
    goto :goto_5

    .line 349
    :cond_b
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 350
    .line 351
    .line 352
    :goto_5
    return-object v2

    .line 353
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
