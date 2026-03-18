.class public abstract Lzj/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lzb/k;->a:Lzb/u;

    .line 2
    .line 3
    return-void
.end method

.method public static final a(Lfd/d;Lb6/f;Ll2/o;I)V
    .locals 12

    .line 1
    move-object v3, p2

    .line 2
    check-cast v3, Ll2/t;

    .line 3
    .line 4
    const p2, 0x827f5a0

    .line 5
    .line 6
    .line 7
    invoke-virtual {v3, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    and-int/lit8 p2, p3, 0x30

    .line 11
    .line 12
    if-nez p2, :cond_1

    .line 13
    .line 14
    invoke-virtual {v3, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    if-eqz p2, :cond_0

    .line 19
    .line 20
    const/16 p2, 0x20

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/16 p2, 0x10

    .line 24
    .line 25
    :goto_0
    or-int/2addr p2, p3

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    move p2, p3

    .line 28
    :goto_1
    and-int/lit8 v0, p2, 0x13

    .line 29
    .line 30
    const/16 v1, 0x12

    .line 31
    .line 32
    const/4 v10, 0x1

    .line 33
    const/4 v11, 0x0

    .line 34
    if-eq v0, v1, :cond_2

    .line 35
    .line 36
    move v0, v10

    .line 37
    goto :goto_2

    .line 38
    :cond_2
    move v0, v11

    .line 39
    :goto_2
    and-int/2addr p2, v10

    .line 40
    invoke-virtual {v3, p2, v0}, Ll2/t;->O(IZ)Z

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    if-eqz p2, :cond_e

    .line 45
    .line 46
    const/4 p2, 0x0

    .line 47
    if-nez p1, :cond_3

    .line 48
    .line 49
    const v0, 0x2222d7e4

    .line 50
    .line 51
    .line 52
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v3, v11}, Ll2/t;->q(Z)V

    .line 56
    .line 57
    .line 58
    move-object v0, p2

    .line 59
    goto :goto_4

    .line 60
    :cond_3
    const v0, 0x2222d7e5

    .line 61
    .line 62
    .line 63
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 64
    .line 65
    .line 66
    new-instance v4, Li91/v2;

    .line 67
    .line 68
    iget-boolean v0, p1, Lb6/f;->d:Z

    .line 69
    .line 70
    if-eqz v0, :cond_4

    .line 71
    .line 72
    const v0, -0x7834b5e2

    .line 73
    .line 74
    .line 75
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 76
    .line 77
    .line 78
    sget-object v0, Lyj/f;->a:Ll2/e0;

    .line 79
    .line 80
    invoke-virtual {v3, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v0

    .line 84
    check-cast v0, Ll2/b1;

    .line 85
    .line 86
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    check-cast v0, Ljava/lang/Boolean;

    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 93
    .line 94
    .line 95
    move-result v0

    .line 96
    invoke-virtual {v3, v11}, Ll2/t;->q(Z)V

    .line 97
    .line 98
    .line 99
    move v9, v0

    .line 100
    goto :goto_3

    .line 101
    :cond_4
    const v0, 0x719dfe77

    .line 102
    .line 103
    .line 104
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v3, v11}, Ll2/t;->q(Z)V

    .line 108
    .line 109
    .line 110
    move v9, v11

    .line 111
    :goto_3
    iget-object v0, p1, Lb6/f;->e:Ljava/lang/Object;

    .line 112
    .line 113
    move-object v7, v0

    .line 114
    check-cast v7, Lyj/b;

    .line 115
    .line 116
    const/4 v6, 0x4

    .line 117
    const v5, 0x7f0803a5

    .line 118
    .line 119
    .line 120
    const/4 v8, 0x0

    .line 121
    invoke-direct/range {v4 .. v9}, Li91/v2;-><init>(IILay0/a;Ljava/lang/String;Z)V

    .line 122
    .line 123
    .line 124
    invoke-static {v4}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    invoke-virtual {v3, v11}, Ll2/t;->q(Z)V

    .line 129
    .line 130
    .line 131
    :goto_4
    if-nez v0, :cond_5

    .line 132
    .line 133
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 134
    .line 135
    :cond_5
    move-object v4, v0

    .line 136
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 137
    .line 138
    const-string v1, "app_bar"

    .line 139
    .line 140
    invoke-static {v0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    const v1, 0x7f1208cd

    .line 145
    .line 146
    .line 147
    invoke-static {v3, v1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v1

    .line 151
    move-object v7, v3

    .line 152
    new-instance v3, Li91/w2;

    .line 153
    .line 154
    invoke-static {v7}, Lzb/b;->r(Ll2/o;)Lay0/a;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    const/4 v5, 0x2

    .line 159
    invoke-direct {v3, v2, v5}, Li91/w2;-><init>(Lay0/a;I)V

    .line 160
    .line 161
    .line 162
    const/4 v8, 0x6

    .line 163
    const/16 v9, 0x33c

    .line 164
    .line 165
    const/4 v2, 0x0

    .line 166
    const/4 v5, 0x0

    .line 167
    const/4 v6, 0x0

    .line 168
    invoke-static/range {v0 .. v9}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 169
    .line 170
    .line 171
    if-nez p0, :cond_6

    .line 172
    .line 173
    const p2, 0x222c4832

    .line 174
    .line 175
    .line 176
    invoke-virtual {v7, p2}, Ll2/t;->Y(I)V

    .line 177
    .line 178
    .line 179
    :goto_5
    invoke-virtual {v7, v11}, Ll2/t;->q(Z)V

    .line 180
    .line 181
    .line 182
    goto/16 :goto_9

    .line 183
    .line 184
    :cond_6
    const v0, 0x222c4833

    .line 185
    .line 186
    .line 187
    invoke-virtual {v7, v0}, Ll2/t;->Y(I)V

    .line 188
    .line 189
    .line 190
    new-instance v0, Ljava/util/ArrayList;

    .line 191
    .line 192
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 193
    .line 194
    .line 195
    const v1, -0x61fe8834

    .line 196
    .line 197
    .line 198
    invoke-virtual {v7, v1}, Ll2/t;->Y(I)V

    .line 199
    .line 200
    .line 201
    iget-object v1, p0, Lfd/d;->a:Ljava/util/List;

    .line 202
    .line 203
    check-cast v1, Ljava/lang/Iterable;

    .line 204
    .line 205
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 206
    .line 207
    .line 208
    move-result-object v1

    .line 209
    move v2, v11

    .line 210
    :goto_6
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 211
    .line 212
    .line 213
    move-result v3

    .line 214
    if-eqz v3, :cond_d

    .line 215
    .line 216
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 217
    .line 218
    .line 219
    move-result-object v3

    .line 220
    add-int/lit8 v4, v2, 0x1

    .line 221
    .line 222
    if-ltz v2, :cond_c

    .line 223
    .line 224
    check-cast v3, Lbd/a;

    .line 225
    .line 226
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 227
    .line 228
    .line 229
    move-result v3

    .line 230
    if-eqz v3, :cond_8

    .line 231
    .line 232
    if-ne v3, v10, :cond_7

    .line 233
    .line 234
    const v3, -0x44fc3bda

    .line 235
    .line 236
    .line 237
    const v5, 0x7f1208d0

    .line 238
    .line 239
    .line 240
    invoke-static {v3, v5, v7, v7, v11}, Lvj/b;->B(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 241
    .line 242
    .line 243
    move-result-object v3

    .line 244
    goto :goto_7

    .line 245
    :cond_7
    const p0, -0x44fc6308

    .line 246
    .line 247
    .line 248
    invoke-static {p0, v7, v11}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    throw p0

    .line 253
    :cond_8
    const v3, -0x44fc4f3a

    .line 254
    .line 255
    .line 256
    const v5, 0x7f1208d1

    .line 257
    .line 258
    .line 259
    invoke-static {v3, v5, v7, v7, v11}, Lvj/b;->B(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 260
    .line 261
    .line 262
    move-result-object v3

    .line 263
    :goto_7
    iget-object v5, p0, Lfd/d;->b:Lp1/v;

    .line 264
    .line 265
    invoke-virtual {v5}, Lp1/v;->k()I

    .line 266
    .line 267
    .line 268
    move-result v5

    .line 269
    if-ne v5, v2, :cond_9

    .line 270
    .line 271
    move v5, v10

    .line 272
    goto :goto_8

    .line 273
    :cond_9
    move v5, v11

    .line 274
    :goto_8
    invoke-virtual {v7, v2}, Ll2/t;->e(I)Z

    .line 275
    .line 276
    .line 277
    move-result v6

    .line 278
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    move-result-object v8

    .line 282
    if-nez v6, :cond_a

    .line 283
    .line 284
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 285
    .line 286
    if-ne v8, v6, :cond_b

    .line 287
    .line 288
    :cond_a
    new-instance v8, Lba0/h;

    .line 289
    .line 290
    const/16 v6, 0xe

    .line 291
    .line 292
    invoke-direct {v8, p0, v2, v6}, Lba0/h;-><init>(Ljava/lang/Object;II)V

    .line 293
    .line 294
    .line 295
    invoke-virtual {v7, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    :cond_b
    check-cast v8, Lay0/a;

    .line 299
    .line 300
    new-instance v2, Li91/u2;

    .line 301
    .line 302
    invoke-direct {v2, v8, v3, v5}, Li91/u2;-><init>(Lay0/a;Ljava/lang/String;Z)V

    .line 303
    .line 304
    .line 305
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 306
    .line 307
    .line 308
    move v2, v4

    .line 309
    goto :goto_6

    .line 310
    :cond_c
    invoke-static {}, Ljp/k1;->r()V

    .line 311
    .line 312
    .line 313
    throw p2

    .line 314
    :cond_d
    invoke-virtual {v7, v11}, Ll2/t;->q(Z)V

    .line 315
    .line 316
    .line 317
    const/4 v4, 0x0

    .line 318
    const/4 v5, 0x6

    .line 319
    const/4 v1, 0x0

    .line 320
    const/4 v2, 0x0

    .line 321
    move-object v3, v7

    .line 322
    invoke-static/range {v0 .. v5}, Li91/j0;->B(Ljava/util/List;Lx2/s;Ljava/lang/String;Ll2/o;II)V

    .line 323
    .line 324
    .line 325
    goto/16 :goto_5

    .line 326
    .line 327
    :cond_e
    move-object v7, v3

    .line 328
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 329
    .line 330
    .line 331
    :goto_9
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 332
    .line 333
    .line 334
    move-result-object p2

    .line 335
    if-eqz p2, :cond_f

    .line 336
    .line 337
    new-instance v0, Lxk0/w;

    .line 338
    .line 339
    const/16 v1, 0xb

    .line 340
    .line 341
    invoke-direct {v0, p3, v1, p0, p1}, Lxk0/w;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 342
    .line 343
    .line 344
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 345
    .line 346
    :cond_f
    return-void
.end method
