.class public final Le2/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILay0/k;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Le2/e0;->d:I

    iput-object p2, p0, Le2/e0;->e:Lay0/k;

    iput-object p3, p0, Le2/e0;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lay0/a;Lay0/k;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Le2/e0;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Le2/e0;->f:Ljava/lang/Object;

    iput-object p2, p0, Le2/e0;->e:Lay0/k;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Le2/e0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lx2/s;

    .line 7
    .line 8
    check-cast p2, Ll2/o;

    .line 9
    .line 10
    check-cast p3, Ljava/lang/Number;

    .line 11
    .line 12
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 13
    .line 14
    .line 15
    iget-object p1, p0, Le2/e0;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p1, Li1/l;

    .line 18
    .line 19
    check-cast p2, Ll2/t;

    .line 20
    .line 21
    const p3, -0x620472b

    .line 22
    .line 23
    .line 24
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p3

    .line 31
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 32
    .line 33
    if-ne p3, v0, :cond_0

    .line 34
    .line 35
    invoke-static {p2}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 36
    .line 37
    .line 38
    move-result-object p3

    .line 39
    invoke-virtual {p2, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    :cond_0
    check-cast p3, Lvy0/b0;

    .line 43
    .line 44
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    if-ne v1, v0, :cond_1

    .line 49
    .line 50
    const/4 v1, 0x0

    .line 51
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-virtual {p2, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    :cond_1
    check-cast v1, Ll2/b1;

    .line 59
    .line 60
    iget-object p0, p0, Le2/e0;->e:Lay0/k;

    .line 61
    .line 62
    invoke-static {p0, p2}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    if-nez v2, :cond_2

    .line 75
    .line 76
    if-ne v3, v0, :cond_3

    .line 77
    .line 78
    :cond_2
    new-instance v3, Lod0/n;

    .line 79
    .line 80
    const/16 v2, 0x17

    .line 81
    .line 82
    invoke-direct {v3, v2, v1, p1}, Lod0/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {p2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :cond_3
    check-cast v3, Lay0/k;

    .line 89
    .line 90
    invoke-static {p1, v3, p2}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {p2, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v2

    .line 97
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v3

    .line 101
    or-int/2addr v2, v3

    .line 102
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v3

    .line 106
    or-int/2addr v2, v3

    .line 107
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v3

    .line 111
    if-nez v2, :cond_4

    .line 112
    .line 113
    if-ne v3, v0, :cond_5

    .line 114
    .line 115
    :cond_4
    new-instance v3, Lt1/d1;

    .line 116
    .line 117
    invoke-direct {v3, p3, v1, p1, p0}, Lt1/d1;-><init>(Lvy0/b0;Ll2/b1;Li1/l;Ll2/b1;)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p2, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    :cond_5
    check-cast v3, Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    .line 124
    .line 125
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 126
    .line 127
    invoke-static {p0, p1, v3}, Lp3/f0;->b(Lx2/s;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lx2/s;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    const/4 p1, 0x0

    .line 132
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 133
    .line 134
    .line 135
    return-object p0

    .line 136
    :pswitch_0
    check-cast p1, Lk1/t;

    .line 137
    .line 138
    check-cast p2, Ll2/o;

    .line 139
    .line 140
    check-cast p3, Ljava/lang/Number;

    .line 141
    .line 142
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 143
    .line 144
    .line 145
    move-result p1

    .line 146
    and-int/lit8 p3, p1, 0x11

    .line 147
    .line 148
    const/16 v0, 0x10

    .line 149
    .line 150
    const/4 v1, 0x0

    .line 151
    const/4 v2, 0x1

    .line 152
    if-eq p3, v0, :cond_6

    .line 153
    .line 154
    move p3, v2

    .line 155
    goto :goto_0

    .line 156
    :cond_6
    move p3, v1

    .line 157
    :goto_0
    and-int/2addr p1, v2

    .line 158
    check-cast p2, Ll2/t;

    .line 159
    .line 160
    invoke-virtual {p2, p1, p3}, Ll2/t;->O(IZ)Z

    .line 161
    .line 162
    .line 163
    move-result p1

    .line 164
    if-eqz p1, :cond_8

    .line 165
    .line 166
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    sget-object p3, Ll2/n;->a:Ll2/x0;

    .line 171
    .line 172
    if-ne p1, p3, :cond_7

    .line 173
    .line 174
    new-instance p1, Lf1/e;

    .line 175
    .line 176
    invoke-direct {p1}, Lf1/e;-><init>()V

    .line 177
    .line 178
    .line 179
    invoke-virtual {p2, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 180
    .line 181
    .line 182
    :cond_7
    check-cast p1, Lf1/e;

    .line 183
    .line 184
    iget-object p3, p0, Le2/e0;->f:Ljava/lang/Object;

    .line 185
    .line 186
    check-cast p3, Lf1/c;

    .line 187
    .line 188
    iget-object v0, p1, Lf1/e;->a:Lv2/o;

    .line 189
    .line 190
    invoke-virtual {v0}, Lv2/o;->clear()V

    .line 191
    .line 192
    .line 193
    iget-object p0, p0, Le2/e0;->e:Lay0/k;

    .line 194
    .line 195
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    invoke-virtual {p1, p3, p2, v1}, Lf1/e;->a(Lf1/c;Ll2/o;I)V

    .line 199
    .line 200
    .line 201
    goto :goto_1

    .line 202
    :cond_8
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 203
    .line 204
    .line 205
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 206
    .line 207
    return-object p0

    .line 208
    :pswitch_1
    check-cast p1, Lx2/s;

    .line 209
    .line 210
    check-cast p2, Ll2/o;

    .line 211
    .line 212
    check-cast p3, Ljava/lang/Number;

    .line 213
    .line 214
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 215
    .line 216
    .line 217
    check-cast p2, Ll2/t;

    .line 218
    .line 219
    const p1, 0x2d4acc1b

    .line 220
    .line 221
    .line 222
    invoke-virtual {p2, p1}, Ll2/t;->Y(I)V

    .line 223
    .line 224
    .line 225
    iget-object p1, p0, Le2/e0;->f:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast p1, Lay0/a;

    .line 228
    .line 229
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object p3

    .line 233
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 234
    .line 235
    if-ne p3, v0, :cond_9

    .line 236
    .line 237
    invoke-static {p1}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 238
    .line 239
    .line 240
    move-result-object p3

    .line 241
    invoke-virtual {p2, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    :cond_9
    check-cast p3, Ll2/t2;

    .line 245
    .line 246
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object p1

    .line 250
    if-ne p1, v0, :cond_a

    .line 251
    .line 252
    new-instance p1, Lc1/c;

    .line 253
    .line 254
    invoke-interface {p3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v1

    .line 258
    check-cast v1, Ld3/b;

    .line 259
    .line 260
    iget-wide v1, v1, Ld3/b;->a:J

    .line 261
    .line 262
    new-instance v3, Ld3/b;

    .line 263
    .line 264
    invoke-direct {v3, v1, v2}, Ld3/b;-><init>(J)V

    .line 265
    .line 266
    .line 267
    sget-object v1, Le2/g0;->b:Lc1/b2;

    .line 268
    .line 269
    sget-wide v4, Le2/g0;->c:J

    .line 270
    .line 271
    new-instance v2, Ld3/b;

    .line 272
    .line 273
    invoke-direct {v2, v4, v5}, Ld3/b;-><init>(J)V

    .line 274
    .line 275
    .line 276
    const/16 v4, 0x8

    .line 277
    .line 278
    invoke-direct {p1, v3, v1, v2, v4}, Lc1/c;-><init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;I)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {p2, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 282
    .line 283
    .line 284
    :cond_a
    check-cast p1, Lc1/c;

    .line 285
    .line 286
    invoke-virtual {p2, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 287
    .line 288
    .line 289
    move-result v1

    .line 290
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    move-result-object v2

    .line 294
    if-nez v1, :cond_b

    .line 295
    .line 296
    if-ne v2, v0, :cond_c

    .line 297
    .line 298
    :cond_b
    new-instance v2, Le1/e;

    .line 299
    .line 300
    const/4 v1, 0x0

    .line 301
    const/4 v3, 0x2

    .line 302
    invoke-direct {v2, v3, p3, p1, v1}, Le1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 303
    .line 304
    .line 305
    invoke-virtual {p2, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 306
    .line 307
    .line 308
    :cond_c
    check-cast v2, Lay0/n;

    .line 309
    .line 310
    sget-object p3, Llx0/b0;->a:Llx0/b0;

    .line 311
    .line 312
    invoke-static {v2, p3, p2}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 313
    .line 314
    .line 315
    iget-object p1, p1, Lc1/c;->c:Lc1/k;

    .line 316
    .line 317
    invoke-virtual {p2, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 318
    .line 319
    .line 320
    move-result p3

    .line 321
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object v1

    .line 325
    if-nez p3, :cond_d

    .line 326
    .line 327
    if-ne v1, v0, :cond_e

    .line 328
    .line 329
    :cond_d
    new-instance v1, Laa/a0;

    .line 330
    .line 331
    const/4 p3, 0x1

    .line 332
    invoke-direct {v1, p1, p3}, Laa/a0;-><init>(Ll2/t2;I)V

    .line 333
    .line 334
    .line 335
    invoke-virtual {p2, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 336
    .line 337
    .line 338
    :cond_e
    check-cast v1, Lay0/a;

    .line 339
    .line 340
    iget-object p0, p0, Le2/e0;->e:Lay0/k;

    .line 341
    .line 342
    invoke-interface {p0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 343
    .line 344
    .line 345
    move-result-object p0

    .line 346
    check-cast p0, Lx2/s;

    .line 347
    .line 348
    const/4 p1, 0x0

    .line 349
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 350
    .line 351
    .line 352
    return-object p0

    .line 353
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
