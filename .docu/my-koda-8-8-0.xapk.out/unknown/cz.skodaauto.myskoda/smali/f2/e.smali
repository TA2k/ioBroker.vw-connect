.class public final Lf2/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lk1/z0;

.field public final synthetic f:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Lk1/z0;Lt2/b;I)V
    .locals 0

    .line 1
    iput p3, p0, Lf2/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lf2/e;->e:Lk1/z0;

    .line 4
    .line 5
    iput-object p2, p0, Lf2/e;->f:Lt2/b;

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
    .locals 6

    .line 1
    iget v0, p0, Lf2/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    and-int/lit8 v0, p2, 0x3

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    const/4 v2, 0x1

    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    move v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 v0, 0x0

    .line 23
    :goto_0
    and-int/2addr p2, v2

    .line 24
    check-cast p1, Ll2/t;

    .line 25
    .line 26
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    if-eqz p2, :cond_4

    .line 31
    .line 32
    sget p2, Lh2/o0;->b:F

    .line 33
    .line 34
    sget v0, Lh2/o0;->c:F

    .line 35
    .line 36
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 37
    .line 38
    invoke-static {v1, p2, v0}, Landroidx/compose/foundation/layout/d;->a(Lx2/s;FF)Lx2/s;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    iget-object v0, p0, Lf2/e;->e:Lk1/z0;

    .line 43
    .line 44
    invoke-static {p2, v0}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    sget-object v0, Lk1/j;->e:Lk1/f;

    .line 49
    .line 50
    sget-object v1, Lx2/c;->n:Lx2/i;

    .line 51
    .line 52
    const/16 v3, 0x36

    .line 53
    .line 54
    invoke-static {v0, v1, p1, v3}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    iget-wide v3, p1, Ll2/t;->T:J

    .line 59
    .line 60
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 73
    .line 74
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 78
    .line 79
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 80
    .line 81
    .line 82
    iget-boolean v5, p1, Ll2/t;->S:Z

    .line 83
    .line 84
    if-eqz v5, :cond_1

    .line 85
    .line 86
    invoke-virtual {p1, v4}, Ll2/t;->l(Lay0/a;)V

    .line 87
    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_1
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 91
    .line 92
    .line 93
    :goto_1
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 94
    .line 95
    invoke-static {v4, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 96
    .line 97
    .line 98
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 99
    .line 100
    invoke-static {v0, v3, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 101
    .line 102
    .line 103
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 104
    .line 105
    iget-boolean v3, p1, Ll2/t;->S:Z

    .line 106
    .line 107
    if-nez v3, :cond_2

    .line 108
    .line 109
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 114
    .line 115
    .line 116
    move-result-object v4

    .line 117
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    if-nez v3, :cond_3

    .line 122
    .line 123
    :cond_2
    invoke-static {v1, p1, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 124
    .line 125
    .line 126
    :cond_3
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 127
    .line 128
    invoke-static {v0, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 129
    .line 130
    .line 131
    const/4 p2, 0x6

    .line 132
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 133
    .line 134
    .line 135
    move-result-object p2

    .line 136
    iget-object p0, p0, Lf2/e;->f:Lt2/b;

    .line 137
    .line 138
    sget-object v0, Lk1/i1;->a:Lk1/i1;

    .line 139
    .line 140
    invoke-virtual {p0, v0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 144
    .line 145
    .line 146
    goto :goto_2

    .line 147
    :cond_4
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 148
    .line 149
    .line 150
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 151
    .line 152
    return-object p0

    .line 153
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 154
    .line 155
    check-cast p2, Ljava/lang/Number;

    .line 156
    .line 157
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 158
    .line 159
    .line 160
    move-result p2

    .line 161
    and-int/lit8 v0, p2, 0x3

    .line 162
    .line 163
    const/4 v1, 0x2

    .line 164
    const/4 v2, 0x1

    .line 165
    if-eq v0, v1, :cond_5

    .line 166
    .line 167
    move v0, v2

    .line 168
    goto :goto_3

    .line 169
    :cond_5
    const/4 v0, 0x0

    .line 170
    :goto_3
    and-int/2addr p2, v2

    .line 171
    check-cast p1, Ll2/t;

    .line 172
    .line 173
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 174
    .line 175
    .line 176
    move-result p2

    .line 177
    if-eqz p2, :cond_6

    .line 178
    .line 179
    sget-object p2, Lf2/x0;->b:Ll2/u2;

    .line 180
    .line 181
    invoke-virtual {p1, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object p2

    .line 185
    check-cast p2, Lf2/w0;

    .line 186
    .line 187
    iget-object p2, p2, Lf2/w0;->k:Lg4/p0;

    .line 188
    .line 189
    new-instance v0, Lf2/e;

    .line 190
    .line 191
    iget-object v1, p0, Lf2/e;->f:Lt2/b;

    .line 192
    .line 193
    const/4 v2, 0x0

    .line 194
    iget-object p0, p0, Lf2/e;->e:Lk1/z0;

    .line 195
    .line 196
    invoke-direct {v0, p0, v1, v2}, Lf2/e;-><init>(Lk1/z0;Lt2/b;I)V

    .line 197
    .line 198
    .line 199
    const p0, 0x9ddf013

    .line 200
    .line 201
    .line 202
    invoke-static {p0, p1, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    const/16 v0, 0x30

    .line 207
    .line 208
    invoke-static {p2, p0, p1, v0}, Lf2/v0;->a(Lg4/p0;Lt2/b;Ll2/o;I)V

    .line 209
    .line 210
    .line 211
    goto :goto_4

    .line 212
    :cond_6
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 213
    .line 214
    .line 215
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 216
    .line 217
    return-object p0

    .line 218
    :pswitch_1
    check-cast p1, Ll2/o;

    .line 219
    .line 220
    check-cast p2, Ljava/lang/Number;

    .line 221
    .line 222
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 223
    .line 224
    .line 225
    move-result p2

    .line 226
    and-int/lit8 v0, p2, 0x3

    .line 227
    .line 228
    const/4 v1, 0x2

    .line 229
    const/4 v2, 0x1

    .line 230
    if-eq v0, v1, :cond_7

    .line 231
    .line 232
    move v0, v2

    .line 233
    goto :goto_5

    .line 234
    :cond_7
    const/4 v0, 0x0

    .line 235
    :goto_5
    and-int/2addr p2, v2

    .line 236
    check-cast p1, Ll2/t;

    .line 237
    .line 238
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 239
    .line 240
    .line 241
    move-result p2

    .line 242
    if-eqz p2, :cond_b

    .line 243
    .line 244
    sget p2, Lf2/c;->b:F

    .line 245
    .line 246
    sget v0, Lf2/c;->c:F

    .line 247
    .line 248
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 249
    .line 250
    invoke-static {v1, p2, v0}, Landroidx/compose/foundation/layout/d;->a(Lx2/s;FF)Lx2/s;

    .line 251
    .line 252
    .line 253
    move-result-object p2

    .line 254
    iget-object v0, p0, Lf2/e;->e:Lk1/z0;

    .line 255
    .line 256
    invoke-static {p2, v0}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 257
    .line 258
    .line 259
    move-result-object p2

    .line 260
    sget-object v0, Lk1/j;->e:Lk1/f;

    .line 261
    .line 262
    sget-object v1, Lx2/c;->n:Lx2/i;

    .line 263
    .line 264
    const/16 v3, 0x36

    .line 265
    .line 266
    invoke-static {v0, v1, p1, v3}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 267
    .line 268
    .line 269
    move-result-object v0

    .line 270
    iget-wide v3, p1, Ll2/t;->T:J

    .line 271
    .line 272
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 273
    .line 274
    .line 275
    move-result v1

    .line 276
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 277
    .line 278
    .line 279
    move-result-object v3

    .line 280
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 281
    .line 282
    .line 283
    move-result-object p2

    .line 284
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 285
    .line 286
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 287
    .line 288
    .line 289
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 290
    .line 291
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 292
    .line 293
    .line 294
    iget-boolean v5, p1, Ll2/t;->S:Z

    .line 295
    .line 296
    if-eqz v5, :cond_8

    .line 297
    .line 298
    invoke-virtual {p1, v4}, Ll2/t;->l(Lay0/a;)V

    .line 299
    .line 300
    .line 301
    goto :goto_6

    .line 302
    :cond_8
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 303
    .line 304
    .line 305
    :goto_6
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 306
    .line 307
    invoke-static {v4, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 308
    .line 309
    .line 310
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 311
    .line 312
    invoke-static {v0, v3, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 313
    .line 314
    .line 315
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 316
    .line 317
    iget-boolean v3, p1, Ll2/t;->S:Z

    .line 318
    .line 319
    if-nez v3, :cond_9

    .line 320
    .line 321
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object v3

    .line 325
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 326
    .line 327
    .line 328
    move-result-object v4

    .line 329
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 330
    .line 331
    .line 332
    move-result v3

    .line 333
    if-nez v3, :cond_a

    .line 334
    .line 335
    :cond_9
    invoke-static {v1, p1, v1, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 336
    .line 337
    .line 338
    :cond_a
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 339
    .line 340
    invoke-static {v0, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 341
    .line 342
    .line 343
    const/4 p2, 0x6

    .line 344
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 345
    .line 346
    .line 347
    move-result-object p2

    .line 348
    iget-object p0, p0, Lf2/e;->f:Lt2/b;

    .line 349
    .line 350
    sget-object v0, Lk1/i1;->a:Lk1/i1;

    .line 351
    .line 352
    invoke-virtual {p0, v0, p1, p2}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 356
    .line 357
    .line 358
    goto :goto_7

    .line 359
    :cond_b
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 360
    .line 361
    .line 362
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 363
    .line 364
    return-object p0

    .line 365
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
