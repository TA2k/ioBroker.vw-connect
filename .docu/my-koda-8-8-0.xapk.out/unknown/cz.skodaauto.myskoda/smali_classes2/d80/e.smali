.class public final synthetic Ld80/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc80/p;


# direct methods
.method public synthetic constructor <init>(Lc80/p;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Ld80/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld80/e;->e:Lc80/p;

    return-void
.end method

.method public synthetic constructor <init>(Lc80/p;I)V
    .locals 0

    .line 2
    const/4 p2, 0x1

    iput p2, p0, Ld80/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ld80/e;->e:Lc80/p;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Ld80/e;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    iget-object p0, p0, Ld80/e;->e:Lc80/p;

    .line 7
    .line 8
    check-cast p1, Ll2/o;

    .line 9
    .line 10
    check-cast p2, Ljava/lang/Integer;

    .line 11
    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    invoke-static {p0, p1, p2}, Ld80/b;->q(Lc80/p;Ll2/o;I)V

    .line 23
    .line 24
    .line 25
    return-object v1

    .line 26
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    and-int/lit8 v0, p2, 0x3

    .line 31
    .line 32
    const/4 v3, 0x2

    .line 33
    const/4 v4, 0x0

    .line 34
    if-eq v0, v3, :cond_0

    .line 35
    .line 36
    move v0, v2

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    move v0, v4

    .line 39
    :goto_0
    and-int/2addr p2, v2

    .line 40
    check-cast p1, Ll2/t;

    .line 41
    .line 42
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 43
    .line 44
    .line 45
    move-result p2

    .line 46
    if-eqz p2, :cond_d

    .line 47
    .line 48
    sget-object p2, Lk1/r1;->v:Ljava/util/WeakHashMap;

    .line 49
    .line 50
    invoke-static {p1}, Lk1/c;->e(Ll2/o;)Lk1/r1;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    iget-object p2, p2, Lk1/r1;->g:Lk1/b;

    .line 55
    .line 56
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 57
    .line 58
    invoke-static {v0, p2}, Lk1/d;->r(Lx2/s;Lk1/q1;)Lx2/s;

    .line 59
    .line 60
    .line 61
    move-result-object p2

    .line 62
    sget-object v0, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 63
    .line 64
    invoke-interface {p2, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    sget-object v0, Lx2/c;->d:Lx2/j;

    .line 69
    .line 70
    invoke-static {v0, v4}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    iget-wide v5, p1, Ll2/t;->T:J

    .line 75
    .line 76
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 81
    .line 82
    .line 83
    move-result-object v5

    .line 84
    invoke-static {p1, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 85
    .line 86
    .line 87
    move-result-object p2

    .line 88
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 89
    .line 90
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 91
    .line 92
    .line 93
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 94
    .line 95
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 96
    .line 97
    .line 98
    iget-boolean v7, p1, Ll2/t;->S:Z

    .line 99
    .line 100
    if-eqz v7, :cond_1

    .line 101
    .line 102
    invoke-virtual {p1, v6}, Ll2/t;->l(Lay0/a;)V

    .line 103
    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_1
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 107
    .line 108
    .line 109
    :goto_1
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 110
    .line 111
    invoke-static {v6, v0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 112
    .line 113
    .line 114
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 115
    .line 116
    invoke-static {v0, v5, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 117
    .line 118
    .line 119
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 120
    .line 121
    iget-boolean v5, p1, Ll2/t;->S:Z

    .line 122
    .line 123
    if-nez v5, :cond_2

    .line 124
    .line 125
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v5

    .line 129
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 130
    .line 131
    .line 132
    move-result-object v6

    .line 133
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v5

    .line 137
    if-nez v5, :cond_3

    .line 138
    .line 139
    :cond_2
    invoke-static {v3, p1, v3, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 140
    .line 141
    .line 142
    :cond_3
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 143
    .line 144
    invoke-static {v0, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 145
    .line 146
    .line 147
    iget-object p0, p0, Lc80/p;->a:Lyq0/m;

    .line 148
    .line 149
    sget-object p2, Lyq0/f;->a:Lyq0/f;

    .line 150
    .line 151
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result p2

    .line 155
    if-eqz p2, :cond_4

    .line 156
    .line 157
    const p0, -0x1f2ab098

    .line 158
    .line 159
    .line 160
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 161
    .line 162
    .line 163
    invoke-static {p1, v4}, Ld80/b;->a(Ll2/o;I)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 167
    .line 168
    .line 169
    goto/16 :goto_2

    .line 170
    .line 171
    :cond_4
    sget-object p2, Lyq0/h;->a:Lyq0/h;

    .line 172
    .line 173
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 174
    .line 175
    .line 176
    move-result p2

    .line 177
    const/4 v0, 0x0

    .line 178
    if-eqz p2, :cond_5

    .line 179
    .line 180
    const p0, -0x1f2aa85f

    .line 181
    .line 182
    .line 183
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 184
    .line 185
    .line 186
    invoke-static {v0, p1, v4}, Ld80/b;->h(Lx2/s;Ll2/o;I)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 190
    .line 191
    .line 192
    goto/16 :goto_2

    .line 193
    .line 194
    :cond_5
    sget-object p2, Lyq0/o;->a:Lyq0/o;

    .line 195
    .line 196
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 197
    .line 198
    .line 199
    move-result p2

    .line 200
    if-eqz p2, :cond_6

    .line 201
    .line 202
    const p0, -0x1f2aa07b

    .line 203
    .line 204
    .line 205
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 206
    .line 207
    .line 208
    invoke-static {v0, p1, v4}, Ld80/b;->v(Lx2/s;Ll2/o;I)V

    .line 209
    .line 210
    .line 211
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 212
    .line 213
    .line 214
    goto/16 :goto_2

    .line 215
    .line 216
    :cond_6
    sget-object p2, Lyq0/q;->a:Lyq0/q;

    .line 217
    .line 218
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 219
    .line 220
    .line 221
    move-result p2

    .line 222
    if-eqz p2, :cond_7

    .line 223
    .line 224
    const p0, -0x1f2a9776

    .line 225
    .line 226
    .line 227
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 228
    .line 229
    .line 230
    invoke-static {v0, p1, v4}, Ld80/b;->C(Lx2/s;Ll2/o;I)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 234
    .line 235
    .line 236
    goto :goto_2

    .line 237
    :cond_7
    sget-object p2, Lyq0/x;->a:Lyq0/x;

    .line 238
    .line 239
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 240
    .line 241
    .line 242
    move-result p2

    .line 243
    if-eqz p2, :cond_8

    .line 244
    .line 245
    const p0, -0x1f2a8e7b

    .line 246
    .line 247
    .line 248
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 249
    .line 250
    .line 251
    invoke-static {v0, p1, v4}, Ld80/b;->G(Lx2/s;Ll2/o;I)V

    .line 252
    .line 253
    .line 254
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 255
    .line 256
    .line 257
    goto :goto_2

    .line 258
    :cond_8
    sget-object p2, Lyq0/r;->a:Lyq0/r;

    .line 259
    .line 260
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    move-result p2

    .line 264
    if-eqz p2, :cond_9

    .line 265
    .line 266
    const p0, -0x1f2a857a

    .line 267
    .line 268
    .line 269
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 270
    .line 271
    .line 272
    invoke-static {p1, v4}, Lnc0/e;->i(Ll2/o;I)V

    .line 273
    .line 274
    .line 275
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 276
    .line 277
    .line 278
    goto :goto_2

    .line 279
    :cond_9
    sget-object p2, Lyq0/s;->a:Lyq0/s;

    .line 280
    .line 281
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    move-result p2

    .line 285
    if-eqz p2, :cond_a

    .line 286
    .line 287
    const p0, -0x1f2a7c39

    .line 288
    .line 289
    .line 290
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 291
    .line 292
    .line 293
    invoke-static {p1, v4}, Ld80/b;->m(Ll2/o;I)V

    .line 294
    .line 295
    .line 296
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 297
    .line 298
    .line 299
    goto :goto_2

    .line 300
    :cond_a
    sget-object p2, Lyq0/p;->a:Lyq0/p;

    .line 301
    .line 302
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 303
    .line 304
    .line 305
    move-result p2

    .line 306
    if-eqz p2, :cond_b

    .line 307
    .line 308
    const p0, -0x1f2a7317

    .line 309
    .line 310
    .line 311
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 312
    .line 313
    .line 314
    invoke-static {p1, v4}, Ld80/b;->z(Ll2/o;I)V

    .line 315
    .line 316
    .line 317
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 318
    .line 319
    .line 320
    goto :goto_2

    .line 321
    :cond_b
    if-nez p0, :cond_c

    .line 322
    .line 323
    const p0, -0x1f2a6c51

    .line 324
    .line 325
    .line 326
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 327
    .line 328
    .line 329
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 330
    .line 331
    .line 332
    :goto_2
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 333
    .line 334
    .line 335
    goto :goto_3

    .line 336
    :cond_c
    const p0, -0x1f2ab6bc

    .line 337
    .line 338
    .line 339
    invoke-static {p0, p1, v4}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 340
    .line 341
    .line 342
    move-result-object p0

    .line 343
    throw p0

    .line 344
    :cond_d
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 345
    .line 346
    .line 347
    :goto_3
    return-object v1

    .line 348
    nop

    .line 349
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
