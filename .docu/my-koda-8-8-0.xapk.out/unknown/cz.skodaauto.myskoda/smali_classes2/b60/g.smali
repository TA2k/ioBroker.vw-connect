.class public final Lb60/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:Lay0/k;

.field public final synthetic g:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(ILay0/k;Ljava/util/List;Ljava/util/List;)V
    .locals 0

    .line 1
    iput p1, p0, Lb60/g;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Lb60/g;->e:Ljava/util/List;

    .line 4
    .line 5
    iput-object p2, p0, Lb60/g;->f:Lay0/k;

    .line 6
    .line 7
    iput-object p4, p0, Lb60/g;->g:Ljava/util/List;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lb60/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Landroidx/compose/foundation/lazy/a;

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
    check-cast p3, Ll2/o;

    .line 15
    .line 16
    check-cast p4, Ljava/lang/Number;

    .line 17
    .line 18
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result p4

    .line 22
    and-int/lit8 v0, p4, 0x6

    .line 23
    .line 24
    if-nez v0, :cond_1

    .line 25
    .line 26
    move-object v0, p3

    .line 27
    check-cast v0, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-eqz p1, :cond_0

    .line 34
    .line 35
    const/4 p1, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 p1, 0x2

    .line 38
    :goto_0
    or-int/2addr p1, p4

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    move p1, p4

    .line 41
    :goto_1
    and-int/lit8 p4, p4, 0x30

    .line 42
    .line 43
    if-nez p4, :cond_3

    .line 44
    .line 45
    move-object p4, p3

    .line 46
    check-cast p4, Ll2/t;

    .line 47
    .line 48
    invoke-virtual {p4, p2}, Ll2/t;->e(I)Z

    .line 49
    .line 50
    .line 51
    move-result p4

    .line 52
    if-eqz p4, :cond_2

    .line 53
    .line 54
    const/16 p4, 0x20

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_2
    const/16 p4, 0x10

    .line 58
    .line 59
    :goto_2
    or-int/2addr p1, p4

    .line 60
    :cond_3
    and-int/lit16 p4, p1, 0x93

    .line 61
    .line 62
    const/16 v0, 0x92

    .line 63
    .line 64
    const/4 v1, 0x1

    .line 65
    const/4 v2, 0x0

    .line 66
    if-eq p4, v0, :cond_4

    .line 67
    .line 68
    move p4, v1

    .line 69
    goto :goto_3

    .line 70
    :cond_4
    move p4, v2

    .line 71
    :goto_3
    and-int/2addr p1, v1

    .line 72
    check-cast p3, Ll2/t;

    .line 73
    .line 74
    invoke-virtual {p3, p1, p4}, Ll2/t;->O(IZ)Z

    .line 75
    .line 76
    .line 77
    move-result p1

    .line 78
    if-eqz p1, :cond_9

    .line 79
    .line 80
    iget-object p1, p0, Lb60/g;->e:Ljava/util/List;

    .line 81
    .line 82
    invoke-interface {p1, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    check-cast p1, Lkd/e;

    .line 87
    .line 88
    const p4, 0x4ef7a8bb

    .line 89
    .line 90
    .line 91
    invoke-virtual {p3, p4}, Ll2/t;->Y(I)V

    .line 92
    .line 93
    .line 94
    new-instance p4, Lkd/k;

    .line 95
    .line 96
    invoke-direct {p4, p2}, Lkd/k;-><init>(I)V

    .line 97
    .line 98
    .line 99
    iget-object v0, p0, Lb60/g;->f:Lay0/k;

    .line 100
    .line 101
    invoke-interface {v0, p4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    instance-of p4, p1, Lkd/c;

    .line 105
    .line 106
    if-eqz p4, :cond_6

    .line 107
    .line 108
    const p0, 0x23946f71

    .line 109
    .line 110
    .line 111
    invoke-virtual {p3, p0}, Ll2/t;->Y(I)V

    .line 112
    .line 113
    .line 114
    if-nez p2, :cond_5

    .line 115
    .line 116
    goto :goto_4

    .line 117
    :cond_5
    move v1, v2

    .line 118
    :goto_4
    check-cast p1, Lkd/c;

    .line 119
    .line 120
    invoke-static {v1, p1, p3, v2}, Lyj/f;->f(ZLkd/c;Ll2/o;I)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {p3, v2}, Ll2/t;->q(Z)V

    .line 124
    .line 125
    .line 126
    goto :goto_5

    .line 127
    :cond_6
    instance-of p4, p1, Lkd/d;

    .line 128
    .line 129
    if-eqz p4, :cond_7

    .line 130
    .line 131
    const p4, 0x23947abb

    .line 132
    .line 133
    .line 134
    invoke-virtual {p3, p4}, Ll2/t;->Y(I)V

    .line 135
    .line 136
    .line 137
    check-cast p1, Lkd/d;

    .line 138
    .line 139
    iget-object p0, p0, Lb60/g;->g:Ljava/util/List;

    .line 140
    .line 141
    add-int/2addr p2, v1

    .line 142
    invoke-static {p2, p0}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    instance-of p0, p0, Lkd/c;

    .line 147
    .line 148
    xor-int/2addr p0, v1

    .line 149
    invoke-static {p1, v0, p0, p3, v2}, Lyj/f;->g(Lkd/d;Lay0/k;ZLl2/o;I)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {p3, v2}, Ll2/t;->q(Z)V

    .line 153
    .line 154
    .line 155
    goto :goto_5

    .line 156
    :cond_7
    sget-object p0, Lkd/b;->a:Lkd/b;

    .line 157
    .line 158
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 159
    .line 160
    .line 161
    move-result p0

    .line 162
    if-eqz p0, :cond_8

    .line 163
    .line 164
    const p0, 0x239495c0

    .line 165
    .line 166
    .line 167
    invoke-virtual {p3, p0}, Ll2/t;->Y(I)V

    .line 168
    .line 169
    .line 170
    invoke-static {v2, v1, p3, v2}, Ldk/b;->e(IILl2/o;Z)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {p3, v2}, Ll2/t;->q(Z)V

    .line 174
    .line 175
    .line 176
    :goto_5
    invoke-virtual {p3, v2}, Ll2/t;->q(Z)V

    .line 177
    .line 178
    .line 179
    goto :goto_6

    .line 180
    :cond_8
    const p0, 0x239468a3

    .line 181
    .line 182
    .line 183
    invoke-static {p0, p3, v2}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    throw p0

    .line 188
    :cond_9
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 189
    .line 190
    .line 191
    :goto_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 192
    .line 193
    return-object p0

    .line 194
    :pswitch_0
    check-cast p1, Landroidx/compose/foundation/lazy/a;

    .line 195
    .line 196
    check-cast p2, Ljava/lang/Number;

    .line 197
    .line 198
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 199
    .line 200
    .line 201
    move-result p2

    .line 202
    check-cast p3, Ll2/o;

    .line 203
    .line 204
    check-cast p4, Ljava/lang/Number;

    .line 205
    .line 206
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 207
    .line 208
    .line 209
    move-result p4

    .line 210
    and-int/lit8 v0, p4, 0x6

    .line 211
    .line 212
    if-nez v0, :cond_b

    .line 213
    .line 214
    move-object v0, p3

    .line 215
    check-cast v0, Ll2/t;

    .line 216
    .line 217
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    move-result v0

    .line 221
    if-eqz v0, :cond_a

    .line 222
    .line 223
    const/4 v0, 0x4

    .line 224
    goto :goto_7

    .line 225
    :cond_a
    const/4 v0, 0x2

    .line 226
    :goto_7
    or-int/2addr v0, p4

    .line 227
    goto :goto_8

    .line 228
    :cond_b
    move v0, p4

    .line 229
    :goto_8
    and-int/lit8 p4, p4, 0x30

    .line 230
    .line 231
    if-nez p4, :cond_d

    .line 232
    .line 233
    move-object p4, p3

    .line 234
    check-cast p4, Ll2/t;

    .line 235
    .line 236
    invoke-virtual {p4, p2}, Ll2/t;->e(I)Z

    .line 237
    .line 238
    .line 239
    move-result p4

    .line 240
    if-eqz p4, :cond_c

    .line 241
    .line 242
    const/16 p4, 0x20

    .line 243
    .line 244
    goto :goto_9

    .line 245
    :cond_c
    const/16 p4, 0x10

    .line 246
    .line 247
    :goto_9
    or-int/2addr v0, p4

    .line 248
    :cond_d
    and-int/lit16 p4, v0, 0x93

    .line 249
    .line 250
    const/16 v1, 0x92

    .line 251
    .line 252
    const/4 v2, 0x1

    .line 253
    const/4 v3, 0x0

    .line 254
    if-eq p4, v1, :cond_e

    .line 255
    .line 256
    move p4, v2

    .line 257
    goto :goto_a

    .line 258
    :cond_e
    move p4, v3

    .line 259
    :goto_a
    and-int/2addr v0, v2

    .line 260
    move-object v8, p3

    .line 261
    check-cast v8, Ll2/t;

    .line 262
    .line 263
    invoke-virtual {v8, v0, p4}, Ll2/t;->O(IZ)Z

    .line 264
    .line 265
    .line 266
    move-result p3

    .line 267
    if-eqz p3, :cond_10

    .line 268
    .line 269
    iget-object p3, p0, Lb60/g;->e:Ljava/util/List;

    .line 270
    .line 271
    invoke-interface {p3, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object p3

    .line 275
    move-object v4, p3

    .line 276
    check-cast v4, La60/c;

    .line 277
    .line 278
    const p3, 0x623cb9f8

    .line 279
    .line 280
    .line 281
    invoke-virtual {v8, p3}, Ll2/t;->Y(I)V

    .line 282
    .line 283
    .line 284
    sget-object p3, Lx2/p;->b:Lx2/p;

    .line 285
    .line 286
    invoke-static {p1, p3}, Landroidx/compose/foundation/lazy/a;->a(Landroidx/compose/foundation/lazy/a;Lx2/s;)Lx2/s;

    .line 287
    .line 288
    .line 289
    move-result-object v5

    .line 290
    const/4 v9, 0x0

    .line 291
    const/4 v10, 0x4

    .line 292
    iget-object v6, p0, Lb60/g;->f:Lay0/k;

    .line 293
    .line 294
    const/4 v7, 0x0

    .line 295
    invoke-static/range {v4 .. v10}, Lb60/i;->e(La60/c;Lx2/s;Lay0/k;ZLl2/o;II)V

    .line 296
    .line 297
    .line 298
    iget-object p0, p0, Lb60/g;->g:Ljava/util/List;

    .line 299
    .line 300
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 301
    .line 302
    .line 303
    move-result p0

    .line 304
    if-ge p2, p0, :cond_f

    .line 305
    .line 306
    const p0, 0x623e315b

    .line 307
    .line 308
    .line 309
    invoke-virtual {v8, p0}, Ll2/t;->Y(I)V

    .line 310
    .line 311
    .line 312
    invoke-static {v8, v3}, Lb60/i;->d(Ll2/o;I)V

    .line 313
    .line 314
    .line 315
    :goto_b
    invoke-virtual {v8, v3}, Ll2/t;->q(Z)V

    .line 316
    .line 317
    .line 318
    goto :goto_c

    .line 319
    :cond_f
    const p0, 0x61f744ec

    .line 320
    .line 321
    .line 322
    invoke-virtual {v8, p0}, Ll2/t;->Y(I)V

    .line 323
    .line 324
    .line 325
    goto :goto_b

    .line 326
    :goto_c
    invoke-virtual {v8, v3}, Ll2/t;->q(Z)V

    .line 327
    .line 328
    .line 329
    goto :goto_d

    .line 330
    :cond_10
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 331
    .line 332
    .line 333
    :goto_d
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 334
    .line 335
    return-object p0

    .line 336
    nop

    .line 337
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
