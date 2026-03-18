.class public final synthetic Lv50/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/a;

.field public final synthetic f:Lu50/p;


# direct methods
.method public synthetic constructor <init>(Lay0/a;Lu50/p;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Lv50/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lv50/i;->e:Lay0/a;

    iput-object p2, p0, Lv50/i;->f:Lu50/p;

    return-void
.end method

.method public synthetic constructor <init>(Lu50/p;Lay0/a;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Lv50/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lv50/i;->f:Lu50/p;

    iput-object p2, p0, Lv50/i;->e:Lay0/a;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lv50/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lk1/q;

    .line 7
    .line 8
    check-cast p2, Ll2/o;

    .line 9
    .line 10
    check-cast p3, Ljava/lang/Integer;

    .line 11
    .line 12
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result p3

    .line 16
    const-string v0, "$this$GradientBox"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 p1, p3, 0x11

    .line 22
    .line 23
    const/16 v0, 0x10

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    if-eq p1, v0, :cond_0

    .line 27
    .line 28
    move p1, v1

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 p1, 0x0

    .line 31
    :goto_0
    and-int/2addr p3, v1

    .line 32
    move-object v7, p2

    .line 33
    check-cast v7, Ll2/t;

    .line 34
    .line 35
    invoke-virtual {v7, p3, p1}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-eqz p1, :cond_4

    .line 40
    .line 41
    sget-object p1, Lx2/c;->q:Lx2/h;

    .line 42
    .line 43
    const/high16 p2, 0x3f800000    # 1.0f

    .line 44
    .line 45
    sget-object p3, Lx2/p;->b:Lx2/p;

    .line 46
    .line 47
    invoke-static {p3, p2}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 48
    .line 49
    .line 50
    move-result-object p2

    .line 51
    sget-object v0, Lk1/j;->c:Lk1/e;

    .line 52
    .line 53
    const/16 v2, 0x30

    .line 54
    .line 55
    invoke-static {v0, p1, v7, v2}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    iget-wide v2, v7, Ll2/t;->T:J

    .line 60
    .line 61
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    invoke-virtual {v7}, Ll2/t;->m()Ll2/p1;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    invoke-static {v7, p2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    sget-object v3, Lv3/k;->m1:Lv3/j;

    .line 74
    .line 75
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    sget-object v3, Lv3/j;->b:Lv3/i;

    .line 79
    .line 80
    invoke-virtual {v7}, Ll2/t;->c0()V

    .line 81
    .line 82
    .line 83
    iget-boolean v4, v7, Ll2/t;->S:Z

    .line 84
    .line 85
    if-eqz v4, :cond_1

    .line 86
    .line 87
    invoke-virtual {v7, v3}, Ll2/t;->l(Lay0/a;)V

    .line 88
    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_1
    invoke-virtual {v7}, Ll2/t;->m0()V

    .line 92
    .line 93
    .line 94
    :goto_1
    sget-object v3, Lv3/j;->g:Lv3/h;

    .line 95
    .line 96
    invoke-static {v3, p1, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 97
    .line 98
    .line 99
    sget-object p1, Lv3/j;->f:Lv3/h;

    .line 100
    .line 101
    invoke-static {p1, v2, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 102
    .line 103
    .line 104
    sget-object p1, Lv3/j;->j:Lv3/h;

    .line 105
    .line 106
    iget-boolean v2, v7, Ll2/t;->S:Z

    .line 107
    .line 108
    if-nez v2, :cond_2

    .line 109
    .line 110
    invoke-virtual {v7}, Ll2/t;->L()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object v3

    .line 118
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v2

    .line 122
    if-nez v2, :cond_3

    .line 123
    .line 124
    :cond_2
    invoke-static {v0, v7, v0, p1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 125
    .line 126
    .line 127
    :cond_3
    sget-object p1, Lv3/j;->d:Lv3/h;

    .line 128
    .line 129
    invoke-static {p1, p2, v7}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 130
    .line 131
    .line 132
    sget-object p1, Lj91/a;->a:Ll2/u2;

    .line 133
    .line 134
    invoke-virtual {v7, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p2

    .line 138
    check-cast p2, Lj91/c;

    .line 139
    .line 140
    iget p2, p2, Lj91/c;->e:F

    .line 141
    .line 142
    const v0, 0x7f12074a

    .line 143
    .line 144
    .line 145
    invoke-static {p3, p2, v7, v0, v7}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v6

    .line 149
    const p2, 0x7f0803a7

    .line 150
    .line 151
    .line 152
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 153
    .line 154
    .line 155
    move-result-object v5

    .line 156
    iget-object p2, p0, Lv50/i;->f:Lu50/p;

    .line 157
    .line 158
    iget-boolean v10, p2, Lu50/p;->a:Z

    .line 159
    .line 160
    const/4 v2, 0x0

    .line 161
    const/16 v3, 0x34

    .line 162
    .line 163
    iget-object v4, p0, Lv50/i;->e:Lay0/a;

    .line 164
    .line 165
    const/4 v8, 0x0

    .line 166
    const/4 v9, 0x0

    .line 167
    invoke-static/range {v2 .. v10}, Li91/j0;->W(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V

    .line 168
    .line 169
    .line 170
    invoke-virtual {v7, p1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    check-cast p0, Lj91/c;

    .line 175
    .line 176
    iget p0, p0, Lj91/c;->f:F

    .line 177
    .line 178
    invoke-static {p3, p0, v7, v1}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 179
    .line 180
    .line 181
    goto :goto_2

    .line 182
    :cond_4
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 183
    .line 184
    .line 185
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 186
    .line 187
    return-object p0

    .line 188
    :pswitch_0
    check-cast p1, Lk1/z0;

    .line 189
    .line 190
    check-cast p2, Ll2/o;

    .line 191
    .line 192
    check-cast p3, Ljava/lang/Integer;

    .line 193
    .line 194
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 195
    .line 196
    .line 197
    move-result p3

    .line 198
    const-string v0, "innerPadding"

    .line 199
    .line 200
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    and-int/lit8 v0, p3, 0x6

    .line 204
    .line 205
    if-nez v0, :cond_6

    .line 206
    .line 207
    move-object v0, p2

    .line 208
    check-cast v0, Ll2/t;

    .line 209
    .line 210
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 211
    .line 212
    .line 213
    move-result v0

    .line 214
    if-eqz v0, :cond_5

    .line 215
    .line 216
    const/4 v0, 0x4

    .line 217
    goto :goto_3

    .line 218
    :cond_5
    const/4 v0, 0x2

    .line 219
    :goto_3
    or-int/2addr p3, v0

    .line 220
    :cond_6
    and-int/lit8 v0, p3, 0x13

    .line 221
    .line 222
    const/16 v1, 0x12

    .line 223
    .line 224
    const/4 v2, 0x0

    .line 225
    if-eq v0, v1, :cond_7

    .line 226
    .line 227
    const/4 v0, 0x1

    .line 228
    goto :goto_4

    .line 229
    :cond_7
    move v0, v2

    .line 230
    :goto_4
    and-int/lit8 v1, p3, 0x1

    .line 231
    .line 232
    move-object v6, p2

    .line 233
    check-cast v6, Ll2/t;

    .line 234
    .line 235
    invoke-virtual {v6, v1, v0}, Ll2/t;->O(IZ)Z

    .line 236
    .line 237
    .line 238
    move-result p2

    .line 239
    if-eqz p2, :cond_b

    .line 240
    .line 241
    iget-object p2, p0, Lv50/i;->f:Lu50/p;

    .line 242
    .line 243
    iget-object v0, p2, Lu50/p;->b:Lql0/g;

    .line 244
    .line 245
    if-nez v0, :cond_8

    .line 246
    .line 247
    const p0, 0x5f5dc88b

    .line 248
    .line 249
    .line 250
    invoke-virtual {v6, p0}, Ll2/t;->Y(I)V

    .line 251
    .line 252
    .line 253
    and-int/lit8 p0, p3, 0xe

    .line 254
    .line 255
    invoke-static {p1, v6, p0}, Lv50/a;->e0(Lk1/z0;Ll2/o;I)V

    .line 256
    .line 257
    .line 258
    invoke-virtual {v6, v2}, Ll2/t;->q(Z)V

    .line 259
    .line 260
    .line 261
    goto :goto_5

    .line 262
    :cond_8
    const p1, 0x5f5ed521

    .line 263
    .line 264
    .line 265
    invoke-virtual {v6, p1}, Ll2/t;->Y(I)V

    .line 266
    .line 267
    .line 268
    iget-object v3, p2, Lu50/p;->b:Lql0/g;

    .line 269
    .line 270
    iget-object p0, p0, Lv50/i;->e:Lay0/a;

    .line 271
    .line 272
    invoke-virtual {v6, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 273
    .line 274
    .line 275
    move-result p1

    .line 276
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object p2

    .line 280
    if-nez p1, :cond_9

    .line 281
    .line 282
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 283
    .line 284
    if-ne p2, p1, :cond_a

    .line 285
    .line 286
    :cond_9
    new-instance p2, Lr40/d;

    .line 287
    .line 288
    const/16 p1, 0x1b

    .line 289
    .line 290
    invoke-direct {p2, p0, p1}, Lr40/d;-><init>(Lay0/a;I)V

    .line 291
    .line 292
    .line 293
    invoke-virtual {v6, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 294
    .line 295
    .line 296
    :cond_a
    move-object v4, p2

    .line 297
    check-cast v4, Lay0/k;

    .line 298
    .line 299
    const/4 v7, 0x0

    .line 300
    const/4 v8, 0x4

    .line 301
    const/4 v5, 0x0

    .line 302
    invoke-static/range {v3 .. v8}, Lyg0/a;->a(Lql0/g;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 303
    .line 304
    .line 305
    invoke-virtual {v6, v2}, Ll2/t;->q(Z)V

    .line 306
    .line 307
    .line 308
    goto :goto_5

    .line 309
    :cond_b
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 310
    .line 311
    .line 312
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 313
    .line 314
    return-object p0

    .line 315
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
