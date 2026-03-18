.class public final Lh2/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lay0/n;

.field public final synthetic e:Lay0/n;

.field public final synthetic f:J

.field public final synthetic g:J

.field public final synthetic h:J

.field public final synthetic i:Lt2/b;


# direct methods
.method public constructor <init>(Lay0/n;Lay0/n;JJJJLt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/f;->d:Lay0/n;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/f;->e:Lay0/n;

    .line 7
    .line 8
    iput-wide p5, p0, Lh2/f;->f:J

    .line 9
    .line 10
    iput-wide p7, p0, Lh2/f;->g:J

    .line 11
    .line 12
    iput-wide p9, p0, Lh2/f;->h:J

    .line 13
    .line 14
    iput-object p11, p0, Lh2/f;->i:Lt2/b;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    check-cast p1, Ll2/o;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    and-int/lit8 v0, p2, 0x3

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    const/4 v2, 0x1

    .line 13
    const/4 v3, 0x0

    .line 14
    if-eq v0, v1, :cond_0

    .line 15
    .line 16
    move v0, v2

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v0, v3

    .line 19
    :goto_0
    and-int/2addr p2, v2

    .line 20
    move-object v8, p1

    .line 21
    check-cast v8, Ll2/t;

    .line 22
    .line 23
    invoke-virtual {v8, p2, v0}, Ll2/t;->O(IZ)Z

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    if-eqz p1, :cond_9

    .line 28
    .line 29
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 30
    .line 31
    sget-object p2, Lh2/j;->e:Lk1/a1;

    .line 32
    .line 33
    invoke-static {p1, p2}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    sget-object p2, Lk1/j;->c:Lk1/e;

    .line 38
    .line 39
    sget-object v0, Lx2/c;->p:Lx2/h;

    .line 40
    .line 41
    invoke-static {p2, v0, v8, v3}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    iget-wide v0, v8, Ll2/t;->T:J

    .line 46
    .line 47
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    invoke-virtual {v8}, Ll2/t;->m()Ll2/p1;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-static {v8, p1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 60
    .line 61
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 62
    .line 63
    .line 64
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 65
    .line 66
    invoke-virtual {v8}, Ll2/t;->c0()V

    .line 67
    .line 68
    .line 69
    iget-boolean v4, v8, Ll2/t;->S:Z

    .line 70
    .line 71
    if-eqz v4, :cond_1

    .line 72
    .line 73
    invoke-virtual {v8, v10}, Ll2/t;->l(Lay0/a;)V

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_1
    invoke-virtual {v8}, Ll2/t;->m0()V

    .line 78
    .line 79
    .line 80
    :goto_1
    sget-object v11, Lv3/j;->g:Lv3/h;

    .line 81
    .line 82
    invoke-static {v11, p2, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 83
    .line 84
    .line 85
    sget-object p2, Lv3/j;->f:Lv3/h;

    .line 86
    .line 87
    invoke-static {p2, v1, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 88
    .line 89
    .line 90
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 91
    .line 92
    iget-boolean v4, v8, Ll2/t;->S:Z

    .line 93
    .line 94
    if-nez v4, :cond_2

    .line 95
    .line 96
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v4

    .line 100
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 101
    .line 102
    .line 103
    move-result-object v5

    .line 104
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v4

    .line 108
    if-nez v4, :cond_3

    .line 109
    .line 110
    :cond_2
    invoke-static {v0, v8, v0, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 111
    .line 112
    .line 113
    :cond_3
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 114
    .line 115
    invoke-static {v0, p1, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 116
    .line 117
    .line 118
    const p1, 0x14a0f326

    .line 119
    .line 120
    .line 121
    invoke-virtual {v8, p1}, Ll2/t;->Y(I)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v8, v3}, Ll2/t;->q(Z)V

    .line 125
    .line 126
    .line 127
    iget-object p1, p0, Lh2/f;->d:Lay0/n;

    .line 128
    .line 129
    if-nez p1, :cond_4

    .line 130
    .line 131
    const p1, 0x14a59771

    .line 132
    .line 133
    .line 134
    invoke-virtual {v8, p1}, Ll2/t;->Y(I)V

    .line 135
    .line 136
    .line 137
    :goto_2
    invoke-virtual {v8, v3}, Ll2/t;->q(Z)V

    .line 138
    .line 139
    .line 140
    goto :goto_3

    .line 141
    :cond_4
    const v4, 0x14a59772

    .line 142
    .line 143
    .line 144
    invoke-virtual {v8, v4}, Ll2/t;->Y(I)V

    .line 145
    .line 146
    .line 147
    sget-object v4, Lk2/n;->f:Lk2/p0;

    .line 148
    .line 149
    invoke-static {v4, v8}, Lh2/ec;->a(Lk2/p0;Ll2/o;)Lg4/p0;

    .line 150
    .line 151
    .line 152
    move-result-object v6

    .line 153
    new-instance v4, Lh2/e;

    .line 154
    .line 155
    const/4 v5, 0x0

    .line 156
    invoke-direct {v4, v5, p1}, Lh2/e;-><init>(ILay0/n;)V

    .line 157
    .line 158
    .line 159
    const p1, 0x43fb671

    .line 160
    .line 161
    .line 162
    invoke-static {p1, v8, v4}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 163
    .line 164
    .line 165
    move-result-object v7

    .line 166
    const/16 v9, 0x180

    .line 167
    .line 168
    iget-wide v4, p0, Lh2/f;->f:J

    .line 169
    .line 170
    invoke-static/range {v4 .. v9}, Li2/a1;->d(JLg4/p0;Lay0/n;Ll2/o;I)V

    .line 171
    .line 172
    .line 173
    goto :goto_2

    .line 174
    :goto_3
    iget-object p1, p0, Lh2/f;->e:Lay0/n;

    .line 175
    .line 176
    if-nez p1, :cond_5

    .line 177
    .line 178
    const p1, 0x14b17479

    .line 179
    .line 180
    .line 181
    invoke-virtual {v8, p1}, Ll2/t;->Y(I)V

    .line 182
    .line 183
    .line 184
    :goto_4
    invoke-virtual {v8, v3}, Ll2/t;->q(Z)V

    .line 185
    .line 186
    .line 187
    goto :goto_5

    .line 188
    :cond_5
    const v4, 0x14b1747a

    .line 189
    .line 190
    .line 191
    invoke-virtual {v8, v4}, Ll2/t;->Y(I)V

    .line 192
    .line 193
    .line 194
    sget-object v4, Lk2/n;->h:Lk2/p0;

    .line 195
    .line 196
    invoke-static {v4, v8}, Lh2/ec;->a(Lk2/p0;Ll2/o;)Lg4/p0;

    .line 197
    .line 198
    .line 199
    move-result-object v6

    .line 200
    new-instance v4, Lh2/e;

    .line 201
    .line 202
    const/4 v5, 0x1

    .line 203
    invoke-direct {v4, v5, p1}, Lh2/e;-><init>(ILay0/n;)V

    .line 204
    .line 205
    .line 206
    const p1, 0x2a0e58f2

    .line 207
    .line 208
    .line 209
    invoke-static {p1, v8, v4}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 210
    .line 211
    .line 212
    move-result-object v7

    .line 213
    const/16 v9, 0x180

    .line 214
    .line 215
    iget-wide v4, p0, Lh2/f;->g:J

    .line 216
    .line 217
    invoke-static/range {v4 .. v9}, Li2/a1;->d(JLg4/p0;Lay0/n;Ll2/o;I)V

    .line 218
    .line 219
    .line 220
    goto :goto_4

    .line 221
    :goto_5
    sget-object p1, Lx2/c;->r:Lx2/h;

    .line 222
    .line 223
    new-instance v4, Landroidx/compose/foundation/layout/HorizontalAlignElement;

    .line 224
    .line 225
    invoke-direct {v4, p1}, Landroidx/compose/foundation/layout/HorizontalAlignElement;-><init>(Lx2/h;)V

    .line 226
    .line 227
    .line 228
    sget-object p1, Lx2/c;->d:Lx2/j;

    .line 229
    .line 230
    invoke-static {p1, v3}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 231
    .line 232
    .line 233
    move-result-object p1

    .line 234
    iget-wide v5, v8, Ll2/t;->T:J

    .line 235
    .line 236
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 237
    .line 238
    .line 239
    move-result v3

    .line 240
    invoke-virtual {v8}, Ll2/t;->m()Ll2/p1;

    .line 241
    .line 242
    .line 243
    move-result-object v5

    .line 244
    invoke-static {v8, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 245
    .line 246
    .line 247
    move-result-object v4

    .line 248
    invoke-virtual {v8}, Ll2/t;->c0()V

    .line 249
    .line 250
    .line 251
    iget-boolean v6, v8, Ll2/t;->S:Z

    .line 252
    .line 253
    if-eqz v6, :cond_6

    .line 254
    .line 255
    invoke-virtual {v8, v10}, Ll2/t;->l(Lay0/a;)V

    .line 256
    .line 257
    .line 258
    goto :goto_6

    .line 259
    :cond_6
    invoke-virtual {v8}, Ll2/t;->m0()V

    .line 260
    .line 261
    .line 262
    :goto_6
    invoke-static {v11, p1, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 263
    .line 264
    .line 265
    invoke-static {p2, v5, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 266
    .line 267
    .line 268
    iget-boolean p1, v8, Ll2/t;->S:Z

    .line 269
    .line 270
    if-nez p1, :cond_7

    .line 271
    .line 272
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object p1

    .line 276
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 277
    .line 278
    .line 279
    move-result-object p2

    .line 280
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 281
    .line 282
    .line 283
    move-result p1

    .line 284
    if-nez p1, :cond_8

    .line 285
    .line 286
    :cond_7
    invoke-static {v3, v8, v3, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 287
    .line 288
    .line 289
    :cond_8
    invoke-static {v0, v4, v8}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 290
    .line 291
    .line 292
    sget-object p1, Lk2/n;->b:Lk2/p0;

    .line 293
    .line 294
    invoke-static {p1, v8}, Lh2/ec;->a(Lk2/p0;Ll2/o;)Lg4/p0;

    .line 295
    .line 296
    .line 297
    move-result-object v6

    .line 298
    const/4 v9, 0x0

    .line 299
    iget-wide v4, p0, Lh2/f;->h:J

    .line 300
    .line 301
    iget-object v7, p0, Lh2/f;->i:Lt2/b;

    .line 302
    .line 303
    invoke-static/range {v4 .. v9}, Li2/a1;->d(JLg4/p0;Lay0/n;Ll2/o;I)V

    .line 304
    .line 305
    .line 306
    invoke-virtual {v8, v2}, Ll2/t;->q(Z)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v8, v2}, Ll2/t;->q(Z)V

    .line 310
    .line 311
    .line 312
    goto :goto_7

    .line 313
    :cond_9
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 314
    .line 315
    .line 316
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 317
    .line 318
    return-object p0
.end method
