.class public final synthetic Le71/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/q;


# instance fields
.field public final synthetic d:Lh71/w;

.field public final synthetic e:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Lh71/w;Lt2/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le71/h;->d:Lh71/w;

    .line 5
    .line 6
    iput-object p2, p0, Le71/h;->e:Lt2/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    check-cast p1, Ljava/lang/Boolean;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    check-cast p2, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    check-cast p3, Lx2/s;

    .line 14
    .line 15
    check-cast p4, Ll2/o;

    .line 16
    .line 17
    check-cast p5, Ljava/lang/Integer;

    .line 18
    .line 19
    invoke-virtual {p5}, Ljava/lang/Integer;->intValue()I

    .line 20
    .line 21
    .line 22
    move-result p5

    .line 23
    const-string v1, "clickableModifier"

    .line 24
    .line 25
    invoke-static {p3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    and-int/lit8 v1, p5, 0x6

    .line 29
    .line 30
    const/4 v2, 0x2

    .line 31
    if-nez v1, :cond_1

    .line 32
    .line 33
    move-object v1, p4

    .line 34
    check-cast v1, Ll2/t;

    .line 35
    .line 36
    invoke-virtual {v1, p1}, Ll2/t;->h(Z)Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-eqz v1, :cond_0

    .line 41
    .line 42
    const/4 v1, 0x4

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    move v1, v2

    .line 45
    :goto_0
    or-int/2addr v1, p5

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    move v1, p5

    .line 48
    :goto_1
    and-int/lit8 v3, p5, 0x30

    .line 49
    .line 50
    if-nez v3, :cond_3

    .line 51
    .line 52
    move-object v3, p4

    .line 53
    check-cast v3, Ll2/t;

    .line 54
    .line 55
    invoke-virtual {v3, v0}, Ll2/t;->h(Z)Z

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    if-eqz v3, :cond_2

    .line 60
    .line 61
    const/16 v3, 0x20

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_2
    const/16 v3, 0x10

    .line 65
    .line 66
    :goto_2
    or-int/2addr v1, v3

    .line 67
    :cond_3
    and-int/lit16 p5, p5, 0x180

    .line 68
    .line 69
    if-nez p5, :cond_5

    .line 70
    .line 71
    move-object p5, p4

    .line 72
    check-cast p5, Ll2/t;

    .line 73
    .line 74
    invoke-virtual {p5, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result p5

    .line 78
    if-eqz p5, :cond_4

    .line 79
    .line 80
    const/16 p5, 0x100

    .line 81
    .line 82
    goto :goto_3

    .line 83
    :cond_4
    const/16 p5, 0x80

    .line 84
    .line 85
    :goto_3
    or-int/2addr v1, p5

    .line 86
    :cond_5
    and-int/lit16 p5, v1, 0x493

    .line 87
    .line 88
    const/16 v3, 0x492

    .line 89
    .line 90
    const/4 v4, 0x0

    .line 91
    const/4 v5, 0x1

    .line 92
    if-eq p5, v3, :cond_6

    .line 93
    .line 94
    move p5, v5

    .line 95
    goto :goto_4

    .line 96
    :cond_6
    move p5, v4

    .line 97
    :goto_4
    and-int/lit8 v3, v1, 0x1

    .line 98
    .line 99
    check-cast p4, Ll2/t;

    .line 100
    .line 101
    invoke-virtual {p4, v3, p5}, Ll2/t;->O(IZ)Z

    .line 102
    .line 103
    .line 104
    move-result p5

    .line 105
    if-eqz p5, :cond_c

    .line 106
    .line 107
    const p5, -0x7e7b55fe

    .line 108
    .line 109
    .line 110
    invoke-virtual {p4, p5}, Ll2/t;->Y(I)V

    .line 111
    .line 112
    .line 113
    sget-object p5, Lh71/o;->a:Ll2/u2;

    .line 114
    .line 115
    invoke-virtual {p4, p5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p5

    .line 119
    check-cast p5, Lh71/n;

    .line 120
    .line 121
    iget p5, p5, Lh71/n;->a:F

    .line 122
    .line 123
    const/4 v3, 0x0

    .line 124
    invoke-static {p3, v3, p5, v5}, Landroidx/compose/foundation/layout/d;->b(Lx2/s;FFI)Lx2/s;

    .line 125
    .line 126
    .line 127
    move-result-object p3

    .line 128
    sget-object p5, Ls1/f;->a:Ls1/e;

    .line 129
    .line 130
    invoke-static {p3, p5}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 131
    .line 132
    .line 133
    move-result-object p3

    .line 134
    iget-object v3, p0, Le71/h;->d:Lh71/w;

    .line 135
    .line 136
    iget-object v6, v3, Lh71/w;->b:Lh71/d;

    .line 137
    .line 138
    invoke-virtual {v6, v0, p1}, Lh71/d;->a(ZZ)J

    .line 139
    .line 140
    .line 141
    move-result-wide v6

    .line 142
    iget-object p1, v3, Lh71/w;->a:Lh71/c;

    .line 143
    .line 144
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 145
    .line 146
    .line 147
    move-result p1

    .line 148
    sget-object v0, Le3/j0;->a:Le3/i0;

    .line 149
    .line 150
    if-eqz p1, :cond_8

    .line 151
    .line 152
    if-ne p1, v5, :cond_7

    .line 153
    .line 154
    sget-wide v8, Le3/s;->h:J

    .line 155
    .line 156
    invoke-static {p3, v8, v9, v0}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 157
    .line 158
    .line 159
    move-result-object p1

    .line 160
    int-to-float p3, v2

    .line 161
    invoke-static {v6, v7, p3}, Lkp/h;->a(JF)Le1/t;

    .line 162
    .line 163
    .line 164
    move-result-object p3

    .line 165
    iget v0, p3, Le1/t;->a:F

    .line 166
    .line 167
    iget-object p3, p3, Le1/t;->b:Le3/p0;

    .line 168
    .line 169
    invoke-static {p1, v0, p3, p5}, Lkp/g;->b(Lx2/s;FLe3/p0;Le3/n0;)Lx2/s;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    goto :goto_5

    .line 174
    :cond_7
    new-instance p0, La8/r0;

    .line 175
    .line 176
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 177
    .line 178
    .line 179
    throw p0

    .line 180
    :cond_8
    invoke-static {p3, v6, v7, v0}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    :goto_5
    invoke-virtual {p4, v4}, Ll2/t;->q(Z)V

    .line 185
    .line 186
    .line 187
    sget-object p3, Lx2/c;->d:Lx2/j;

    .line 188
    .line 189
    invoke-static {p3, v4}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 190
    .line 191
    .line 192
    move-result-object p3

    .line 193
    iget-wide v2, p4, Ll2/t;->T:J

    .line 194
    .line 195
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 196
    .line 197
    .line 198
    move-result p5

    .line 199
    invoke-virtual {p4}, Ll2/t;->m()Ll2/p1;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    invoke-static {p4, p1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 204
    .line 205
    .line 206
    move-result-object p1

    .line 207
    sget-object v2, Lv3/k;->m1:Lv3/j;

    .line 208
    .line 209
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 210
    .line 211
    .line 212
    sget-object v2, Lv3/j;->b:Lv3/i;

    .line 213
    .line 214
    invoke-virtual {p4}, Ll2/t;->c0()V

    .line 215
    .line 216
    .line 217
    iget-boolean v3, p4, Ll2/t;->S:Z

    .line 218
    .line 219
    if-eqz v3, :cond_9

    .line 220
    .line 221
    invoke-virtual {p4, v2}, Ll2/t;->l(Lay0/a;)V

    .line 222
    .line 223
    .line 224
    goto :goto_6

    .line 225
    :cond_9
    invoke-virtual {p4}, Ll2/t;->m0()V

    .line 226
    .line 227
    .line 228
    :goto_6
    sget-object v2, Lv3/j;->g:Lv3/h;

    .line 229
    .line 230
    invoke-static {v2, p3, p4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 231
    .line 232
    .line 233
    sget-object p3, Lv3/j;->f:Lv3/h;

    .line 234
    .line 235
    invoke-static {p3, v0, p4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 236
    .line 237
    .line 238
    sget-object p3, Lv3/j;->j:Lv3/h;

    .line 239
    .line 240
    iget-boolean v0, p4, Ll2/t;->S:Z

    .line 241
    .line 242
    if-nez v0, :cond_a

    .line 243
    .line 244
    invoke-virtual {p4}, Ll2/t;->L()Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v0

    .line 248
    invoke-static {p5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 249
    .line 250
    .line 251
    move-result-object v2

    .line 252
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 253
    .line 254
    .line 255
    move-result v0

    .line 256
    if-nez v0, :cond_b

    .line 257
    .line 258
    :cond_a
    invoke-static {p5, p4, p5, p3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 259
    .line 260
    .line 261
    :cond_b
    sget-object p3, Lv3/j;->d:Lv3/h;

    .line 262
    .line 263
    invoke-static {p3, p1, p4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 264
    .line 265
    .line 266
    and-int/lit8 p1, v1, 0x70

    .line 267
    .line 268
    const/4 p3, 0x6

    .line 269
    or-int/2addr p1, p3

    .line 270
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 271
    .line 272
    .line 273
    move-result-object p1

    .line 274
    iget-object p0, p0, Le71/h;->e:Lt2/b;

    .line 275
    .line 276
    sget-object p3, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 277
    .line 278
    invoke-virtual {p0, p3, p2, p4, p1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    invoke-virtual {p4, v5}, Ll2/t;->q(Z)V

    .line 282
    .line 283
    .line 284
    goto :goto_7

    .line 285
    :cond_c
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 286
    .line 287
    .line 288
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 289
    .line 290
    return-object p0
.end method
