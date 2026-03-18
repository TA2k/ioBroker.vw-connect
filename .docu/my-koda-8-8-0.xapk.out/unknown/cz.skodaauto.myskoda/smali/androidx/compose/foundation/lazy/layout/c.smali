.class public final Landroidx/compose/foundation/lazy/layout/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Lo1/l0;

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Lo1/c0;

.field public final synthetic g:Ll2/b1;


# direct methods
.method public constructor <init>(Lo1/l0;Lx2/s;Lo1/c0;Ll2/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/foundation/lazy/layout/c;->d:Lo1/l0;

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/compose/foundation/lazy/layout/c;->e:Lx2/s;

    .line 7
    .line 8
    iput-object p3, p0, Landroidx/compose/foundation/lazy/layout/c;->f:Lo1/c0;

    .line 9
    .line 10
    iput-object p4, p0, Landroidx/compose/foundation/lazy/layout/c;->g:Ll2/b1;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    check-cast p1, Lu2/c;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Number;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 8
    .line 9
    .line 10
    check-cast p2, Ll2/t;

    .line 11
    .line 12
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p3

    .line 16
    const/16 v0, 0x8

    .line 17
    .line 18
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 19
    .line 20
    if-ne p3, v1, :cond_0

    .line 21
    .line 22
    new-instance p3, Lo1/a0;

    .line 23
    .line 24
    new-instance v2, Lio0/f;

    .line 25
    .line 26
    iget-object v3, p0, Landroidx/compose/foundation/lazy/layout/c;->g:Ll2/b1;

    .line 27
    .line 28
    invoke-direct {v2, v3, v0}, Lio0/f;-><init>(Ll2/b1;I)V

    .line 29
    .line 30
    .line 31
    invoke-direct {p3, p1, v2}, Lo1/a0;-><init>(Lu2/c;Lio0/f;)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p2, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    :cond_0
    move-object v4, p3

    .line 38
    check-cast v4, Lo1/a0;

    .line 39
    .line 40
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    if-ne p1, v1, :cond_1

    .line 45
    .line 46
    new-instance p1, Lt3/o1;

    .line 47
    .line 48
    new-instance p3, Lvp/y1;

    .line 49
    .line 50
    invoke-direct {p3, v4}, Lvp/y1;-><init>(Lo1/a0;)V

    .line 51
    .line 52
    .line 53
    invoke-direct {p1, p3}, Lt3/o1;-><init>(Lt3/q1;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p2, p1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :cond_1
    move-object v5, p1

    .line 60
    check-cast v5, Lt3/o1;

    .line 61
    .line 62
    iget-object v3, p0, Landroidx/compose/foundation/lazy/layout/c;->d:Lo1/l0;

    .line 63
    .line 64
    const/4 p1, 0x0

    .line 65
    if-eqz v3, :cond_9

    .line 66
    .line 67
    const p3, 0x67eb8deb

    .line 68
    .line 69
    .line 70
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 71
    .line 72
    .line 73
    const p3, 0x34e696b7

    .line 74
    .line 75
    .line 76
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 77
    .line 78
    .line 79
    sget-object p3, Lo1/b1;->a:Lo1/a1;

    .line 80
    .line 81
    if-eqz p3, :cond_2

    .line 82
    .line 83
    const v2, 0x5034f7f0

    .line 84
    .line 85
    .line 86
    invoke-virtual {p2, v2}, Ll2/t;->Y(I)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 90
    .line 91
    .line 92
    :goto_0
    move-object v6, p3

    .line 93
    goto :goto_2

    .line 94
    :cond_2
    const p3, 0x5035b7a1

    .line 95
    .line 96
    .line 97
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 98
    .line 99
    .line 100
    sget-object p3, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->f:Ll2/u2;

    .line 101
    .line 102
    invoke-virtual {p2, p3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p3

    .line 106
    check-cast p3, Landroid/view/View;

    .line 107
    .line 108
    invoke-virtual {p2, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v2

    .line 112
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v6

    .line 116
    if-nez v2, :cond_3

    .line 117
    .line 118
    if-ne v6, v1, :cond_6

    .line 119
    .line 120
    :cond_3
    const v2, 0x7f0a00e8

    .line 121
    .line 122
    .line 123
    invoke-virtual {p3, v2}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v6

    .line 127
    instance-of v7, v6, Lo1/z0;

    .line 128
    .line 129
    if-eqz v7, :cond_4

    .line 130
    .line 131
    check-cast v6, Lo1/z0;

    .line 132
    .line 133
    goto :goto_1

    .line 134
    :cond_4
    const/4 v6, 0x0

    .line 135
    :goto_1
    if-nez v6, :cond_5

    .line 136
    .line 137
    new-instance v6, Lo1/a;

    .line 138
    .line 139
    invoke-direct {v6, p3}, Lo1/a;-><init>(Landroid/view/View;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {p3, v2, v6}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    :cond_5
    invoke-virtual {p2, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    :cond_6
    move-object p3, v6

    .line 149
    check-cast p3, Lo1/z0;

    .line 150
    .line 151
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 152
    .line 153
    .line 154
    goto :goto_0

    .line 155
    :goto_2
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 156
    .line 157
    .line 158
    filled-new-array {v3, v4, v5, v6}, [Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object p3

    .line 162
    invoke-virtual {p2, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result v2

    .line 166
    invoke-virtual {p2, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v7

    .line 170
    or-int/2addr v2, v7

    .line 171
    invoke-virtual {p2, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result v7

    .line 175
    or-int/2addr v2, v7

    .line 176
    invoke-virtual {p2, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result v7

    .line 180
    or-int/2addr v2, v7

    .line 181
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v7

    .line 185
    if-nez v2, :cond_7

    .line 186
    .line 187
    if-ne v7, v1, :cond_8

    .line 188
    .line 189
    :cond_7
    new-instance v2, Lbg/a;

    .line 190
    .line 191
    const/16 v7, 0xd

    .line 192
    .line 193
    invoke-direct/range {v2 .. v7}, Lbg/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {p2, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    move-object v7, v2

    .line 200
    :cond_8
    check-cast v7, Lay0/k;

    .line 201
    .line 202
    invoke-static {p3, v7, p2}, Ll2/l0;->c([Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 206
    .line 207
    .line 208
    goto :goto_3

    .line 209
    :cond_9
    const p3, 0x67f47fcd

    .line 210
    .line 211
    .line 212
    invoke-virtual {p2, p3}, Ll2/t;->Y(I)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 216
    .line 217
    .line 218
    :goto_3
    sget p1, Lo1/m0;->a:I

    .line 219
    .line 220
    iget-object p1, p0, Landroidx/compose/foundation/lazy/layout/c;->e:Lx2/s;

    .line 221
    .line 222
    if-eqz v3, :cond_b

    .line 223
    .line 224
    new-instance p3, Landroidx/compose/foundation/lazy/layout/TraversablePrefetchStateModifierElement;

    .line 225
    .line 226
    invoke-direct {p3, v3}, Landroidx/compose/foundation/lazy/layout/TraversablePrefetchStateModifierElement;-><init>(Lo1/l0;)V

    .line 227
    .line 228
    .line 229
    invoke-interface {p1, p3}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 230
    .line 231
    .line 232
    move-result-object p3

    .line 233
    if-nez p3, :cond_a

    .line 234
    .line 235
    goto :goto_4

    .line 236
    :cond_a
    move-object p1, p3

    .line 237
    :cond_b
    :goto_4
    invoke-virtual {p2, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    move-result p3

    .line 241
    iget-object p0, p0, Landroidx/compose/foundation/lazy/layout/c;->f:Lo1/c0;

    .line 242
    .line 243
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    move-result v2

    .line 247
    or-int/2addr p3, v2

    .line 248
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v2

    .line 252
    if-nez p3, :cond_c

    .line 253
    .line 254
    if-ne v2, v1, :cond_d

    .line 255
    .line 256
    :cond_c
    new-instance v2, Ll2/u;

    .line 257
    .line 258
    const/16 p3, 0x1d

    .line 259
    .line 260
    invoke-direct {v2, p3, v4, p0}, Ll2/u;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 261
    .line 262
    .line 263
    invoke-virtual {p2, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 264
    .line 265
    .line 266
    :cond_d
    check-cast v2, Lay0/n;

    .line 267
    .line 268
    invoke-static {v5, p1, v2, p2, v0}, Lt3/k1;->b(Lt3/o1;Lx2/s;Lay0/n;Ll2/o;I)V

    .line 269
    .line 270
    .line 271
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 272
    .line 273
    return-object p0
.end method
