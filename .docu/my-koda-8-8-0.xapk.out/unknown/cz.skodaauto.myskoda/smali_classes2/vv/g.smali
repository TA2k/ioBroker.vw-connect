.class public abstract Lvv/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lvv/c;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lvv/c;

    .line 2
    .line 3
    invoke-direct {v0}, Lvv/c;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lvv/g;->a:Lvv/c;

    .line 7
    .line 8
    return-void
.end method

.method public static final a(Lvv/m0;Lt2/b;Ll2/o;I)V
    .locals 12

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v5, p2

    .line 7
    check-cast v5, Ll2/t;

    .line 8
    .line 9
    const p2, 0x6fbc333a

    .line 10
    .line 11
    .line 12
    invoke-virtual {v5, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 p2, p3, 0xe

    .line 16
    .line 17
    const/4 v0, 0x2

    .line 18
    if-nez p2, :cond_1

    .line 19
    .line 20
    invoke-virtual {v5, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    if-eqz p2, :cond_0

    .line 25
    .line 26
    const/4 p2, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move p2, v0

    .line 29
    :goto_0
    or-int/2addr p2, p3

    .line 30
    goto :goto_1

    .line 31
    :cond_1
    move p2, p3

    .line 32
    :goto_1
    and-int/lit8 v1, p3, 0x70

    .line 33
    .line 34
    if-nez v1, :cond_3

    .line 35
    .line 36
    invoke-virtual {v5, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-eqz v1, :cond_2

    .line 41
    .line 42
    const/16 v1, 0x20

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_2
    const/16 v1, 0x10

    .line 46
    .line 47
    :goto_2
    or-int/2addr p2, v1

    .line 48
    :cond_3
    and-int/lit8 v1, p2, 0x5b

    .line 49
    .line 50
    const/16 v2, 0x12

    .line 51
    .line 52
    if-ne v1, v2, :cond_5

    .line 53
    .line 54
    invoke-virtual {v5}, Ll2/t;->A()Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-nez v1, :cond_4

    .line 59
    .line 60
    goto :goto_3

    .line 61
    :cond_4
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 62
    .line 63
    .line 64
    move-object v4, p1

    .line 65
    goto/16 :goto_5

    .line 66
    .line 67
    :cond_5
    :goto_3
    and-int/lit8 v1, p2, 0xe

    .line 68
    .line 69
    invoke-static {p0, v5}, Lvv/o0;->b(Lvv/m0;Ll2/o;)Lvv/n0;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    invoke-static {v2}, Lvv/o0;->c(Lvv/n0;)Lvv/n0;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    iget-object v2, v2, Lvv/n0;->d:Lvv/c;

    .line 78
    .line 79
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    const v3, 0x318c2b60

    .line 83
    .line 84
    .line 85
    invoke-virtual {v5, v3}, Ll2/t;->Z(I)V

    .line 86
    .line 87
    .line 88
    sget-object v3, Lw3/h1;->h:Ll2/u2;

    .line 89
    .line 90
    invoke-virtual {v5, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    check-cast v3, Lt4/c;

    .line 95
    .line 96
    invoke-static {p0, v5}, Lvv/o0;->b(Lvv/m0;Ll2/o;)Lvv/n0;

    .line 97
    .line 98
    .line 99
    move-result-object v4

    .line 100
    invoke-static {v4}, Lvv/o0;->c(Lvv/n0;)Lvv/n0;

    .line 101
    .line 102
    .line 103
    move-result-object v4

    .line 104
    iget-object v4, v4, Lvv/n0;->a:Lt4/o;

    .line 105
    .line 106
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    iget-wide v6, v4, Lt4/o;->a:J

    .line 110
    .line 111
    invoke-interface {v3, v6, v7}, Lt4/c;->s(J)F

    .line 112
    .line 113
    .line 114
    move-result v3

    .line 115
    int-to-float v0, v0

    .line 116
    div-float v8, v3, v0

    .line 117
    .line 118
    const/4 v0, 0x0

    .line 119
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 120
    .line 121
    .line 122
    const v3, -0x4ee9b9da

    .line 123
    .line 124
    .line 125
    invoke-virtual {v5, v3}, Ll2/t;->Z(I)V

    .line 126
    .line 127
    .line 128
    iget-wide v3, v5, Ll2/t;->T:J

    .line 129
    .line 130
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 131
    .line 132
    .line 133
    move-result v3

    .line 134
    invoke-virtual {v5}, Ll2/t;->m()Ll2/p1;

    .line 135
    .line 136
    .line 137
    move-result-object v4

    .line 138
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 139
    .line 140
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 141
    .line 142
    .line 143
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 144
    .line 145
    move-object v7, v6

    .line 146
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 147
    .line 148
    invoke-static {v6}, Lt3/k1;->k(Lx2/s;)Lt2/b;

    .line 149
    .line 150
    .line 151
    move-result-object v9

    .line 152
    invoke-virtual {v5}, Ll2/t;->c0()V

    .line 153
    .line 154
    .line 155
    iget-boolean v10, v5, Ll2/t;->S:Z

    .line 156
    .line 157
    if-eqz v10, :cond_6

    .line 158
    .line 159
    invoke-virtual {v5, v7}, Ll2/t;->l(Lay0/a;)V

    .line 160
    .line 161
    .line 162
    goto :goto_4

    .line 163
    :cond_6
    invoke-virtual {v5}, Ll2/t;->m0()V

    .line 164
    .line 165
    .line 166
    :goto_4
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 167
    .line 168
    sget-object v10, Lvv/e;->a:Lvv/e;

    .line 169
    .line 170
    invoke-static {v7, v10, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 171
    .line 172
    .line 173
    sget-object v7, Lv3/j;->f:Lv3/h;

    .line 174
    .line 175
    invoke-static {v7, v4, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 176
    .line 177
    .line 178
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 179
    .line 180
    iget-boolean v7, v5, Ll2/t;->S:Z

    .line 181
    .line 182
    if-nez v7, :cond_7

    .line 183
    .line 184
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v7

    .line 188
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 189
    .line 190
    .line 191
    move-result-object v10

    .line 192
    invoke-static {v7, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 193
    .line 194
    .line 195
    move-result v7

    .line 196
    if-nez v7, :cond_8

    .line 197
    .line 198
    :cond_7
    invoke-static {v3, v5, v3, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 199
    .line 200
    .line 201
    :cond_8
    new-instance v3, Ll2/d2;

    .line 202
    .line 203
    invoke-direct {v3, v5}, Ll2/d2;-><init>(Ll2/o;)V

    .line 204
    .line 205
    .line 206
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 207
    .line 208
    .line 209
    move-result-object v4

    .line 210
    invoke-virtual {v9, v3, v5, v4}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    const v3, 0x7ab4aae9

    .line 214
    .line 215
    .line 216
    invoke-virtual {v5, v3}, Ll2/t;->Z(I)V

    .line 217
    .line 218
    .line 219
    const v3, -0x374ae27b

    .line 220
    .line 221
    .line 222
    invoke-virtual {v5, v3}, Ll2/t;->Z(I)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {v2, p0, v5, v1}, Lvv/c;->a(Lvv/m0;Ll2/o;I)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 229
    .line 230
    .line 231
    const/4 v9, 0x0

    .line 232
    const/4 v11, 0x5

    .line 233
    const/4 v7, 0x0

    .line 234
    move v10, v8

    .line 235
    invoke-static/range {v6 .. v11}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 236
    .line 237
    .line 238
    move-result-object v1

    .line 239
    shl-int/lit8 p2, p2, 0x6

    .line 240
    .line 241
    and-int/lit16 v6, p2, 0x1c00

    .line 242
    .line 243
    const/4 v7, 0x6

    .line 244
    const/4 v2, 0x0

    .line 245
    const/4 v3, 0x0

    .line 246
    move-object v4, p1

    .line 247
    invoke-static/range {v1 .. v7}, Llp/dc;->a(Lx2/s;Lvv/n0;Lxf0/b2;Lay0/o;Ll2/o;II)V

    .line 248
    .line 249
    .line 250
    const/4 p1, 0x1

    .line 251
    invoke-static {v5, v0, p1, v0}, Lf2/m0;->w(Ll2/t;ZZZ)V

    .line 252
    .line 253
    .line 254
    :goto_5
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 255
    .line 256
    .line 257
    move-result-object p1

    .line 258
    if-eqz p1, :cond_9

    .line 259
    .line 260
    new-instance p2, Lvv/f;

    .line 261
    .line 262
    const/4 v0, 0x0

    .line 263
    invoke-direct {p2, p3, v0, v4, p0}, Lvv/f;-><init>(IILt2/b;Lvv/m0;)V

    .line 264
    .line 265
    .line 266
    iput-object p2, p1, Ll2/u1;->d:Lay0/n;

    .line 267
    .line 268
    :cond_9
    return-void
.end method
