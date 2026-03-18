.class public abstract Lal/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/u2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, La2/m;

    .line 2
    .line 3
    const/16 v1, 0x1c

    .line 4
    .line 5
    invoke-direct {v0, v1}, La2/m;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/u2;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lal/g;->a:Ll2/u2;

    .line 14
    .line 15
    return-void
.end method

.method public static final a(Lmh/r;Lay0/k;Ll2/o;I)V
    .locals 11

    .line 1
    const-string v0, "uiState"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "event"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    move-object v5, p2

    .line 12
    check-cast v5, Ll2/t;

    .line 13
    .line 14
    const p2, 0x4f475eec

    .line 15
    .line 16
    .line 17
    invoke-virtual {v5, p2}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v5, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    const/16 v0, 0x10

    .line 25
    .line 26
    const/16 v1, 0x20

    .line 27
    .line 28
    if-eqz p2, :cond_0

    .line 29
    .line 30
    move p2, v1

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    move p2, v0

    .line 33
    :goto_0
    or-int/2addr p2, p3

    .line 34
    and-int/lit8 v2, p2, 0x11

    .line 35
    .line 36
    const/4 v8, 0x1

    .line 37
    const/4 v9, 0x0

    .line 38
    if-eq v2, v0, :cond_1

    .line 39
    .line 40
    move v0, v8

    .line 41
    goto :goto_1

    .line 42
    :cond_1
    move v0, v9

    .line 43
    :goto_1
    and-int/lit8 v2, p2, 0x1

    .line 44
    .line 45
    invoke-virtual {v5, v2, v0}, Ll2/t;->O(IZ)Z

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    if-eqz v0, :cond_9

    .line 50
    .line 51
    const/high16 v0, 0x3f800000    # 1.0f

    .line 52
    .line 53
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 54
    .line 55
    invoke-static {v10, v0}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 60
    .line 61
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 62
    .line 63
    invoke-static {v2, v3, v5, v9}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    iget-wide v3, v5, Ll2/t;->T:J

    .line 68
    .line 69
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    invoke-virtual {v5}, Ll2/t;->m()Ll2/p1;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    invoke-static {v5, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 82
    .line 83
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 87
    .line 88
    invoke-virtual {v5}, Ll2/t;->c0()V

    .line 89
    .line 90
    .line 91
    iget-boolean v7, v5, Ll2/t;->S:Z

    .line 92
    .line 93
    if-eqz v7, :cond_2

    .line 94
    .line 95
    invoke-virtual {v5, v6}, Ll2/t;->l(Lay0/a;)V

    .line 96
    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_2
    invoke-virtual {v5}, Ll2/t;->m0()V

    .line 100
    .line 101
    .line 102
    :goto_2
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 103
    .line 104
    invoke-static {v6, v2, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 105
    .line 106
    .line 107
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 108
    .line 109
    invoke-static {v2, v4, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 110
    .line 111
    .line 112
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 113
    .line 114
    iget-boolean v4, v5, Ll2/t;->S:Z

    .line 115
    .line 116
    if-nez v4, :cond_3

    .line 117
    .line 118
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 123
    .line 124
    .line 125
    move-result-object v6

    .line 126
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result v4

    .line 130
    if-nez v4, :cond_4

    .line 131
    .line 132
    :cond_3
    invoke-static {v3, v5, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 133
    .line 134
    .line 135
    :cond_4
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 136
    .line 137
    invoke-static {v2, v0, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 138
    .line 139
    .line 140
    sget-object v0, Lal/g;->a:Ll2/u2;

    .line 141
    .line 142
    invoke-virtual {v5, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    check-cast v0, Ll2/b1;

    .line 147
    .line 148
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    check-cast v0, Lal/u;

    .line 153
    .line 154
    iget-boolean v0, v0, Lal/u;->a:Z

    .line 155
    .line 156
    if-eqz v0, :cond_8

    .line 157
    .line 158
    const v0, 0x1854836a

    .line 159
    .line 160
    .line 161
    invoke-virtual {v5, v0}, Ll2/t;->Y(I)V

    .line 162
    .line 163
    .line 164
    sget-wide v2, Le3/s;->g:J

    .line 165
    .line 166
    sget-object v0, Le3/j0;->a:Le3/i0;

    .line 167
    .line 168
    invoke-static {v10, v2, v3, v0}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 169
    .line 170
    .line 171
    move-result-object v2

    .line 172
    const v0, 0x7f120bd4

    .line 173
    .line 174
    .line 175
    invoke-static {v5, v0}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    and-int/lit8 p2, p2, 0x70

    .line 180
    .line 181
    if-ne p2, v1, :cond_5

    .line 182
    .line 183
    move p2, v8

    .line 184
    goto :goto_3

    .line 185
    :cond_5
    move p2, v9

    .line 186
    :goto_3
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v1

    .line 190
    if-nez p2, :cond_6

    .line 191
    .line 192
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 193
    .line 194
    if-ne v1, p2, :cond_7

    .line 195
    .line 196
    :cond_6
    new-instance v1, Lak/n;

    .line 197
    .line 198
    const/4 p2, 0x4

    .line 199
    invoke-direct {v1, p2, p1}, Lak/n;-><init>(ILay0/k;)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v5, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 203
    .line 204
    .line 205
    :cond_7
    check-cast v1, Lay0/a;

    .line 206
    .line 207
    new-instance v3, Li91/w2;

    .line 208
    .line 209
    const/4 p2, 0x2

    .line 210
    invoke-direct {v3, v1, p2}, Li91/w2;-><init>(Lay0/a;I)V

    .line 211
    .line 212
    .line 213
    const/16 v6, 0x30

    .line 214
    .line 215
    const/16 v7, 0x8

    .line 216
    .line 217
    const/4 v4, 0x0

    .line 218
    move-object v1, v0

    .line 219
    invoke-static/range {v1 .. v7}, Ldk/l;->a(Ljava/lang/String;Lx2/s;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;Ll2/o;II)V

    .line 220
    .line 221
    .line 222
    const/16 p2, 0x14

    .line 223
    .line 224
    int-to-float p2, p2

    .line 225
    invoke-static {v10, p2, v5, v9}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 226
    .line 227
    .line 228
    goto :goto_4

    .line 229
    :cond_8
    const p2, 0x18223420

    .line 230
    .line 231
    .line 232
    invoke-virtual {v5, p2}, Ll2/t;->Y(I)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v5, v9}, Ll2/t;->q(Z)V

    .line 236
    .line 237
    .line 238
    :goto_4
    invoke-virtual {v5, v8}, Ll2/t;->q(Z)V

    .line 239
    .line 240
    .line 241
    goto :goto_5

    .line 242
    :cond_9
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 243
    .line 244
    .line 245
    :goto_5
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 246
    .line 247
    .line 248
    move-result-object p2

    .line 249
    if-eqz p2, :cond_a

    .line 250
    .line 251
    new-instance v0, Lal/f;

    .line 252
    .line 253
    const/4 v1, 0x0

    .line 254
    invoke-direct {v0, p0, p1, p3, v1}, Lal/f;-><init>(Lmh/r;Lay0/k;II)V

    .line 255
    .line 256
    .line 257
    iput-object v0, p2, Ll2/u1;->d:Lay0/n;

    .line 258
    .line 259
    :cond_a
    return-void
.end method
