.class public final Lh2/y2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:Lvy0/b0;

.field public final synthetic g:Lm1/t;

.field public final synthetic h:Lgy0/j;

.field public final synthetic i:Li2/c0;

.field public final synthetic j:Lh2/e8;

.field public final synthetic k:Li2/z;

.field public final synthetic l:Lh2/z1;


# direct methods
.method public constructor <init>(JLl2/b1;Lvy0/b0;Lm1/t;Lgy0/j;Li2/c0;Lh2/e8;Li2/z;Lh2/z1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lh2/y2;->d:J

    .line 5
    .line 6
    iput-object p3, p0, Lh2/y2;->e:Ll2/b1;

    .line 7
    .line 8
    iput-object p4, p0, Lh2/y2;->f:Lvy0/b0;

    .line 9
    .line 10
    iput-object p5, p0, Lh2/y2;->g:Lm1/t;

    .line 11
    .line 12
    iput-object p6, p0, Lh2/y2;->h:Lgy0/j;

    .line 13
    .line 14
    iput-object p7, p0, Lh2/y2;->i:Li2/c0;

    .line 15
    .line 16
    iput-object p8, p0, Lh2/y2;->j:Lh2/e8;

    .line 17
    .line 18
    iput-object p9, p0, Lh2/y2;->k:Li2/z;

    .line 19
    .line 20
    iput-object p10, p0, Lh2/y2;->l:Lh2/z1;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    check-cast p1, Lb1/a0;

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
    const p1, 0x7f1205a9

    .line 11
    .line 12
    .line 13
    invoke-static {p2, p1}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    move-object v4, p2

    .line 18
    check-cast v4, Ll2/t;

    .line 19
    .line 20
    invoke-virtual {v4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p3

    .line 28
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 29
    .line 30
    if-nez p2, :cond_0

    .line 31
    .line 32
    if-ne p3, v0, :cond_1

    .line 33
    .line 34
    :cond_0
    new-instance p3, Lac0/r;

    .line 35
    .line 36
    const/16 p2, 0x10

    .line 37
    .line 38
    invoke-direct {p3, p1, p2}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v4, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    :cond_1
    check-cast p3, Lay0/k;

    .line 45
    .line 46
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 47
    .line 48
    const/4 p2, 0x0

    .line 49
    invoke-static {p1, p2, p3}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 50
    .line 51
    .line 52
    move-result-object p3

    .line 53
    sget-object v1, Lk1/j;->c:Lk1/e;

    .line 54
    .line 55
    sget-object v2, Lx2/c;->p:Lx2/h;

    .line 56
    .line 57
    invoke-static {v1, v2, v4, p2}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    iget-wide v1, v4, Ll2/t;->T:J

    .line 62
    .line 63
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    invoke-virtual {v4}, Ll2/t;->m()Ll2/p1;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    invoke-static {v4, p3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 72
    .line 73
    .line 74
    move-result-object p3

    .line 75
    sget-object v3, Lv3/k;->m1:Lv3/j;

    .line 76
    .line 77
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    sget-object v3, Lv3/j;->b:Lv3/i;

    .line 81
    .line 82
    invoke-virtual {v4}, Ll2/t;->c0()V

    .line 83
    .line 84
    .line 85
    iget-boolean v5, v4, Ll2/t;->S:Z

    .line 86
    .line 87
    if-eqz v5, :cond_2

    .line 88
    .line 89
    invoke-virtual {v4, v3}, Ll2/t;->l(Lay0/a;)V

    .line 90
    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_2
    invoke-virtual {v4}, Ll2/t;->m0()V

    .line 94
    .line 95
    .line 96
    :goto_0
    sget-object v3, Lv3/j;->g:Lv3/h;

    .line 97
    .line 98
    invoke-static {v3, p2, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 99
    .line 100
    .line 101
    sget-object p2, Lv3/j;->f:Lv3/h;

    .line 102
    .line 103
    invoke-static {p2, v2, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 104
    .line 105
    .line 106
    sget-object p2, Lv3/j;->j:Lv3/h;

    .line 107
    .line 108
    iget-boolean v2, v4, Ll2/t;->S:Z

    .line 109
    .line 110
    if-nez v2, :cond_3

    .line 111
    .line 112
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v2

    .line 116
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 117
    .line 118
    .line 119
    move-result-object v3

    .line 120
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v2

    .line 124
    if-nez v2, :cond_4

    .line 125
    .line 126
    :cond_3
    invoke-static {v1, v4, v1, p2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 127
    .line 128
    .line 129
    :cond_4
    sget-object p2, Lv3/j;->d:Lv3/h;

    .line 130
    .line 131
    invoke-static {p2, p3, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 132
    .line 133
    .line 134
    sget p2, Lh2/m3;->a:F

    .line 135
    .line 136
    const/4 p3, 0x7

    .line 137
    int-to-float p3, p3

    .line 138
    mul-float/2addr p2, p3

    .line 139
    sget p3, Lh2/p4;->a:F

    .line 140
    .line 141
    sub-float/2addr p2, p3

    .line 142
    invoke-static {p1, p2}, Landroidx/compose/foundation/layout/d;->h(Lx2/s;F)Lx2/s;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    sget p2, Lh2/m3;->c:F

    .line 147
    .line 148
    const/4 p3, 0x0

    .line 149
    const/4 v1, 0x2

    .line 150
    invoke-static {p1, p2, p3, v1}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    iget-object v7, p0, Lh2/y2;->e:Ll2/b1;

    .line 155
    .line 156
    invoke-virtual {v4, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    move-result p2

    .line 160
    iget-object v6, p0, Lh2/y2;->f:Lvy0/b0;

    .line 161
    .line 162
    invoke-virtual {v4, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result p3

    .line 166
    or-int/2addr p2, p3

    .line 167
    iget-object v8, p0, Lh2/y2;->g:Lm1/t;

    .line 168
    .line 169
    invoke-virtual {v4, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result p3

    .line 173
    or-int/2addr p2, p3

    .line 174
    iget-object v9, p0, Lh2/y2;->h:Lgy0/j;

    .line 175
    .line 176
    invoke-virtual {v4, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result p3

    .line 180
    or-int/2addr p2, p3

    .line 181
    iget-object v10, p0, Lh2/y2;->i:Li2/c0;

    .line 182
    .line 183
    invoke-virtual {v4, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 184
    .line 185
    .line 186
    move-result p3

    .line 187
    or-int/2addr p2, p3

    .line 188
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object p3

    .line 192
    if-nez p2, :cond_6

    .line 193
    .line 194
    if-ne p3, v0, :cond_5

    .line 195
    .line 196
    goto :goto_1

    .line 197
    :cond_5
    move-object v6, v9

    .line 198
    goto :goto_2

    .line 199
    :cond_6
    :goto_1
    new-instance v5, Lc/b;

    .line 200
    .line 201
    invoke-direct/range {v5 .. v10}, Lc/b;-><init>(Lvy0/b0;Ll2/b1;Lm1/t;Lgy0/j;Li2/c0;)V

    .line 202
    .line 203
    .line 204
    move-object v6, v9

    .line 205
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 206
    .line 207
    .line 208
    move-object p3, v5

    .line 209
    :goto_2
    move-object v3, p3

    .line 210
    check-cast v3, Lay0/k;

    .line 211
    .line 212
    const/4 v9, 0x6

    .line 213
    iget-wide v1, p0, Lh2/y2;->d:J

    .line 214
    .line 215
    move-object v8, v4

    .line 216
    iget-object v4, p0, Lh2/y2;->j:Lh2/e8;

    .line 217
    .line 218
    iget-object v5, p0, Lh2/y2;->k:Li2/z;

    .line 219
    .line 220
    iget-object v7, p0, Lh2/y2;->l:Lh2/z1;

    .line 221
    .line 222
    move-object v0, p1

    .line 223
    invoke-static/range {v0 .. v9}, Lh2/m3;->n(Lx2/s;JLay0/k;Lh2/e8;Li2/z;Lgy0/j;Lh2/z1;Ll2/o;I)V

    .line 224
    .line 225
    .line 226
    iget-wide v2, v7, Lh2/z1;->x:J

    .line 227
    .line 228
    const/4 v5, 0x0

    .line 229
    const/4 v6, 0x3

    .line 230
    const/4 v0, 0x0

    .line 231
    const/4 v1, 0x0

    .line 232
    move-object v4, v8

    .line 233
    invoke-static/range {v0 .. v6}, Lh2/r;->k(Lx2/s;FJLl2/o;II)V

    .line 234
    .line 235
    .line 236
    const/4 p0, 0x1

    .line 237
    invoke-virtual {v8, p0}, Ll2/t;->q(Z)V

    .line 238
    .line 239
    .line 240
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 241
    .line 242
    return-object p0
.end method
