.class public final Le2/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:Z

.field public final synthetic f:Lx2/s;

.field public final synthetic g:Le2/l;


# direct methods
.method public constructor <init>(JZLx2/s;Le2/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Le2/d;->d:J

    .line 5
    .line 6
    iput-boolean p3, p0, Le2/d;->e:Z

    .line 7
    .line 8
    iput-object p4, p0, Le2/d;->f:Lx2/s;

    .line 9
    .line 10
    iput-object p5, p0, Le2/d;->g:Le2/l;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

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
    check-cast p1, Ll2/t;

    .line 21
    .line 22
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 23
    .line 24
    .line 25
    move-result p2

    .line 26
    if-eqz p2, :cond_a

    .line 27
    .line 28
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    iget-wide v4, p0, Le2/d;->d:J

    .line 34
    .line 35
    cmp-long p2, v4, v0

    .line 36
    .line 37
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 38
    .line 39
    iget-object v1, p0, Le2/d;->g:Le2/l;

    .line 40
    .line 41
    iget-boolean v6, p0, Le2/d;->e:Z

    .line 42
    .line 43
    if-eqz p2, :cond_7

    .line 44
    .line 45
    const p2, 0x34c4c6

    .line 46
    .line 47
    .line 48
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 49
    .line 50
    .line 51
    if-eqz v6, :cond_1

    .line 52
    .line 53
    sget-object p2, Lk1/d;->b:Lk1/c;

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_1
    sget-object p2, Lk1/d;->a:Lk1/c;

    .line 57
    .line 58
    :goto_1
    invoke-static {v4, v5}, Lt4/h;->c(J)F

    .line 59
    .line 60
    .line 61
    move-result v8

    .line 62
    invoke-static {v4, v5}, Lt4/h;->b(J)F

    .line 63
    .line 64
    .line 65
    move-result v9

    .line 66
    const/4 v11, 0x0

    .line 67
    const/16 v12, 0xc

    .line 68
    .line 69
    iget-object v7, p0, Le2/d;->f:Lx2/s;

    .line 70
    .line 71
    const/4 v10, 0x0

    .line 72
    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/layout/d;->l(Lx2/s;FFFFI)Lx2/s;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    sget-object v4, Lx2/c;->m:Lx2/i;

    .line 77
    .line 78
    invoke-static {p2, v4, p1, v3}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    iget-wide v4, p1, Ll2/t;->T:J

    .line 83
    .line 84
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 85
    .line 86
    .line 87
    move-result v4

    .line 88
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 89
    .line 90
    .line 91
    move-result-object v5

    .line 92
    invoke-static {p1, p0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 97
    .line 98
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 99
    .line 100
    .line 101
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 102
    .line 103
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 104
    .line 105
    .line 106
    iget-boolean v8, p1, Ll2/t;->S:Z

    .line 107
    .line 108
    if-eqz v8, :cond_2

    .line 109
    .line 110
    invoke-virtual {p1, v7}, Ll2/t;->l(Lay0/a;)V

    .line 111
    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_2
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 115
    .line 116
    .line 117
    :goto_2
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 118
    .line 119
    invoke-static {v7, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 120
    .line 121
    .line 122
    sget-object p2, Lv3/j;->f:Lv3/h;

    .line 123
    .line 124
    invoke-static {p2, v5, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 125
    .line 126
    .line 127
    sget-object p2, Lv3/j;->j:Lv3/h;

    .line 128
    .line 129
    iget-boolean v5, p1, Ll2/t;->S:Z

    .line 130
    .line 131
    if-nez v5, :cond_3

    .line 132
    .line 133
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v5

    .line 137
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 138
    .line 139
    .line 140
    move-result-object v7

    .line 141
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 142
    .line 143
    .line 144
    move-result v5

    .line 145
    if-nez v5, :cond_4

    .line 146
    .line 147
    :cond_3
    invoke-static {v4, p1, v4, p2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 148
    .line 149
    .line 150
    :cond_4
    sget-object p2, Lv3/j;->d:Lv3/h;

    .line 151
    .line 152
    invoke-static {p2, p0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {p1, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result p0

    .line 159
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object p2

    .line 163
    if-nez p0, :cond_5

    .line 164
    .line 165
    if-ne p2, v0, :cond_6

    .line 166
    .line 167
    :cond_5
    new-instance p2, Le2/c;

    .line 168
    .line 169
    const/4 p0, 0x0

    .line 170
    invoke-direct {p2, v1, p0}, Le2/c;-><init>(Le2/l;I)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {p1, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 174
    .line 175
    .line 176
    :cond_6
    check-cast p2, Lay0/a;

    .line 177
    .line 178
    const/4 p0, 0x6

    .line 179
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 180
    .line 181
    invoke-static {p0, p2, p1, v0, v6}, Lkp/o;->c(ILay0/a;Ll2/o;Lx2/s;Z)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {p1, v2}, Ll2/t;->q(Z)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 188
    .line 189
    .line 190
    goto :goto_3

    .line 191
    :cond_7
    const p2, 0x42f938

    .line 192
    .line 193
    .line 194
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {p1, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result p2

    .line 201
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v2

    .line 205
    if-nez p2, :cond_8

    .line 206
    .line 207
    if-ne v2, v0, :cond_9

    .line 208
    .line 209
    :cond_8
    new-instance v2, Le2/c;

    .line 210
    .line 211
    const/4 p2, 0x1

    .line 212
    invoke-direct {v2, v1, p2}, Le2/c;-><init>(Le2/l;I)V

    .line 213
    .line 214
    .line 215
    invoke-virtual {p1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    :cond_9
    check-cast v2, Lay0/a;

    .line 219
    .line 220
    iget-object p0, p0, Le2/d;->f:Lx2/s;

    .line 221
    .line 222
    invoke-static {v3, v2, p1, p0, v6}, Lkp/o;->c(ILay0/a;Ll2/o;Lx2/s;Z)V

    .line 223
    .line 224
    .line 225
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 226
    .line 227
    .line 228
    goto :goto_3

    .line 229
    :cond_a
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 230
    .line 231
    .line 232
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 233
    .line 234
    return-object p0
.end method
