.class public final Llc/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llc/o;->a:Ljava/lang/Object;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ll2/o;I)V
    .locals 12

    .line 1
    check-cast p1, Ll2/t;

    .line 2
    .line 3
    const v0, -0x4bc7a74a

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    or-int/lit8 v0, p2, 0x6

    .line 10
    .line 11
    and-int/lit8 v1, p2, 0x30

    .line 12
    .line 13
    sget-object v2, Lyk/a;->c:Lt2/b;

    .line 14
    .line 15
    if-nez v1, :cond_1

    .line 16
    .line 17
    invoke-virtual {p1, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    const/16 v1, 0x20

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/16 v1, 0x10

    .line 27
    .line 28
    :goto_0
    or-int/2addr v0, v1

    .line 29
    :cond_1
    and-int/lit16 v1, p2, 0x180

    .line 30
    .line 31
    if-nez v1, :cond_4

    .line 32
    .line 33
    and-int/lit16 v1, p2, 0x200

    .line 34
    .line 35
    if-nez v1, :cond_2

    .line 36
    .line 37
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    goto :goto_1

    .line 42
    :cond_2
    invoke-virtual {p1, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    :goto_1
    if-eqz v1, :cond_3

    .line 47
    .line 48
    const/16 v1, 0x100

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_3
    const/16 v1, 0x80

    .line 52
    .line 53
    :goto_2
    or-int/2addr v0, v1

    .line 54
    :cond_4
    and-int/lit16 v1, v0, 0x93

    .line 55
    .line 56
    const/16 v3, 0x92

    .line 57
    .line 58
    const/4 v4, 0x0

    .line 59
    const/4 v5, 0x1

    .line 60
    if-eq v1, v3, :cond_5

    .line 61
    .line 62
    move v1, v5

    .line 63
    goto :goto_3

    .line 64
    :cond_5
    move v1, v4

    .line 65
    :goto_3
    and-int/lit8 v3, v0, 0x1

    .line 66
    .line 67
    invoke-virtual {p1, v3, v1}, Ll2/t;->O(IZ)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-eqz v1, :cond_b

    .line 72
    .line 73
    iget-object v1, p0, Llc/o;->a:Ljava/lang/Object;

    .line 74
    .line 75
    if-nez v1, :cond_6

    .line 76
    .line 77
    const v0, 0x691fbfe8

    .line 78
    .line 79
    .line 80
    invoke-virtual {p1, v0}, Ll2/t;->Y(I)V

    .line 81
    .line 82
    .line 83
    :goto_4
    invoke-virtual {p1, v4}, Ll2/t;->q(Z)V

    .line 84
    .line 85
    .line 86
    goto/16 :goto_6

    .line 87
    .line 88
    :cond_6
    const v3, 0x691fbfe9

    .line 89
    .line 90
    .line 91
    invoke-virtual {p1, v3}, Ll2/t;->Y(I)V

    .line 92
    .line 93
    .line 94
    sget-object v3, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 95
    .line 96
    sget-object v6, Lx2/c;->d:Lx2/j;

    .line 97
    .line 98
    invoke-static {v6, v4}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 99
    .line 100
    .line 101
    move-result-object v6

    .line 102
    iget-wide v7, p1, Ll2/t;->T:J

    .line 103
    .line 104
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 105
    .line 106
    .line 107
    move-result v7

    .line 108
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 109
    .line 110
    .line 111
    move-result-object v8

    .line 112
    invoke-static {p1, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 113
    .line 114
    .line 115
    move-result-object v9

    .line 116
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 117
    .line 118
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 119
    .line 120
    .line 121
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 122
    .line 123
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 124
    .line 125
    .line 126
    iget-boolean v11, p1, Ll2/t;->S:Z

    .line 127
    .line 128
    if-eqz v11, :cond_7

    .line 129
    .line 130
    invoke-virtual {p1, v10}, Ll2/t;->l(Lay0/a;)V

    .line 131
    .line 132
    .line 133
    goto :goto_5

    .line 134
    :cond_7
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 135
    .line 136
    .line 137
    :goto_5
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 138
    .line 139
    invoke-static {v10, v6, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 140
    .line 141
    .line 142
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 143
    .line 144
    invoke-static {v6, v8, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 145
    .line 146
    .line 147
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 148
    .line 149
    iget-boolean v8, p1, Ll2/t;->S:Z

    .line 150
    .line 151
    if-nez v8, :cond_8

    .line 152
    .line 153
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v8

    .line 157
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 158
    .line 159
    .line 160
    move-result-object v10

    .line 161
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result v8

    .line 165
    if-nez v8, :cond_9

    .line 166
    .line 167
    :cond_8
    invoke-static {v7, p1, v7, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 168
    .line 169
    .line 170
    :cond_9
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 171
    .line 172
    invoke-static {v6, v9, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 173
    .line 174
    .line 175
    and-int/lit8 v0, v0, 0x70

    .line 176
    .line 177
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 178
    .line 179
    .line 180
    move-result-object v0

    .line 181
    invoke-virtual {v2, v1, p1, v0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 185
    .line 186
    invoke-interface {v3, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 195
    .line 196
    if-ne v1, v2, :cond_a

    .line 197
    .line 198
    sget-object v1, Llc/n;->d:Llc/n;

    .line 199
    .line 200
    invoke-virtual {p1, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    :cond_a
    check-cast v1, Landroidx/compose/ui/input/pointer/PointerInputEventHandler;

    .line 204
    .line 205
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 206
    .line 207
    invoke-static {v0, v2, v1}, Lp3/f0;->b(Lx2/s;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lx2/s;

    .line 208
    .line 209
    .line 210
    move-result-object v0

    .line 211
    invoke-static {v0, p1, v4}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {p1, v5}, Ll2/t;->q(Z)V

    .line 215
    .line 216
    .line 217
    goto/16 :goto_4

    .line 218
    .line 219
    :cond_b
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 220
    .line 221
    .line 222
    :goto_6
    invoke-virtual {p1}, Ll2/t;->s()Ll2/u1;

    .line 223
    .line 224
    .line 225
    move-result-object p1

    .line 226
    if-eqz p1, :cond_c

    .line 227
    .line 228
    new-instance v0, Ld90/h;

    .line 229
    .line 230
    const/16 v1, 0x9

    .line 231
    .line 232
    invoke-direct {v0, p0, p2, v1}, Ld90/h;-><init>(Ljava/lang/Object;II)V

    .line 233
    .line 234
    .line 235
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 236
    .line 237
    :cond_c
    return-void
.end method
