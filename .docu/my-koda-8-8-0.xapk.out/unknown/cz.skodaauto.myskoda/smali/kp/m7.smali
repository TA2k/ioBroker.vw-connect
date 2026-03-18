.class public abstract Lkp/m7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ly6/q;IILt2/b;Ll2/o;II)V
    .locals 7

    .line 1
    check-cast p4, Ll2/t;

    .line 2
    .line 3
    const v0, -0x704a306d

    .line 4
    .line 5
    .line 6
    invoke-virtual {p4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p5, 0x6

    .line 10
    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int/2addr v0, p5

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    move v0, p5

    .line 25
    :goto_1
    and-int/lit8 v1, p6, 0x2

    .line 26
    .line 27
    if-eqz v1, :cond_2

    .line 28
    .line 29
    or-int/lit8 v0, v0, 0x30

    .line 30
    .line 31
    goto :goto_3

    .line 32
    :cond_2
    and-int/lit8 v2, p5, 0x30

    .line 33
    .line 34
    if-nez v2, :cond_4

    .line 35
    .line 36
    invoke-virtual {p4, p1}, Ll2/t;->e(I)Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-eqz v2, :cond_3

    .line 41
    .line 42
    const/16 v2, 0x20

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_3
    const/16 v2, 0x10

    .line 46
    .line 47
    :goto_2
    or-int/2addr v0, v2

    .line 48
    :cond_4
    :goto_3
    and-int/lit8 v2, p6, 0x4

    .line 49
    .line 50
    if-eqz v2, :cond_5

    .line 51
    .line 52
    or-int/lit16 v0, v0, 0x180

    .line 53
    .line 54
    goto :goto_5

    .line 55
    :cond_5
    and-int/lit16 v3, p5, 0x180

    .line 56
    .line 57
    if-nez v3, :cond_7

    .line 58
    .line 59
    invoke-virtual {p4, p2}, Ll2/t;->e(I)Z

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    if-eqz v3, :cond_6

    .line 64
    .line 65
    const/16 v3, 0x100

    .line 66
    .line 67
    goto :goto_4

    .line 68
    :cond_6
    const/16 v3, 0x80

    .line 69
    .line 70
    :goto_4
    or-int/2addr v0, v3

    .line 71
    :cond_7
    :goto_5
    and-int/lit16 v3, p5, 0xc00

    .line 72
    .line 73
    if-nez v3, :cond_9

    .line 74
    .line 75
    invoke-virtual {p4, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v3

    .line 79
    if-eqz v3, :cond_8

    .line 80
    .line 81
    const/16 v3, 0x800

    .line 82
    .line 83
    goto :goto_6

    .line 84
    :cond_8
    const/16 v3, 0x400

    .line 85
    .line 86
    :goto_6
    or-int/2addr v0, v3

    .line 87
    :cond_9
    and-int/lit16 v3, v0, 0x493

    .line 88
    .line 89
    const/16 v4, 0x492

    .line 90
    .line 91
    if-ne v3, v4, :cond_b

    .line 92
    .line 93
    invoke-virtual {p4}, Ll2/t;->A()Z

    .line 94
    .line 95
    .line 96
    move-result v3

    .line 97
    if-nez v3, :cond_a

    .line 98
    .line 99
    goto :goto_8

    .line 100
    :cond_a
    invoke-virtual {p4}, Ll2/t;->R()V

    .line 101
    .line 102
    .line 103
    :goto_7
    move v2, p1

    .line 104
    move v3, p2

    .line 105
    goto :goto_a

    .line 106
    :cond_b
    :goto_8
    const/4 v3, 0x0

    .line 107
    if-eqz v1, :cond_c

    .line 108
    .line 109
    move p1, v3

    .line 110
    :cond_c
    if-eqz v2, :cond_d

    .line 111
    .line 112
    move p2, v3

    .line 113
    :cond_d
    sget-object v1, Lf7/g;->d:Lf7/g;

    .line 114
    .line 115
    const v2, 0x227c4e56

    .line 116
    .line 117
    .line 118
    invoke-virtual {p4, v2}, Ll2/t;->Z(I)V

    .line 119
    .line 120
    .line 121
    const v2, -0x20ad3f64

    .line 122
    .line 123
    .line 124
    invoke-virtual {p4, v2}, Ll2/t;->Z(I)V

    .line 125
    .line 126
    .line 127
    iget-object v2, p4, Ll2/t;->a:Leb/j0;

    .line 128
    .line 129
    instance-of v2, v2, Ly6/b;

    .line 130
    .line 131
    if-eqz v2, :cond_10

    .line 132
    .line 133
    invoke-virtual {p4}, Ll2/t;->W()V

    .line 134
    .line 135
    .line 136
    iget-boolean v2, p4, Ll2/t;->S:Z

    .line 137
    .line 138
    if-eqz v2, :cond_e

    .line 139
    .line 140
    invoke-virtual {p4, v1}, Ll2/t;->l(Lay0/a;)V

    .line 141
    .line 142
    .line 143
    goto :goto_9

    .line 144
    :cond_e
    invoke-virtual {p4}, Ll2/t;->m0()V

    .line 145
    .line 146
    .line 147
    :goto_9
    sget-object v1, Lf7/e;->i:Lf7/e;

    .line 148
    .line 149
    invoke-static {v1, p0, p4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 150
    .line 151
    .line 152
    new-instance v1, Lf7/a;

    .line 153
    .line 154
    invoke-direct {v1, p2}, Lf7/a;-><init>(I)V

    .line 155
    .line 156
    .line 157
    sget-object v2, Lf7/e;->j:Lf7/e;

    .line 158
    .line 159
    invoke-static {v2, v1, p4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 160
    .line 161
    .line 162
    new-instance v1, Lf7/b;

    .line 163
    .line 164
    invoke-direct {v1, p1}, Lf7/b;-><init>(I)V

    .line 165
    .line 166
    .line 167
    sget-object v2, Lf7/e;->k:Lf7/e;

    .line 168
    .line 169
    invoke-static {v2, v1, p4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 170
    .line 171
    .line 172
    shr-int/lit8 v0, v0, 0x6

    .line 173
    .line 174
    and-int/lit8 v0, v0, 0x70

    .line 175
    .line 176
    or-int/lit8 v0, v0, 0x6

    .line 177
    .line 178
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    sget-object v1, Lf7/i;->a:Lf7/i;

    .line 183
    .line 184
    invoke-virtual {p3, v1, p4, v0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    const/4 v0, 0x1

    .line 188
    invoke-virtual {p4, v0}, Ll2/t;->q(Z)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {p4, v3}, Ll2/t;->q(Z)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {p4, v3}, Ll2/t;->q(Z)V

    .line 195
    .line 196
    .line 197
    goto :goto_7

    .line 198
    :goto_a
    invoke-virtual {p4}, Ll2/t;->s()Ll2/u1;

    .line 199
    .line 200
    .line 201
    move-result-object p1

    .line 202
    if-eqz p1, :cond_f

    .line 203
    .line 204
    new-instance v0, Lf7/h;

    .line 205
    .line 206
    move-object v1, p0

    .line 207
    move-object v4, p3

    .line 208
    move v5, p5

    .line 209
    move v6, p6

    .line 210
    invoke-direct/range {v0 .. v6}, Lf7/h;-><init>(Ly6/q;IILt2/b;II)V

    .line 211
    .line 212
    .line 213
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 214
    .line 215
    :cond_f
    return-void

    .line 216
    :cond_10
    invoke-static {}, Ll2/b;->l()V

    .line 217
    .line 218
    .line 219
    const/4 p0, 0x0

    .line 220
    throw p0
.end method


# virtual methods
.method public abstract b(Ljava/lang/Throwable;)V
.end method

.method public abstract c(Lcom/google/firebase/messaging/w;)V
.end method
