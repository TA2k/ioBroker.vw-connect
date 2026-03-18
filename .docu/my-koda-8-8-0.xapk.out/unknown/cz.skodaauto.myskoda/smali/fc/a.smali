.class public abstract Lfc/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lz81/g;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lz81/g;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Lz81/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lfc/a;->a:Lz81/g;

    .line 8
    .line 9
    return-void
.end method

.method public static final a(IILl2/o;Z)V
    .locals 18

    .line 1
    move/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v11, p2

    .line 6
    .line 7
    check-cast v11, Ll2/t;

    .line 8
    .line 9
    const v2, -0x4ef8d189

    .line 10
    .line 11
    .line 12
    invoke-virtual {v11, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v2, v1, 0x1

    .line 16
    .line 17
    const/4 v3, 0x2

    .line 18
    const/4 v4, 0x4

    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    or-int/lit8 v5, v0, 0x6

    .line 22
    .line 23
    move v6, v5

    .line 24
    move/from16 v5, p3

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_0
    and-int/lit8 v5, v0, 0x6

    .line 28
    .line 29
    if-nez v5, :cond_2

    .line 30
    .line 31
    move/from16 v5, p3

    .line 32
    .line 33
    invoke-virtual {v11, v5}, Ll2/t;->h(Z)Z

    .line 34
    .line 35
    .line 36
    move-result v6

    .line 37
    if-eqz v6, :cond_1

    .line 38
    .line 39
    move v6, v4

    .line 40
    goto :goto_0

    .line 41
    :cond_1
    move v6, v3

    .line 42
    :goto_0
    or-int/2addr v6, v0

    .line 43
    goto :goto_1

    .line 44
    :cond_2
    move/from16 v5, p3

    .line 45
    .line 46
    move v6, v0

    .line 47
    :goto_1
    and-int/lit8 v7, v6, 0x3

    .line 48
    .line 49
    const/4 v8, 0x0

    .line 50
    const/4 v9, 0x1

    .line 51
    if-eq v7, v3, :cond_3

    .line 52
    .line 53
    move v3, v9

    .line 54
    goto :goto_2

    .line 55
    :cond_3
    move v3, v8

    .line 56
    :goto_2
    and-int/lit8 v7, v6, 0x1

    .line 57
    .line 58
    invoke-virtual {v11, v7, v3}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    if-eqz v3, :cond_b

    .line 63
    .line 64
    if-eqz v2, :cond_4

    .line 65
    .line 66
    move v15, v9

    .line 67
    goto :goto_3

    .line 68
    :cond_4
    move v15, v5

    .line 69
    :goto_3
    const-string v2, "ConsentsFlowScreen"

    .line 70
    .line 71
    invoke-static {v2, v11}, Lzb/b;->C(Ljava/lang/String;Ll2/o;)Lzb/v0;

    .line 72
    .line 73
    .line 74
    move-result-object v2

    .line 75
    new-array v3, v8, [Ljava/lang/Object;

    .line 76
    .line 77
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 82
    .line 83
    if-ne v5, v7, :cond_5

    .line 84
    .line 85
    new-instance v5, Lf2/h0;

    .line 86
    .line 87
    const/4 v10, 0x7

    .line 88
    invoke-direct {v5, v10}, Lf2/h0;-><init>(I)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v11, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    :cond_5
    check-cast v5, Lay0/a;

    .line 95
    .line 96
    const/16 v10, 0x30

    .line 97
    .line 98
    invoke-static {v3, v5, v11, v10}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v3

    .line 102
    check-cast v3, Ll2/b1;

    .line 103
    .line 104
    new-instance v13, Ly1/i;

    .line 105
    .line 106
    const/16 v5, 0x11

    .line 107
    .line 108
    invoke-direct {v13, v2, v5}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v11, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v5

    .line 115
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v10

    .line 119
    if-nez v5, :cond_6

    .line 120
    .line 121
    if-ne v10, v7, :cond_7

    .line 122
    .line 123
    :cond_6
    new-instance v10, Leh/c;

    .line 124
    .line 125
    const/16 v5, 0xc

    .line 126
    .line 127
    invoke-direct {v10, v3, v5}, Leh/c;-><init>(Ll2/b1;I)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v11, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    :cond_7
    check-cast v10, Lay0/n;

    .line 134
    .line 135
    invoke-virtual {v2, v10}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 136
    .line 137
    .line 138
    move-result-object v14

    .line 139
    invoke-virtual {v2}, Lzb/v0;->b()Lz9/y;

    .line 140
    .line 141
    .line 142
    move-result-object v2

    .line 143
    invoke-virtual {v11, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 144
    .line 145
    .line 146
    move-result v5

    .line 147
    and-int/lit8 v6, v6, 0xe

    .line 148
    .line 149
    if-ne v6, v4, :cond_8

    .line 150
    .line 151
    move v8, v9

    .line 152
    :cond_8
    or-int v4, v5, v8

    .line 153
    .line 154
    invoke-virtual {v11, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result v5

    .line 158
    or-int/2addr v4, v5

    .line 159
    invoke-virtual {v11, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v5

    .line 163
    or-int/2addr v4, v5

    .line 164
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v5

    .line 168
    if-nez v4, :cond_9

    .line 169
    .line 170
    if-ne v5, v7, :cond_a

    .line 171
    .line 172
    :cond_9
    new-instance v12, Le2/g;

    .line 173
    .line 174
    const/16 v17, 0x2

    .line 175
    .line 176
    move-object/from16 v16, v3

    .line 177
    .line 178
    invoke-direct/range {v12 .. v17}, Le2/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;I)V

    .line 179
    .line 180
    .line 181
    invoke-virtual {v11, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 182
    .line 183
    .line 184
    move-object v5, v12

    .line 185
    :cond_a
    move-object v10, v5

    .line 186
    check-cast v10, Lay0/k;

    .line 187
    .line 188
    const/4 v13, 0x0

    .line 189
    const/16 v14, 0x3fc

    .line 190
    .line 191
    const-string v3, "/form"

    .line 192
    .line 193
    const/4 v4, 0x0

    .line 194
    const/4 v5, 0x0

    .line 195
    const/4 v6, 0x0

    .line 196
    const/4 v7, 0x0

    .line 197
    const/4 v8, 0x0

    .line 198
    const/4 v9, 0x0

    .line 199
    const/16 v12, 0x30

    .line 200
    .line 201
    invoke-static/range {v2 .. v14}, Ljp/w0;->b(Lz9/y;Ljava/lang/String;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;III)V

    .line 202
    .line 203
    .line 204
    goto :goto_4

    .line 205
    :cond_b
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 206
    .line 207
    .line 208
    move v15, v5

    .line 209
    :goto_4
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 210
    .line 211
    .line 212
    move-result-object v2

    .line 213
    if-eqz v2, :cond_c

    .line 214
    .line 215
    new-instance v3, Ldk/i;

    .line 216
    .line 217
    const/4 v4, 0x1

    .line 218
    invoke-direct {v3, v0, v1, v4, v15}, Ldk/i;-><init>(IIIZ)V

    .line 219
    .line 220
    .line 221
    iput-object v3, v2, Ll2/u1;->d:Lay0/n;

    .line 222
    .line 223
    :cond_c
    return-void
.end method
