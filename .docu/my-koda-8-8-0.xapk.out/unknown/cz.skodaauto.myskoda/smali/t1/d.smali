.class public abstract Lt1/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Llx0/l;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Llx0/l;

    .line 2
    .line 3
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    invoke-direct {v0, v1, v1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lt1/d;->a:Llx0/l;

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lg4/g;Ljava/util/List;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    move-object/from16 v3, p2

    .line 8
    .line 9
    check-cast v3, Ll2/t;

    .line 10
    .line 11
    const v4, -0x6af76057

    .line 12
    .line 13
    .line 14
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v4, v2, 0x6

    .line 18
    .line 19
    if-nez v4, :cond_1

    .line 20
    .line 21
    invoke-virtual {v3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v4

    .line 25
    if-eqz v4, :cond_0

    .line 26
    .line 27
    const/4 v4, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v4, 0x2

    .line 30
    :goto_0
    or-int/2addr v4, v2

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v4, v2

    .line 33
    :goto_1
    and-int/lit8 v5, v2, 0x30

    .line 34
    .line 35
    if-nez v5, :cond_3

    .line 36
    .line 37
    invoke-virtual {v3, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v5

    .line 41
    if-eqz v5, :cond_2

    .line 42
    .line 43
    const/16 v5, 0x20

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_2
    const/16 v5, 0x10

    .line 47
    .line 48
    :goto_2
    or-int/2addr v4, v5

    .line 49
    :cond_3
    and-int/lit8 v5, v4, 0x13

    .line 50
    .line 51
    const/16 v6, 0x12

    .line 52
    .line 53
    const/4 v8, 0x1

    .line 54
    if-eq v5, v6, :cond_4

    .line 55
    .line 56
    move v5, v8

    .line 57
    goto :goto_3

    .line 58
    :cond_4
    const/4 v5, 0x0

    .line 59
    :goto_3
    and-int/2addr v4, v8

    .line 60
    invoke-virtual {v3, v4, v5}, Ll2/t;->O(IZ)Z

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    if-eqz v4, :cond_9

    .line 65
    .line 66
    move-object v4, v1

    .line 67
    check-cast v4, Ljava/util/Collection;

    .line 68
    .line 69
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 70
    .line 71
    .line 72
    move-result v4

    .line 73
    const/4 v5, 0x0

    .line 74
    :goto_4
    if-ge v5, v4, :cond_a

    .line 75
    .line 76
    invoke-interface {v1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v6

    .line 80
    check-cast v6, Lg4/e;

    .line 81
    .line 82
    iget-object v9, v6, Lg4/e;->a:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v9, Lay0/o;

    .line 85
    .line 86
    iget v10, v6, Lg4/e;->b:I

    .line 87
    .line 88
    iget v6, v6, Lg4/e;->c:I

    .line 89
    .line 90
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v11

    .line 94
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 95
    .line 96
    if-ne v11, v12, :cond_5

    .line 97
    .line 98
    sget-object v11, Lt1/c;->b:Lt1/c;

    .line 99
    .line 100
    invoke-virtual {v3, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    :cond_5
    check-cast v11, Lt3/q0;

    .line 104
    .line 105
    iget-wide v12, v3, Ll2/t;->T:J

    .line 106
    .line 107
    invoke-static {v12, v13}, Ljava/lang/Long;->hashCode(J)I

    .line 108
    .line 109
    .line 110
    move-result v12

    .line 111
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 112
    .line 113
    .line 114
    move-result-object v13

    .line 115
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 116
    .line 117
    invoke-static {v3, v14}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 118
    .line 119
    .line 120
    move-result-object v14

    .line 121
    sget-object v15, Lv3/k;->m1:Lv3/j;

    .line 122
    .line 123
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 124
    .line 125
    .line 126
    sget-object v15, Lv3/j;->b:Lv3/i;

    .line 127
    .line 128
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 129
    .line 130
    .line 131
    const/16 p2, 0x0

    .line 132
    .line 133
    iget-boolean v7, v3, Ll2/t;->S:Z

    .line 134
    .line 135
    if-eqz v7, :cond_6

    .line 136
    .line 137
    invoke-virtual {v3, v15}, Ll2/t;->l(Lay0/a;)V

    .line 138
    .line 139
    .line 140
    goto :goto_5

    .line 141
    :cond_6
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 142
    .line 143
    .line 144
    :goto_5
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 145
    .line 146
    invoke-static {v7, v11, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 147
    .line 148
    .line 149
    sget-object v7, Lv3/j;->f:Lv3/h;

    .line 150
    .line 151
    invoke-static {v7, v13, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 152
    .line 153
    .line 154
    sget-object v7, Lv3/j;->j:Lv3/h;

    .line 155
    .line 156
    iget-boolean v11, v3, Ll2/t;->S:Z

    .line 157
    .line 158
    if-nez v11, :cond_7

    .line 159
    .line 160
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v11

    .line 164
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 165
    .line 166
    .line 167
    move-result-object v13

    .line 168
    invoke-static {v11, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    move-result v11

    .line 172
    if-nez v11, :cond_8

    .line 173
    .line 174
    :cond_7
    invoke-static {v12, v3, v12, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 175
    .line 176
    .line 177
    :cond_8
    sget-object v7, Lv3/j;->d:Lv3/h;

    .line 178
    .line 179
    invoke-static {v7, v14, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v0, v10, v6}, Lg4/g;->d(II)Lg4/g;

    .line 183
    .line 184
    .line 185
    move-result-object v6

    .line 186
    iget-object v6, v6, Lg4/g;->e:Ljava/lang/String;

    .line 187
    .line 188
    invoke-static/range {p2 .. p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 189
    .line 190
    .line 191
    move-result-object v7

    .line 192
    invoke-interface {v9, v6, v3, v7}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    invoke-virtual {v3, v8}, Ll2/t;->q(Z)V

    .line 196
    .line 197
    .line 198
    add-int/lit8 v5, v5, 0x1

    .line 199
    .line 200
    goto :goto_4

    .line 201
    :cond_9
    invoke-virtual {v3}, Ll2/t;->R()V

    .line 202
    .line 203
    .line 204
    :cond_a
    invoke-virtual {v3}, Ll2/t;->s()Ll2/u1;

    .line 205
    .line 206
    .line 207
    move-result-object v3

    .line 208
    if-eqz v3, :cond_b

    .line 209
    .line 210
    new-instance v4, Ljk/b;

    .line 211
    .line 212
    const/16 v5, 0x19

    .line 213
    .line 214
    invoke-direct {v4, v2, v5, v0, v1}, Ljk/b;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    iput-object v4, v3, Ll2/u1;->d:Lay0/n;

    .line 218
    .line 219
    :cond_b
    return-void
.end method
