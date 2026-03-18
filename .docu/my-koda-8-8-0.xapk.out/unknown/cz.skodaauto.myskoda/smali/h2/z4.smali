.class public final Lh2/z4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx4/v;


# instance fields
.field public final d:I

.field public final e:Ll2/b1;

.field public final f:Leh/c;

.field public final g:Li2/c;

.field public final h:Li2/c;

.field public final i:Li2/j1;

.field public final j:Li2/j1;

.field public final k:Li2/d;

.field public final l:Li2/d;

.field public final m:Li2/k1;

.field public final n:Li2/k1;


# direct methods
.method public constructor <init>(Lt4/c;ILl2/b1;Leh/c;)V
    .locals 1

    .line 1
    sget v0, Lh2/q5;->a:F

    .line 2
    .line 3
    invoke-interface {p1, v0}, Lt4/c;->Q(F)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    iput p2, p0, Lh2/z4;->d:I

    .line 11
    .line 12
    iput-object p3, p0, Lh2/z4;->e:Ll2/b1;

    .line 13
    .line 14
    iput-object p4, p0, Lh2/z4;->f:Leh/c;

    .line 15
    .line 16
    new-instance p2, Li2/c;

    .line 17
    .line 18
    sget-object p3, Lx2/c;->p:Lx2/h;

    .line 19
    .line 20
    invoke-direct {p2, p3, p3}, Li2/c;-><init>(Lx2/h;Lx2/h;)V

    .line 21
    .line 22
    .line 23
    iput-object p2, p0, Lh2/z4;->g:Li2/c;

    .line 24
    .line 25
    new-instance p2, Li2/c;

    .line 26
    .line 27
    sget-object p3, Lx2/c;->r:Lx2/h;

    .line 28
    .line 29
    invoke-direct {p2, p3, p3}, Li2/c;-><init>(Lx2/h;Lx2/h;)V

    .line 30
    .line 31
    .line 32
    iput-object p2, p0, Lh2/z4;->h:Li2/c;

    .line 33
    .line 34
    new-instance p2, Li2/j1;

    .line 35
    .line 36
    sget-object p3, Lx2/a;->c:Lx2/f;

    .line 37
    .line 38
    invoke-direct {p2, p3}, Li2/j1;-><init>(Lx2/f;)V

    .line 39
    .line 40
    .line 41
    iput-object p2, p0, Lh2/z4;->i:Li2/j1;

    .line 42
    .line 43
    new-instance p2, Li2/j1;

    .line 44
    .line 45
    sget-object p3, Lx2/a;->d:Lx2/f;

    .line 46
    .line 47
    invoke-direct {p2, p3}, Li2/j1;-><init>(Lx2/f;)V

    .line 48
    .line 49
    .line 50
    iput-object p2, p0, Lh2/z4;->j:Li2/j1;

    .line 51
    .line 52
    new-instance p2, Li2/d;

    .line 53
    .line 54
    sget-object p3, Lx2/c;->m:Lx2/i;

    .line 55
    .line 56
    sget-object p4, Lx2/c;->o:Lx2/i;

    .line 57
    .line 58
    invoke-direct {p2, p3, p4}, Li2/d;-><init>(Lx2/i;Lx2/i;)V

    .line 59
    .line 60
    .line 61
    iput-object p2, p0, Lh2/z4;->k:Li2/d;

    .line 62
    .line 63
    new-instance p2, Li2/d;

    .line 64
    .line 65
    invoke-direct {p2, p4, p3}, Li2/d;-><init>(Lx2/i;Lx2/i;)V

    .line 66
    .line 67
    .line 68
    iput-object p2, p0, Lh2/z4;->l:Li2/d;

    .line 69
    .line 70
    new-instance p2, Li2/k1;

    .line 71
    .line 72
    invoke-direct {p2, p3, p1}, Li2/k1;-><init>(Lx2/i;I)V

    .line 73
    .line 74
    .line 75
    iput-object p2, p0, Lh2/z4;->m:Li2/k1;

    .line 76
    .line 77
    new-instance p2, Li2/k1;

    .line 78
    .line 79
    invoke-direct {p2, p4, p1}, Li2/k1;-><init>(Lx2/i;I)V

    .line 80
    .line 81
    .line 82
    iput-object p2, p0, Lh2/z4;->n:Li2/k1;

    .line 83
    .line 84
    return-void
.end method


# virtual methods
.method public final F(Lt4/k;JLt4/m;J)J
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v7, p5

    .line 4
    .line 5
    iget-object v1, v0, Lh2/z4;->e:Ll2/b1;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    :cond_0
    const/16 v9, 0x20

    .line 13
    .line 14
    shr-long v1, p2, v9

    .line 15
    .line 16
    long-to-int v1, v1

    .line 17
    const-wide v10, 0xffffffffL

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    and-long v2, p2, v10

    .line 23
    .line 24
    long-to-int v2, v2

    .line 25
    iget v3, v0, Lh2/z4;->d:I

    .line 26
    .line 27
    add-int/2addr v2, v3

    .line 28
    int-to-long v3, v1

    .line 29
    shl-long/2addr v3, v9

    .line 30
    int-to-long v1, v2

    .line 31
    and-long/2addr v1, v10

    .line 32
    or-long/2addr v3, v1

    .line 33
    invoke-virtual/range {p1 .. p1}, Lt4/k;->a()J

    .line 34
    .line 35
    .line 36
    move-result-wide v1

    .line 37
    shr-long/2addr v1, v9

    .line 38
    long-to-int v1, v1

    .line 39
    shr-long v5, v3, v9

    .line 40
    .line 41
    long-to-int v12, v5

    .line 42
    div-int/lit8 v2, v12, 0x2

    .line 43
    .line 44
    if-ge v1, v2, :cond_1

    .line 45
    .line 46
    iget-object v1, v0, Lh2/z4;->i:Li2/j1;

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_1
    iget-object v1, v0, Lh2/z4;->j:Li2/j1;

    .line 50
    .line 51
    :goto_0
    const/4 v13, 0x3

    .line 52
    new-array v2, v13, [Li2/v0;

    .line 53
    .line 54
    const/4 v14, 0x0

    .line 55
    iget-object v5, v0, Lh2/z4;->g:Li2/c;

    .line 56
    .line 57
    aput-object v5, v2, v14

    .line 58
    .line 59
    const/4 v15, 0x1

    .line 60
    iget-object v5, v0, Lh2/z4;->h:Li2/c;

    .line 61
    .line 62
    aput-object v5, v2, v15

    .line 63
    .line 64
    const/16 v16, 0x2

    .line 65
    .line 66
    aput-object v1, v2, v16

    .line 67
    .line 68
    invoke-static {v2}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    move-object v2, v1

    .line 73
    check-cast v2, Ljava/util/Collection;

    .line 74
    .line 75
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    move v5, v14

    .line 80
    :goto_1
    if-ge v5, v2, :cond_3

    .line 81
    .line 82
    invoke-interface {v1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    check-cast v6, Li2/v0;

    .line 87
    .line 88
    move/from16 v17, v9

    .line 89
    .line 90
    move-wide/from16 v18, v10

    .line 91
    .line 92
    shr-long v9, v7, v17

    .line 93
    .line 94
    long-to-int v9, v9

    .line 95
    move v10, v2

    .line 96
    move v11, v5

    .line 97
    move v5, v9

    .line 98
    move-object/from16 v2, p1

    .line 99
    .line 100
    move-object v9, v1

    .line 101
    move-object v1, v6

    .line 102
    move-object/from16 v6, p4

    .line 103
    .line 104
    invoke-interface/range {v1 .. v6}, Li2/v0;->a(Lt4/k;JILt4/m;)I

    .line 105
    .line 106
    .line 107
    move-result v1

    .line 108
    invoke-static {v9}, Ljp/k1;->h(Ljava/util/List;)I

    .line 109
    .line 110
    .line 111
    move-result v6

    .line 112
    if-eq v11, v6, :cond_4

    .line 113
    .line 114
    if-ltz v1, :cond_2

    .line 115
    .line 116
    add-int/2addr v5, v1

    .line 117
    if-gt v5, v12, :cond_2

    .line 118
    .line 119
    goto :goto_2

    .line 120
    :cond_2
    add-int/lit8 v5, v11, 0x1

    .line 121
    .line 122
    move-object v1, v9

    .line 123
    move v2, v10

    .line 124
    move/from16 v9, v17

    .line 125
    .line 126
    move-wide/from16 v10, v18

    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_3
    move-object/from16 v2, p1

    .line 130
    .line 131
    move/from16 v17, v9

    .line 132
    .line 133
    move-wide/from16 v18, v10

    .line 134
    .line 135
    move v1, v14

    .line 136
    :cond_4
    :goto_2
    invoke-virtual {v2}, Lt4/k;->a()J

    .line 137
    .line 138
    .line 139
    move-result-wide v5

    .line 140
    and-long v5, v5, v18

    .line 141
    .line 142
    long-to-int v5, v5

    .line 143
    and-long v9, v3, v18

    .line 144
    .line 145
    long-to-int v6, v9

    .line 146
    div-int/lit8 v9, v6, 0x2

    .line 147
    .line 148
    if-ge v5, v9, :cond_5

    .line 149
    .line 150
    iget-object v5, v0, Lh2/z4;->m:Li2/k1;

    .line 151
    .line 152
    goto :goto_3

    .line 153
    :cond_5
    iget-object v5, v0, Lh2/z4;->n:Li2/k1;

    .line 154
    .line 155
    :goto_3
    new-array v9, v13, [Li2/w0;

    .line 156
    .line 157
    iget-object v10, v0, Lh2/z4;->k:Li2/d;

    .line 158
    .line 159
    aput-object v10, v9, v14

    .line 160
    .line 161
    iget-object v10, v0, Lh2/z4;->l:Li2/d;

    .line 162
    .line 163
    aput-object v10, v9, v15

    .line 164
    .line 165
    aput-object v5, v9, v16

    .line 166
    .line 167
    invoke-static {v9}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 168
    .line 169
    .line 170
    move-result-object v5

    .line 171
    move-object v9, v5

    .line 172
    check-cast v9, Ljava/util/Collection;

    .line 173
    .line 174
    invoke-interface {v9}, Ljava/util/Collection;->size()I

    .line 175
    .line 176
    .line 177
    move-result v9

    .line 178
    move v10, v14

    .line 179
    :goto_4
    if-ge v10, v9, :cond_8

    .line 180
    .line 181
    invoke-interface {v5, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v11

    .line 185
    check-cast v11, Li2/w0;

    .line 186
    .line 187
    and-long v12, v7, v18

    .line 188
    .line 189
    long-to-int v12, v12

    .line 190
    invoke-interface {v11, v2, v3, v4, v12}, Li2/w0;->a(Lt4/k;JI)I

    .line 191
    .line 192
    .line 193
    move-result v11

    .line 194
    invoke-static {v5}, Ljp/k1;->h(Ljava/util/List;)I

    .line 195
    .line 196
    .line 197
    move-result v13

    .line 198
    if-eq v10, v13, :cond_7

    .line 199
    .line 200
    if-ltz v11, :cond_6

    .line 201
    .line 202
    add-int/2addr v12, v11

    .line 203
    if-gt v12, v6, :cond_6

    .line 204
    .line 205
    goto :goto_5

    .line 206
    :cond_6
    add-int/lit8 v10, v10, 0x1

    .line 207
    .line 208
    goto :goto_4

    .line 209
    :cond_7
    :goto_5
    move v14, v11

    .line 210
    :cond_8
    int-to-long v3, v1

    .line 211
    shl-long v3, v3, v17

    .line 212
    .line 213
    int-to-long v5, v14

    .line 214
    and-long v5, v5, v18

    .line 215
    .line 216
    or-long/2addr v3, v5

    .line 217
    iget-object v0, v0, Lh2/z4;->f:Leh/c;

    .line 218
    .line 219
    invoke-static {v3, v4, v7, v8}, Lkp/e9;->a(JJ)Lt4/k;

    .line 220
    .line 221
    .line 222
    move-result-object v1

    .line 223
    invoke-virtual {v0, v2, v1}, Leh/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    return-wide v3
.end method
