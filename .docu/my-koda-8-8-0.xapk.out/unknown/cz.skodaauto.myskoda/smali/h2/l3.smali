.class public final Lh2/l3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Li2/z;

.field public final synthetic e:J

.field public final synthetic f:Lgy0/j;

.field public final synthetic g:Lx2/s;

.field public final synthetic h:Lh2/z1;

.field public final synthetic i:Lay0/k;

.field public final synthetic j:Lh2/e8;


# direct methods
.method public constructor <init>(Li2/z;JLgy0/j;Lx2/s;Lh2/z1;Lay0/k;Lh2/e8;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/l3;->d:Li2/z;

    .line 5
    .line 6
    iput-wide p2, p0, Lh2/l3;->e:J

    .line 7
    .line 8
    iput-object p4, p0, Lh2/l3;->f:Lgy0/j;

    .line 9
    .line 10
    iput-object p5, p0, Lh2/l3;->g:Lx2/s;

    .line 11
    .line 12
    iput-object p6, p0, Lh2/l3;->h:Lh2/z1;

    .line 13
    .line 14
    iput-object p7, p0, Lh2/l3;->i:Lay0/k;

    .line 15
    .line 16
    iput-object p8, p0, Lh2/l3;->j:Lh2/e8;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Ll2/o;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ljava/lang/Number;

    .line 10
    .line 11
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    and-int/lit8 v3, v2, 0x3

    .line 16
    .line 17
    const/4 v4, 0x1

    .line 18
    const/4 v5, 0x0

    .line 19
    const/4 v6, 0x2

    .line 20
    if-eq v3, v6, :cond_0

    .line 21
    .line 22
    move v3, v4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v3, v5

    .line 25
    :goto_0
    and-int/2addr v2, v4

    .line 26
    check-cast v1, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    if-eqz v2, :cond_3

    .line 33
    .line 34
    iget-object v2, v0, Lh2/l3;->d:Li2/z;

    .line 35
    .line 36
    invoke-virtual {v2}, Li2/z;->c()Li2/y;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    move-object v7, v2

    .line 41
    check-cast v7, Li2/b0;

    .line 42
    .line 43
    iget v8, v3, Li2/y;->d:I

    .line 44
    .line 45
    iget v3, v3, Li2/y;->e:I

    .line 46
    .line 47
    invoke-static {v8, v3, v4}, Ljava/time/LocalDate;->of(III)Ljava/time/LocalDate;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    invoke-virtual {v7, v3}, Li2/b0;->e(Ljava/time/LocalDate;)Li2/c0;

    .line 52
    .line 53
    .line 54
    move-result-object v3

    .line 55
    iget v11, v3, Li2/c0;->a:I

    .line 56
    .line 57
    iget-wide v3, v0, Lh2/l3;->e:J

    .line 58
    .line 59
    invoke-virtual {v2, v3, v4}, Li2/z;->b(J)Li2/c0;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    iget v10, v3, Li2/c0;->a:I

    .line 64
    .line 65
    iget-object v3, v0, Lh2/l3;->f:Lgy0/j;

    .line 66
    .line 67
    iget v4, v3, Lgy0/h;->d:I

    .line 68
    .line 69
    sub-int v4, v10, v4

    .line 70
    .line 71
    add-int/lit8 v4, v4, -0x3

    .line 72
    .line 73
    invoke-static {v5, v4}, Ljava/lang/Math;->max(II)I

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    invoke-static {v4, v6, v1}, Ln1/x;->a(IILl2/o;)Ln1/v;

    .line 78
    .line 79
    .line 80
    move-result-object v4

    .line 81
    new-instance v5, Ln1/a;

    .line 82
    .line 83
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 84
    .line 85
    .line 86
    iget-object v14, v0, Lh2/l3;->h:Lh2/z1;

    .line 87
    .line 88
    iget-wide v6, v14, Lh2/z1;->a:J

    .line 89
    .line 90
    sget-object v8, Le3/j0;->a:Le3/i0;

    .line 91
    .line 92
    iget-object v9, v0, Lh2/l3;->g:Lx2/s;

    .line 93
    .line 94
    invoke-static {v9, v6, v7, v8}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 95
    .line 96
    .line 97
    move-result-object v6

    .line 98
    sget-object v15, Lk1/j;->f:Lk1/f;

    .line 99
    .line 100
    sget v7, Lh2/m3;->f:F

    .line 101
    .line 102
    invoke-static {v7}, Lk1/j;->g(F)Lk1/h;

    .line 103
    .line 104
    .line 105
    move-result-object v16

    .line 106
    invoke-virtual {v1, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v3

    .line 110
    invoke-virtual {v1, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    or-int/2addr v2, v3

    .line 115
    invoke-virtual {v1, v10}, Ll2/t;->e(I)Z

    .line 116
    .line 117
    .line 118
    move-result v3

    .line 119
    or-int/2addr v2, v3

    .line 120
    invoke-virtual {v1, v11}, Ll2/t;->e(I)Z

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    or-int/2addr v2, v3

    .line 125
    iget-object v3, v0, Lh2/l3;->i:Lay0/k;

    .line 126
    .line 127
    invoke-virtual {v1, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v3

    .line 131
    or-int/2addr v2, v3

    .line 132
    iget-object v3, v0, Lh2/l3;->j:Lh2/e8;

    .line 133
    .line 134
    invoke-virtual {v1, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v3

    .line 138
    or-int/2addr v2, v3

    .line 139
    invoke-virtual {v1, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v3

    .line 143
    or-int/2addr v2, v3

    .line 144
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v3

    .line 148
    if-nez v2, :cond_1

    .line 149
    .line 150
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 151
    .line 152
    if-ne v3, v2, :cond_2

    .line 153
    .line 154
    :cond_1
    new-instance v7, Lh2/j3;

    .line 155
    .line 156
    iget-object v8, v0, Lh2/l3;->f:Lgy0/j;

    .line 157
    .line 158
    iget-object v9, v0, Lh2/l3;->d:Li2/z;

    .line 159
    .line 160
    iget-object v12, v0, Lh2/l3;->i:Lay0/k;

    .line 161
    .line 162
    iget-object v13, v0, Lh2/l3;->j:Lh2/e8;

    .line 163
    .line 164
    invoke-direct/range {v7 .. v14}, Lh2/j3;-><init>(Lgy0/j;Li2/z;IILay0/k;Lh2/e8;Lh2/z1;)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v1, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    move-object v3, v7

    .line 171
    :cond_2
    check-cast v3, Lay0/k;

    .line 172
    .line 173
    const/high16 v18, 0x1b0000

    .line 174
    .line 175
    const/4 v10, 0x0

    .line 176
    const/4 v13, 0x0

    .line 177
    const/4 v14, 0x0

    .line 178
    move-object v12, v15

    .line 179
    const/4 v15, 0x0

    .line 180
    move-object/from16 v17, v1

    .line 181
    .line 182
    move-object v9, v4

    .line 183
    move-object v7, v5

    .line 184
    move-object v8, v6

    .line 185
    move-object/from16 v11, v16

    .line 186
    .line 187
    move-object/from16 v16, v3

    .line 188
    .line 189
    invoke-static/range {v7 .. v18}, Ljp/q1;->a(Ln1/a;Lx2/s;Ln1/v;Lk1/z0;Lk1/i;Lk1/g;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;I)V

    .line 190
    .line 191
    .line 192
    goto :goto_1

    .line 193
    :cond_3
    move-object/from16 v17, v1

    .line 194
    .line 195
    invoke-virtual/range {v17 .. v17}, Ll2/t;->R()V

    .line 196
    .line 197
    .line 198
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 199
    .line 200
    return-object v0
.end method
