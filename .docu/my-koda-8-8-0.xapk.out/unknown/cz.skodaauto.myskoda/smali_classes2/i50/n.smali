.class public final synthetic Li50/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:Lt4/m;

.field public final synthetic f:Li91/r2;

.field public final synthetic g:Lh50/v;

.field public final synthetic h:Ll2/b1;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Ll2/b1;

.field public final synthetic k:Lay0/k;

.field public final synthetic l:Lay0/k;

.field public final synthetic m:Lay0/k;

.field public final synthetic n:Lay0/a;

.field public final synthetic o:Ll2/b1;

.field public final synthetic p:Lay0/a;


# direct methods
.method public synthetic constructor <init>(FLt4/m;Li91/r2;Lh50/v;Ll2/b1;Lay0/a;Ll2/b1;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Ll2/b1;Lay0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Li50/n;->d:F

    .line 5
    .line 6
    iput-object p2, p0, Li50/n;->e:Lt4/m;

    .line 7
    .line 8
    iput-object p3, p0, Li50/n;->f:Li91/r2;

    .line 9
    .line 10
    iput-object p4, p0, Li50/n;->g:Lh50/v;

    .line 11
    .line 12
    iput-object p5, p0, Li50/n;->h:Ll2/b1;

    .line 13
    .line 14
    iput-object p6, p0, Li50/n;->i:Lay0/a;

    .line 15
    .line 16
    iput-object p7, p0, Li50/n;->j:Ll2/b1;

    .line 17
    .line 18
    iput-object p8, p0, Li50/n;->k:Lay0/k;

    .line 19
    .line 20
    iput-object p9, p0, Li50/n;->l:Lay0/k;

    .line 21
    .line 22
    iput-object p10, p0, Li50/n;->m:Lay0/k;

    .line 23
    .line 24
    iput-object p11, p0, Li50/n;->n:Lay0/a;

    .line 25
    .line 26
    iput-object p12, p0, Li50/n;->o:Ll2/b1;

    .line 27
    .line 28
    iput-object p13, p0, Li50/n;->p:Lay0/a;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v5, p1

    .line 4
    .line 5
    check-cast v5, Lk1/z0;

    .line 6
    .line 7
    move-object/from16 v1, p2

    .line 8
    .line 9
    check-cast v1, Ll2/o;

    .line 10
    .line 11
    move-object/from16 v2, p3

    .line 12
    .line 13
    check-cast v2, Ljava/lang/Integer;

    .line 14
    .line 15
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    const-string v3, "paddingValues"

    .line 20
    .line 21
    invoke-static {v5, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    and-int/lit8 v3, v2, 0x6

    .line 25
    .line 26
    if-nez v3, :cond_1

    .line 27
    .line 28
    move-object v3, v1

    .line 29
    check-cast v3, Ll2/t;

    .line 30
    .line 31
    invoke-virtual {v3, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-eqz v3, :cond_0

    .line 36
    .line 37
    const/4 v3, 0x4

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v3, 0x2

    .line 40
    :goto_0
    or-int/2addr v2, v3

    .line 41
    :cond_1
    and-int/lit8 v3, v2, 0x13

    .line 42
    .line 43
    const/16 v4, 0x12

    .line 44
    .line 45
    const/4 v6, 0x1

    .line 46
    if-eq v3, v4, :cond_2

    .line 47
    .line 48
    move v3, v6

    .line 49
    goto :goto_1

    .line 50
    :cond_2
    const/4 v3, 0x0

    .line 51
    :goto_1
    and-int/2addr v2, v6

    .line 52
    move-object v11, v1

    .line 53
    check-cast v11, Ll2/t;

    .line 54
    .line 55
    invoke-virtual {v11, v2, v3}, Ll2/t;->O(IZ)Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-eqz v1, :cond_7

    .line 60
    .line 61
    iget v1, v0, Li50/n;->d:F

    .line 62
    .line 63
    invoke-virtual {v11, v1}, Ll2/t;->d(F)Z

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    iget-object v3, v0, Li50/n;->e:Lt4/m;

    .line 68
    .line 69
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 70
    .line 71
    .line 72
    move-result v4

    .line 73
    invoke-virtual {v11, v4}, Ll2/t;->e(I)Z

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    or-int/2addr v2, v4

    .line 78
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v4

    .line 82
    iget-object v13, v0, Li50/n;->h:Ll2/b1;

    .line 83
    .line 84
    sget-object v12, Ll2/n;->a:Ll2/x0;

    .line 85
    .line 86
    if-nez v2, :cond_3

    .line 87
    .line 88
    if-ne v4, v12, :cond_4

    .line 89
    .line 90
    :cond_3
    new-instance v4, Lg1/j3;

    .line 91
    .line 92
    const/4 v2, 0x1

    .line 93
    invoke-direct {v4, v1, v13, v3, v2}, Lg1/j3;-><init>(FLjava/lang/Object;Ljava/lang/Object;I)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {v11, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    :cond_4
    check-cast v4, Lay0/k;

    .line 100
    .line 101
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 102
    .line 103
    invoke-static {v14, v4}, Landroidx/compose/ui/layout/a;->d(Lx2/s;Lay0/k;)Lx2/s;

    .line 104
    .line 105
    .line 106
    move-result-object v18

    .line 107
    new-instance v1, Ld00/f;

    .line 108
    .line 109
    iget-object v2, v0, Li50/n;->g:Lh50/v;

    .line 110
    .line 111
    iget-object v3, v0, Li50/n;->f:Li91/r2;

    .line 112
    .line 113
    iget-object v4, v0, Li50/n;->j:Ll2/b1;

    .line 114
    .line 115
    iget-object v6, v0, Li50/n;->k:Lay0/k;

    .line 116
    .line 117
    iget-object v7, v0, Li50/n;->l:Lay0/k;

    .line 118
    .line 119
    iget-object v8, v0, Li50/n;->m:Lay0/k;

    .line 120
    .line 121
    iget-object v9, v0, Li50/n;->n:Lay0/a;

    .line 122
    .line 123
    iget-object v10, v0, Li50/n;->o:Ll2/b1;

    .line 124
    .line 125
    invoke-direct/range {v1 .. v10}, Ld00/f;-><init>(Lh50/v;Li91/r2;Ll2/b1;Lk1/z0;Lay0/k;Lay0/k;Lay0/k;Lay0/a;Ll2/b1;)V

    .line 126
    .line 127
    .line 128
    const v4, -0x79263cb5

    .line 129
    .line 130
    .line 131
    invoke-static {v4, v11, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 132
    .line 133
    .line 134
    move-result-object v6

    .line 135
    move-object v1, v12

    .line 136
    new-instance v12, Laj0/b;

    .line 137
    .line 138
    const/16 v17, 0x12

    .line 139
    .line 140
    iget-object v15, v0, Li50/n;->i:Lay0/a;

    .line 141
    .line 142
    iget-object v0, v0, Li50/n;->p:Lay0/a;

    .line 143
    .line 144
    move-object/from16 v16, v0

    .line 145
    .line 146
    move-object v0, v14

    .line 147
    move-object v14, v2

    .line 148
    invoke-direct/range {v12 .. v17}, Laj0/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 149
    .line 150
    .line 151
    move-object v4, v15

    .line 152
    const v5, 0x3d624a3e

    .line 153
    .line 154
    .line 155
    invoke-static {v5, v11, v12}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 156
    .line 157
    .line 158
    move-result-object v9

    .line 159
    move-object v10, v11

    .line 160
    const/16 v11, 0xe06

    .line 161
    .line 162
    const/4 v12, 0x0

    .line 163
    move-object v8, v3

    .line 164
    move-object/from16 v7, v18

    .line 165
    .line 166
    invoke-static/range {v6 .. v12}, Li91/j0;->p0(Lt2/b;Lx2/s;Li91/r2;Lt2/b;Ll2/o;II)V

    .line 167
    .line 168
    .line 169
    iget-object v6, v2, Lh50/v;->v:Ler0/g;

    .line 170
    .line 171
    invoke-interface {v13}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v2

    .line 175
    check-cast v2, Lk1/z0;

    .line 176
    .line 177
    invoke-interface {v2}, Lk1/z0;->d()F

    .line 178
    .line 179
    .line 180
    move-result v16

    .line 181
    const/16 v18, 0x0

    .line 182
    .line 183
    const/16 v19, 0xd

    .line 184
    .line 185
    const/4 v15, 0x0

    .line 186
    const/16 v17, 0x0

    .line 187
    .line 188
    move-object v14, v0

    .line 189
    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 190
    .line 191
    .line 192
    move-result-object v7

    .line 193
    invoke-virtual {v10, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result v0

    .line 197
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v2

    .line 201
    if-nez v0, :cond_5

    .line 202
    .line 203
    if-ne v2, v1, :cond_6

    .line 204
    .line 205
    :cond_5
    new-instance v2, Lha0/f;

    .line 206
    .line 207
    const/4 v0, 0x2

    .line 208
    invoke-direct {v2, v4, v0}, Lha0/f;-><init>(Lay0/a;I)V

    .line 209
    .line 210
    .line 211
    invoke-virtual {v10, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 212
    .line 213
    .line 214
    :cond_6
    move-object v8, v2

    .line 215
    check-cast v8, Lay0/a;

    .line 216
    .line 217
    const/4 v11, 0x0

    .line 218
    const/16 v12, 0x8

    .line 219
    .line 220
    const/4 v9, 0x0

    .line 221
    invoke-static/range {v6 .. v12}, Lgr0/a;->e(Ler0/g;Lx2/s;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 222
    .line 223
    .line 224
    goto :goto_2

    .line 225
    :cond_7
    move-object v10, v11

    .line 226
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 227
    .line 228
    .line 229
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 230
    .line 231
    return-object v0
.end method
