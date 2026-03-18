.class public final synthetic La71/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Z

.field public final synthetic h:Lay0/a;

.field public final synthetic i:Lay0/a;

.field public final synthetic j:Lay0/a;

.field public final synthetic k:Lay0/a;

.field public final synthetic l:Lx61/b;

.field public final synthetic m:Ljava/util/Set;

.field public final synthetic n:Ljava/util/Set;

.field public final synthetic o:Z

.field public final synthetic p:Ls71/k;

.field public final synthetic q:Ljava/lang/Boolean;

.field public final synthetic r:Lay0/k;

.field public final synthetic s:Z

.field public final synthetic t:Lt71/d;

.field public final synthetic u:Ls71/h;


# direct methods
.method public synthetic constructor <init>(ZZZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lx61/b;Ljava/util/Set;Ljava/util/Set;ZLs71/k;Ljava/lang/Boolean;Lay0/k;ZLt71/d;Ls71/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, La71/g0;->d:Z

    iput-boolean p2, p0, La71/g0;->e:Z

    iput-boolean p3, p0, La71/g0;->f:Z

    iput-boolean p4, p0, La71/g0;->g:Z

    iput-object p5, p0, La71/g0;->h:Lay0/a;

    iput-object p6, p0, La71/g0;->i:Lay0/a;

    iput-object p7, p0, La71/g0;->j:Lay0/a;

    iput-object p8, p0, La71/g0;->k:Lay0/a;

    iput-object p9, p0, La71/g0;->l:Lx61/b;

    iput-object p10, p0, La71/g0;->m:Ljava/util/Set;

    iput-object p11, p0, La71/g0;->n:Ljava/util/Set;

    iput-boolean p12, p0, La71/g0;->o:Z

    iput-object p13, p0, La71/g0;->p:Ls71/k;

    iput-object p14, p0, La71/g0;->q:Ljava/lang/Boolean;

    iput-object p15, p0, La71/g0;->r:Lay0/k;

    move/from16 p1, p16

    iput-boolean p1, p0, La71/g0;->s:Z

    move-object/from16 p1, p17

    iput-object p1, p0, La71/g0;->t:Lt71/d;

    move-object/from16 p1, p18

    iput-object p1, p0, La71/g0;->u:Ls71/h;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Ljava/lang/Boolean;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 8
    .line 9
    .line 10
    move-result v5

    .line 11
    move-object/from16 v11, p2

    .line 12
    .line 13
    check-cast v11, Lay0/a;

    .line 14
    .line 15
    move-object/from16 v1, p3

    .line 16
    .line 17
    check-cast v1, Ll2/o;

    .line 18
    .line 19
    move-object/from16 v2, p4

    .line 20
    .line 21
    check-cast v2, Ljava/lang/Integer;

    .line 22
    .line 23
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    const-string v3, "onShowStopDriveBottomSheet"

    .line 28
    .line 29
    invoke-static {v11, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    and-int/lit8 v3, v2, 0x6

    .line 33
    .line 34
    if-nez v3, :cond_1

    .line 35
    .line 36
    move-object v3, v1

    .line 37
    check-cast v3, Ll2/t;

    .line 38
    .line 39
    invoke-virtual {v3, v5}, Ll2/t;->h(Z)Z

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    if-eqz v3, :cond_0

    .line 44
    .line 45
    const/4 v3, 0x4

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    const/4 v3, 0x2

    .line 48
    :goto_0
    or-int/2addr v3, v2

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    move v3, v2

    .line 51
    :goto_1
    and-int/lit8 v2, v2, 0x30

    .line 52
    .line 53
    if-nez v2, :cond_3

    .line 54
    .line 55
    move-object v2, v1

    .line 56
    check-cast v2, Ll2/t;

    .line 57
    .line 58
    invoke-virtual {v2, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-eqz v2, :cond_2

    .line 63
    .line 64
    const/16 v2, 0x20

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_2
    const/16 v2, 0x10

    .line 68
    .line 69
    :goto_2
    or-int/2addr v3, v2

    .line 70
    :cond_3
    move v9, v3

    .line 71
    and-int/lit16 v2, v9, 0x93

    .line 72
    .line 73
    const/16 v3, 0x92

    .line 74
    .line 75
    const/4 v10, 0x0

    .line 76
    if-eq v2, v3, :cond_4

    .line 77
    .line 78
    const/4 v2, 0x1

    .line 79
    goto :goto_3

    .line 80
    :cond_4
    move v2, v10

    .line 81
    :goto_3
    and-int/lit8 v3, v9, 0x1

    .line 82
    .line 83
    check-cast v1, Ll2/t;

    .line 84
    .line 85
    invoke-virtual {v1, v3, v2}, Ll2/t;->O(IZ)Z

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    if-eqz v2, :cond_7

    .line 90
    .line 91
    sget-object v18, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 92
    .line 93
    new-instance v2, La71/i0;

    .line 94
    .line 95
    iget-object v3, v0, La71/g0;->l:Lx61/b;

    .line 96
    .line 97
    iget-boolean v4, v0, La71/g0;->e:Z

    .line 98
    .line 99
    iget-boolean v6, v0, La71/g0;->s:Z

    .line 100
    .line 101
    iget-object v7, v0, La71/g0;->t:Lt71/d;

    .line 102
    .line 103
    iget-object v8, v0, La71/g0;->u:Ls71/h;

    .line 104
    .line 105
    invoke-direct/range {v2 .. v8}, La71/i0;-><init>(Lx61/b;ZZZLt71/d;Ls71/h;)V

    .line 106
    .line 107
    .line 108
    const v5, 0x2d660e7d

    .line 109
    .line 110
    .line 111
    invoke-static {v5, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 112
    .line 113
    .line 114
    move-result-object v16

    .line 115
    new-instance v2, La71/o;

    .line 116
    .line 117
    move v5, v9

    .line 118
    iget-boolean v9, v0, La71/g0;->f:Z

    .line 119
    .line 120
    invoke-direct {v2, v3, v4, v9, v7}, La71/o;-><init>(Lx61/b;ZZLt71/d;)V

    .line 121
    .line 122
    .line 123
    const v6, 0x740629fe

    .line 124
    .line 125
    .line 126
    invoke-static {v6, v1, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 127
    .line 128
    .line 129
    move-result-object v17

    .line 130
    shl-int/lit8 v2, v5, 0xc

    .line 131
    .line 132
    const/high16 v5, 0x70000

    .line 133
    .line 134
    and-int/2addr v2, v5

    .line 135
    or-int/lit8 v19, v2, 0x6

    .line 136
    .line 137
    iget-boolean v7, v0, La71/g0;->d:Z

    .line 138
    .line 139
    move v2, v10

    .line 140
    iget-boolean v10, v0, La71/g0;->g:Z

    .line 141
    .line 142
    iget-object v12, v0, La71/g0;->h:Lay0/a;

    .line 143
    .line 144
    iget-object v13, v0, La71/g0;->i:Lay0/a;

    .line 145
    .line 146
    iget-object v14, v0, La71/g0;->j:Lay0/a;

    .line 147
    .line 148
    iget-object v15, v0, La71/g0;->k:Lay0/a;

    .line 149
    .line 150
    move v8, v4

    .line 151
    move-object/from16 v6, v18

    .line 152
    .line 153
    move-object/from16 v18, v1

    .line 154
    .line 155
    invoke-static/range {v6 .. v19}, La71/b;->a(Lx2/s;ZZZZLay0/a;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Lt2/b;Lt2/b;Ll2/o;I)V

    .line 156
    .line 157
    .line 158
    move-object/from16 v18, v6

    .line 159
    .line 160
    sget-object v4, Lx61/b;->e:Lx61/b;

    .line 161
    .line 162
    if-ne v3, v4, :cond_6

    .line 163
    .line 164
    const v3, -0x6a496321

    .line 165
    .line 166
    .line 167
    invoke-virtual {v1, v3}, Ll2/t;->Y(I)V

    .line 168
    .line 169
    .line 170
    iget-object v3, v0, La71/g0;->q:Ljava/lang/Boolean;

    .line 171
    .line 172
    if-eqz v3, :cond_5

    .line 173
    .line 174
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 175
    .line 176
    .line 177
    move-result v10

    .line 178
    move/from16 v20, v10

    .line 179
    .line 180
    goto :goto_4

    .line 181
    :cond_5
    move/from16 v20, v2

    .line 182
    .line 183
    :goto_4
    const/4 v12, 0x6

    .line 184
    iget-object v13, v0, La71/g0;->r:Lay0/k;

    .line 185
    .line 186
    iget-object v14, v0, La71/g0;->m:Ljava/util/Set;

    .line 187
    .line 188
    iget-object v15, v0, La71/g0;->n:Ljava/util/Set;

    .line 189
    .line 190
    iget-object v3, v0, La71/g0;->p:Ls71/k;

    .line 191
    .line 192
    iget-boolean v0, v0, La71/g0;->o:Z

    .line 193
    .line 194
    move/from16 v19, v0

    .line 195
    .line 196
    move-object/from16 v16, v1

    .line 197
    .line 198
    move-object/from16 v17, v3

    .line 199
    .line 200
    invoke-static/range {v12 .. v20}, Lz61/a;->o(ILay0/k;Ljava/util/Set;Ljava/util/Set;Ll2/o;Ls71/k;Lx2/s;ZZ)V

    .line 201
    .line 202
    .line 203
    :goto_5
    invoke-virtual {v1, v2}, Ll2/t;->q(Z)V

    .line 204
    .line 205
    .line 206
    goto :goto_6

    .line 207
    :cond_6
    const v0, -0x6b0704c4

    .line 208
    .line 209
    .line 210
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 211
    .line 212
    .line 213
    goto :goto_5

    .line 214
    :cond_7
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 215
    .line 216
    .line 217
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 218
    .line 219
    return-object v0
.end method
