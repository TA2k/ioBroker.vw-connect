.class public final synthetic Lh2/j3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lgy0/j;Li2/z;IILay0/k;Lh2/e8;Lh2/z1;)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    iput v0, p0, Lh2/j3;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/j3;->g:Ljava/lang/Object;

    iput-object p2, p0, Lh2/j3;->h:Ljava/lang/Object;

    iput p3, p0, Lh2/j3;->e:I

    iput p4, p0, Lh2/j3;->f:I

    iput-object p5, p0, Lh2/j3;->i:Ljava/lang/Object;

    iput-object p6, p0, Lh2/j3;->j:Ljava/lang/Object;

    iput-object p7, p0, Lh2/j3;->k:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lt3/e1;Lt3/e1;Lt3/s0;IILjava/lang/Integer;Ljava/lang/Integer;)V
    .locals 1

    .line 2
    const/4 v0, 0x1

    iput v0, p0, Lh2/j3;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh2/j3;->g:Ljava/lang/Object;

    iput-object p2, p0, Lh2/j3;->h:Ljava/lang/Object;

    iput-object p3, p0, Lh2/j3;->i:Ljava/lang/Object;

    iput p4, p0, Lh2/j3;->e:I

    iput p5, p0, Lh2/j3;->f:I

    iput-object p6, p0, Lh2/j3;->j:Ljava/lang/Object;

    iput-object p7, p0, Lh2/j3;->k:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/j3;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, v0, Lh2/j3;->k:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v4, v0, Lh2/j3;->j:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v5, v0, Lh2/j3;->i:Ljava/lang/Object;

    .line 12
    .line 13
    iget-object v6, v0, Lh2/j3;->h:Ljava/lang/Object;

    .line 14
    .line 15
    iget-object v7, v0, Lh2/j3;->g:Ljava/lang/Object;

    .line 16
    .line 17
    const/4 v8, 0x0

    .line 18
    packed-switch v1, :pswitch_data_0

    .line 19
    .line 20
    .line 21
    check-cast v7, Lt3/e1;

    .line 22
    .line 23
    check-cast v6, Lt3/e1;

    .line 24
    .line 25
    check-cast v5, Lt3/s0;

    .line 26
    .line 27
    check-cast v4, Ljava/lang/Integer;

    .line 28
    .line 29
    check-cast v3, Ljava/lang/Integer;

    .line 30
    .line 31
    move-object/from16 v1, p1

    .line 32
    .line 33
    check-cast v1, Lt3/d1;

    .line 34
    .line 35
    iget v9, v0, Lh2/j3;->f:I

    .line 36
    .line 37
    if-eqz v7, :cond_1

    .line 38
    .line 39
    if-eqz v6, :cond_1

    .line 40
    .line 41
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    if-ne v4, v3, :cond_0

    .line 56
    .line 57
    sget v8, Lh2/wa;->c:F

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_0
    sget v8, Lh2/wa;->d:F

    .line 61
    .line 62
    :goto_0
    invoke-interface {v5, v8}, Lt4/c;->Q(F)I

    .line 63
    .line 64
    .line 65
    move-result v8

    .line 66
    sget v10, Lk2/c0;->b:F

    .line 67
    .line 68
    invoke-interface {v5, v10}, Lt4/c;->Q(F)I

    .line 69
    .line 70
    .line 71
    move-result v10

    .line 72
    add-int/2addr v10, v8

    .line 73
    iget v8, v6, Lt3/e1;->e:I

    .line 74
    .line 75
    sget-wide v11, Lh2/wa;->e:J

    .line 76
    .line 77
    invoke-interface {v5, v11, v12}, Lt4/c;->z0(J)I

    .line 78
    .line 79
    .line 80
    move-result v5

    .line 81
    add-int/2addr v5, v8

    .line 82
    sub-int/2addr v5, v4

    .line 83
    iget v4, v7, Lt3/e1;->d:I

    .line 84
    .line 85
    iget v0, v0, Lh2/j3;->e:I

    .line 86
    .line 87
    sub-int v4, v0, v4

    .line 88
    .line 89
    div-int/lit8 v4, v4, 0x2

    .line 90
    .line 91
    sub-int/2addr v9, v3

    .line 92
    sub-int/2addr v9, v10

    .line 93
    invoke-static {v1, v7, v4, v9}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 94
    .line 95
    .line 96
    iget v3, v6, Lt3/e1;->d:I

    .line 97
    .line 98
    sub-int/2addr v0, v3

    .line 99
    div-int/lit8 v0, v0, 0x2

    .line 100
    .line 101
    sub-int/2addr v9, v5

    .line 102
    invoke-static {v1, v6, v0, v9}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 103
    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_1
    if-eqz v7, :cond_2

    .line 107
    .line 108
    sget v0, Lh2/wa;->a:F

    .line 109
    .line 110
    iget v0, v7, Lt3/e1;->e:I

    .line 111
    .line 112
    sub-int/2addr v9, v0

    .line 113
    div-int/lit8 v9, v9, 0x2

    .line 114
    .line 115
    invoke-static {v1, v7, v8, v9}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 116
    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_2
    if-eqz v6, :cond_3

    .line 120
    .line 121
    sget v0, Lh2/wa;->a:F

    .line 122
    .line 123
    iget v0, v6, Lt3/e1;->e:I

    .line 124
    .line 125
    sub-int/2addr v9, v0

    .line 126
    div-int/lit8 v9, v9, 0x2

    .line 127
    .line 128
    invoke-static {v1, v6, v8, v9}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 129
    .line 130
    .line 131
    :cond_3
    :goto_1
    return-object v2

    .line 132
    :pswitch_0
    move-object v11, v7

    .line 133
    check-cast v11, Lgy0/j;

    .line 134
    .line 135
    move-object v12, v6

    .line 136
    check-cast v12, Li2/z;

    .line 137
    .line 138
    move-object v15, v5

    .line 139
    check-cast v15, Lay0/k;

    .line 140
    .line 141
    move-object/from16 v16, v4

    .line 142
    .line 143
    check-cast v16, Lh2/e8;

    .line 144
    .line 145
    move-object/from16 v17, v3

    .line 146
    .line 147
    check-cast v17, Lh2/z1;

    .line 148
    .line 149
    move-object/from16 v1, p1

    .line 150
    .line 151
    check-cast v1, Ln1/g;

    .line 152
    .line 153
    const-string v3, "<this>"

    .line 154
    .line 155
    invoke-static {v11, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    instance-of v3, v11, Ljava/util/Collection;

    .line 159
    .line 160
    if-eqz v3, :cond_4

    .line 161
    .line 162
    move-object v3, v11

    .line 163
    check-cast v3, Ljava/util/Collection;

    .line 164
    .line 165
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 166
    .line 167
    .line 168
    move-result v3

    .line 169
    goto :goto_3

    .line 170
    :cond_4
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 171
    .line 172
    .line 173
    move-result-object v3

    .line 174
    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 175
    .line 176
    .line 177
    move-result v4

    .line 178
    if-eqz v4, :cond_6

    .line 179
    .line 180
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    add-int/lit8 v8, v8, 0x1

    .line 184
    .line 185
    if-ltz v8, :cond_5

    .line 186
    .line 187
    goto :goto_2

    .line 188
    :cond_5
    invoke-static {}, Ljp/k1;->q()V

    .line 189
    .line 190
    .line 191
    const/4 v0, 0x0

    .line 192
    throw v0

    .line 193
    :cond_6
    move v3, v8

    .line 194
    :goto_3
    new-instance v10, Lh2/k3;

    .line 195
    .line 196
    iget v13, v0, Lh2/j3;->e:I

    .line 197
    .line 198
    iget v14, v0, Lh2/j3;->f:I

    .line 199
    .line 200
    invoke-direct/range {v10 .. v17}, Lh2/k3;-><init>(Lgy0/j;Li2/z;IILay0/k;Lh2/e8;Lh2/z1;)V

    .line 201
    .line 202
    .line 203
    new-instance v0, Lt2/b;

    .line 204
    .line 205
    const/4 v4, 0x1

    .line 206
    const v5, 0x2835c752

    .line 207
    .line 208
    .line 209
    invoke-direct {v0, v10, v4, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 210
    .line 211
    .line 212
    iget-object v1, v1, Ln1/g;->d:Lbb/g0;

    .line 213
    .line 214
    new-instance v4, Ln1/f;

    .line 215
    .line 216
    sget-object v5, Ln1/g;->e:Lmo0/a;

    .line 217
    .line 218
    sget-object v6, Ln1/q;->d:Ln1/q;

    .line 219
    .line 220
    invoke-direct {v4, v5, v6, v0}, Ln1/f;-><init>(Lay0/n;Lay0/k;Lt2/b;)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v1, v3, v4}, Lbb/g0;->b(ILo1/q;)V

    .line 224
    .line 225
    .line 226
    return-object v2

    .line 227
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
