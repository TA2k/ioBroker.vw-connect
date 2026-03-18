.class public final Lvv/s0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:F

.field public final synthetic g:Ljava/util/ArrayList;

.field public final synthetic h:Lt3/p1;

.field public final synthetic i:I

.field public final synthetic j:I

.field public final synthetic k:Ljava/util/ArrayList;

.field public final synthetic l:F

.field public final synthetic m:Lay0/k;


# direct methods
.method public constructor <init>(FLjava/util/ArrayList;Lt3/p1;IILjava/util/ArrayList;FLay0/k;)V
    .locals 0

    .line 1
    iput p1, p0, Lvv/s0;->f:F

    .line 2
    .line 3
    iput-object p2, p0, Lvv/s0;->g:Ljava/util/ArrayList;

    .line 4
    .line 5
    iput-object p3, p0, Lvv/s0;->h:Lt3/p1;

    .line 6
    .line 7
    iput p4, p0, Lvv/s0;->i:I

    .line 8
    .line 9
    iput p5, p0, Lvv/s0;->j:I

    .line 10
    .line 11
    iput-object p6, p0, Lvv/s0;->k:Ljava/util/ArrayList;

    .line 12
    .line 13
    iput p7, p0, Lvv/s0;->l:F

    .line 14
    .line 15
    iput-object p8, p0, Lvv/s0;->m:Lay0/k;

    .line 16
    .line 17
    const/4 p1, 0x1

    .line 18
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 19
    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lt3/d1;

    .line 6
    .line 7
    const-string v2, "$this$layout"

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    new-instance v2, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 15
    .line 16
    .line 17
    new-instance v3, Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 20
    .line 21
    .line 22
    iget-object v4, v0, Lvv/s0;->g:Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    iget v5, v0, Lvv/s0;->f:F

    .line 29
    .line 30
    move v7, v5

    .line 31
    const/4 v8, 0x0

    .line 32
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v9

    .line 36
    const/high16 v10, 0x40000000    # 2.0f

    .line 37
    .line 38
    if-eqz v9, :cond_4

    .line 39
    .line 40
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v9

    .line 44
    add-int/lit8 v11, v8, 0x1

    .line 45
    .line 46
    if-ltz v8, :cond_3

    .line 47
    .line 48
    check-cast v9, Ljava/util/List;

    .line 49
    .line 50
    div-float v10, v5, v10

    .line 51
    .line 52
    sub-float v12, v7, v10

    .line 53
    .line 54
    invoke-static {v12}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 55
    .line 56
    .line 57
    move-result-object v12

    .line 58
    invoke-virtual {v2, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    check-cast v9, Ljava/lang/Iterable;

    .line 62
    .line 63
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 64
    .line 65
    .line 66
    move-result-object v9

    .line 67
    move v12, v5

    .line 68
    :goto_1
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 69
    .line 70
    .line 71
    move-result v13

    .line 72
    if-eqz v13, :cond_1

    .line 73
    .line 74
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v13

    .line 78
    check-cast v13, Lt3/e1;

    .line 79
    .line 80
    if-nez v8, :cond_0

    .line 81
    .line 82
    sub-float v14, v12, v10

    .line 83
    .line 84
    invoke-static {v14}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 85
    .line 86
    .line 87
    move-result-object v14

    .line 88
    invoke-virtual {v3, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    :cond_0
    invoke-static {v12}, Lcy0/a;->i(F)I

    .line 92
    .line 93
    .line 94
    move-result v14

    .line 95
    invoke-static {v7}, Lcy0/a;->i(F)I

    .line 96
    .line 97
    .line 98
    move-result v15

    .line 99
    const/4 v6, 0x0

    .line 100
    invoke-virtual {v1, v13, v14, v15, v6}, Lt3/d1;->g(Lt3/e1;IIF)V

    .line 101
    .line 102
    .line 103
    iget v6, v0, Lvv/s0;->l:F

    .line 104
    .line 105
    add-float/2addr v6, v5

    .line 106
    add-float/2addr v12, v6

    .line 107
    goto :goto_1

    .line 108
    :cond_1
    if-nez v8, :cond_2

    .line 109
    .line 110
    sub-float/2addr v12, v10

    .line 111
    invoke-static {v12}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 112
    .line 113
    .line 114
    move-result-object v6

    .line 115
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    :cond_2
    iget-object v6, v0, Lvv/s0;->k:Ljava/util/ArrayList;

    .line 119
    .line 120
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v6

    .line 124
    check-cast v6, Ljava/lang/Number;

    .line 125
    .line 126
    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    .line 127
    .line 128
    .line 129
    move-result v6

    .line 130
    add-float/2addr v6, v5

    .line 131
    add-float/2addr v7, v6

    .line 132
    move v8, v11

    .line 133
    goto :goto_0

    .line 134
    :cond_3
    invoke-static {}, Ljp/k1;->r()V

    .line 135
    .line 136
    .line 137
    const/4 v0, 0x0

    .line 138
    throw v0

    .line 139
    :cond_4
    div-float/2addr v5, v10

    .line 140
    sub-float/2addr v7, v5

    .line 141
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 142
    .line 143
    .line 144
    move-result-object v4

    .line 145
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    new-instance v4, Lvv/a1;

    .line 149
    .line 150
    invoke-direct {v4, v2, v3}, Lvv/a1;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    .line 151
    .line 152
    .line 153
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 154
    .line 155
    new-instance v3, Lkn/i0;

    .line 156
    .line 157
    iget-object v5, v0, Lvv/s0;->m:Lay0/k;

    .line 158
    .line 159
    const/4 v6, 0x5

    .line 160
    invoke-direct {v3, v6, v5, v4}, Lkn/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    new-instance v4, Lt2/b;

    .line 164
    .line 165
    const/4 v5, 0x1

    .line 166
    const v6, -0x52b45377

    .line 167
    .line 168
    .line 169
    invoke-direct {v4, v3, v5, v6}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 170
    .line 171
    .line 172
    iget-object v3, v0, Lvv/s0;->h:Lt3/p1;

    .line 173
    .line 174
    invoke-interface {v3, v2, v4}, Lt3/p1;->C(Ljava/lang/Object;Lay0/n;)Ljava/util/List;

    .line 175
    .line 176
    .line 177
    move-result-object v2

    .line 178
    invoke-static {v2}, Lmx0/q;->i0(Ljava/util/List;)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v2

    .line 182
    check-cast v2, Lt3/p0;

    .line 183
    .line 184
    iget v3, v0, Lvv/s0;->i:I

    .line 185
    .line 186
    if-ltz v3, :cond_5

    .line 187
    .line 188
    move v4, v5

    .line 189
    goto :goto_2

    .line 190
    :cond_5
    const/4 v4, 0x0

    .line 191
    :goto_2
    iget v0, v0, Lvv/s0;->j:I

    .line 192
    .line 193
    if-ltz v0, :cond_6

    .line 194
    .line 195
    goto :goto_3

    .line 196
    :cond_6
    const/4 v5, 0x0

    .line 197
    :goto_3
    and-int/2addr v4, v5

    .line 198
    if-nez v4, :cond_7

    .line 199
    .line 200
    const-string v4, "width and height must be >= 0"

    .line 201
    .line 202
    invoke-static {v4}, Lt4/i;->a(Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    :cond_7
    invoke-static {v3, v3, v0, v0}, Lt4/b;->h(IIII)J

    .line 206
    .line 207
    .line 208
    move-result-wide v3

    .line 209
    invoke-interface {v2, v3, v4}, Lt3/p0;->L(J)Lt3/e1;

    .line 210
    .line 211
    .line 212
    move-result-object v0

    .line 213
    const/4 v2, 0x0

    .line 214
    invoke-static {v1, v0, v2, v2}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 215
    .line 216
    .line 217
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 218
    .line 219
    return-object v0
.end method
