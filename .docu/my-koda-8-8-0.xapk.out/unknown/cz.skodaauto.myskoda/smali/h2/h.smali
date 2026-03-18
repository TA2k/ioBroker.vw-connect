.class public final Lh2/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final synthetic a:F

.field public final synthetic b:F


# direct methods
.method public constructor <init>(FF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lh2/h;->a:F

    .line 5
    .line 6
    iput p2, p0, Lh2/h;->b:F

    .line 7
    .line 8
    return-void
.end method

.method public static final f(Ljava/util/ArrayList;Lkotlin/jvm/internal/d0;Lt3/s0;FLjava/util/ArrayList;Ljava/util/ArrayList;Lkotlin/jvm/internal/d0;Ljava/util/ArrayList;Lkotlin/jvm/internal/d0;Lkotlin/jvm/internal/d0;)V
    .locals 1

    .line 1
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iget v0, p1, Lkotlin/jvm/internal/d0;->d:I

    .line 8
    .line 9
    invoke-interface {p2, p3}, Lt4/c;->Q(F)I

    .line 10
    .line 11
    .line 12
    move-result p2

    .line 13
    add-int/2addr p2, v0

    .line 14
    iput p2, p1, Lkotlin/jvm/internal/d0;->d:I

    .line 15
    .line 16
    :cond_0
    invoke-static {p4}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    const/4 p3, 0x0

    .line 21
    invoke-virtual {p0, p3, p2}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    iget p0, p6, Lkotlin/jvm/internal/d0;->d:I

    .line 25
    .line 26
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-interface {p5, p0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    iget p0, p1, Lkotlin/jvm/internal/d0;->d:I

    .line 34
    .line 35
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-interface {p7, p0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    iget p0, p1, Lkotlin/jvm/internal/d0;->d:I

    .line 43
    .line 44
    iget p2, p6, Lkotlin/jvm/internal/d0;->d:I

    .line 45
    .line 46
    add-int/2addr p0, p2

    .line 47
    iput p0, p1, Lkotlin/jvm/internal/d0;->d:I

    .line 48
    .line 49
    iget p0, p8, Lkotlin/jvm/internal/d0;->d:I

    .line 50
    .line 51
    iget p1, p9, Lkotlin/jvm/internal/d0;->d:I

    .line 52
    .line 53
    invoke-static {p0, p1}, Ljava/lang/Math;->max(II)I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    iput p0, p8, Lkotlin/jvm/internal/d0;->d:I

    .line 58
    .line 59
    invoke-virtual {p4}, Ljava/util/ArrayList;->clear()V

    .line 60
    .line 61
    .line 62
    iput p3, p9, Lkotlin/jvm/internal/d0;->d:I

    .line 63
    .line 64
    iput p3, p6, Lkotlin/jvm/internal/d0;->d:I

    .line 65
    .line 66
    return-void
.end method


# virtual methods
.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    move-object/from16 v11, p2

    .line 6
    .line 7
    new-instance v1, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 10
    .line 11
    .line 12
    new-instance v6, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 15
    .line 16
    .line 17
    new-instance v8, Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 20
    .line 21
    .line 22
    new-instance v9, Lkotlin/jvm/internal/d0;

    .line 23
    .line 24
    invoke-direct {v9}, Ljava/lang/Object;-><init>()V

    .line 25
    .line 26
    .line 27
    new-instance v2, Lkotlin/jvm/internal/d0;

    .line 28
    .line 29
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 30
    .line 31
    .line 32
    new-instance v5, Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 35
    .line 36
    .line 37
    new-instance v10, Lkotlin/jvm/internal/d0;

    .line 38
    .line 39
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 40
    .line 41
    .line 42
    new-instance v7, Lkotlin/jvm/internal/d0;

    .line 43
    .line 44
    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    .line 45
    .line 46
    .line 47
    move-object v4, v11

    .line 48
    check-cast v4, Ljava/util/Collection;

    .line 49
    .line 50
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 51
    .line 52
    .line 53
    move-result v12

    .line 54
    const/4 v4, 0x0

    .line 55
    move v13, v4

    .line 56
    :goto_0
    if-ge v13, v12, :cond_3

    .line 57
    .line 58
    invoke-interface {v11, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v4

    .line 62
    check-cast v4, Lt3/p0;

    .line 63
    .line 64
    move-wide/from16 v14, p3

    .line 65
    .line 66
    invoke-interface {v4, v14, v15}, Lt3/p0;->L(J)Lt3/e1;

    .line 67
    .line 68
    .line 69
    move-result-object v4

    .line 70
    invoke-virtual {v5}, Ljava/util/ArrayList;->isEmpty()Z

    .line 71
    .line 72
    .line 73
    move-result v16

    .line 74
    iget v11, v0, Lh2/h;->a:F

    .line 75
    .line 76
    if-nez v16, :cond_0

    .line 77
    .line 78
    move-object/from16 v16, v1

    .line 79
    .line 80
    iget v1, v10, Lkotlin/jvm/internal/d0;->d:I

    .line 81
    .line 82
    invoke-interface {v3, v11}, Lt4/c;->Q(F)I

    .line 83
    .line 84
    .line 85
    move-result v17

    .line 86
    add-int v17, v17, v1

    .line 87
    .line 88
    iget v1, v4, Lt3/e1;->d:I

    .line 89
    .line 90
    add-int v1, v17, v1

    .line 91
    .line 92
    move-object/from16 v17, v2

    .line 93
    .line 94
    invoke-static {v14, v15}, Lt4/a;->h(J)I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    if-gt v1, v2, :cond_1

    .line 99
    .line 100
    move-object/from16 v1, v16

    .line 101
    .line 102
    move-object/from16 v2, v17

    .line 103
    .line 104
    :cond_0
    move/from16 v18, v12

    .line 105
    .line 106
    move-object v12, v4

    .line 107
    goto :goto_1

    .line 108
    :cond_1
    move-object v1, v4

    .line 109
    iget v4, v0, Lh2/h;->b:F

    .line 110
    .line 111
    move/from16 v18, v12

    .line 112
    .line 113
    move-object/from16 v2, v17

    .line 114
    .line 115
    move-object v12, v1

    .line 116
    move-object/from16 v1, v16

    .line 117
    .line 118
    invoke-static/range {v1 .. v10}, Lh2/h;->f(Ljava/util/ArrayList;Lkotlin/jvm/internal/d0;Lt3/s0;FLjava/util/ArrayList;Ljava/util/ArrayList;Lkotlin/jvm/internal/d0;Ljava/util/ArrayList;Lkotlin/jvm/internal/d0;Lkotlin/jvm/internal/d0;)V

    .line 119
    .line 120
    .line 121
    :goto_1
    invoke-virtual {v5}, Ljava/util/ArrayList;->isEmpty()Z

    .line 122
    .line 123
    .line 124
    move-result v4

    .line 125
    if-nez v4, :cond_2

    .line 126
    .line 127
    iget v4, v10, Lkotlin/jvm/internal/d0;->d:I

    .line 128
    .line 129
    invoke-interface {v3, v11}, Lt4/c;->Q(F)I

    .line 130
    .line 131
    .line 132
    move-result v11

    .line 133
    add-int/2addr v11, v4

    .line 134
    iput v11, v10, Lkotlin/jvm/internal/d0;->d:I

    .line 135
    .line 136
    :cond_2
    invoke-virtual {v5, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    iget v4, v10, Lkotlin/jvm/internal/d0;->d:I

    .line 140
    .line 141
    iget v11, v12, Lt3/e1;->d:I

    .line 142
    .line 143
    add-int/2addr v4, v11

    .line 144
    iput v4, v10, Lkotlin/jvm/internal/d0;->d:I

    .line 145
    .line 146
    iget v4, v7, Lkotlin/jvm/internal/d0;->d:I

    .line 147
    .line 148
    iget v11, v12, Lt3/e1;->e:I

    .line 149
    .line 150
    invoke-static {v4, v11}, Ljava/lang/Math;->max(II)I

    .line 151
    .line 152
    .line 153
    move-result v4

    .line 154
    iput v4, v7, Lkotlin/jvm/internal/d0;->d:I

    .line 155
    .line 156
    add-int/lit8 v13, v13, 0x1

    .line 157
    .line 158
    move-object/from16 v11, p2

    .line 159
    .line 160
    move/from16 v12, v18

    .line 161
    .line 162
    goto :goto_0

    .line 163
    :cond_3
    move-wide/from16 v14, p3

    .line 164
    .line 165
    invoke-virtual {v5}, Ljava/util/ArrayList;->isEmpty()Z

    .line 166
    .line 167
    .line 168
    move-result v4

    .line 169
    if-nez v4, :cond_4

    .line 170
    .line 171
    iget v4, v0, Lh2/h;->b:F

    .line 172
    .line 173
    invoke-static/range {v1 .. v10}, Lh2/h;->f(Ljava/util/ArrayList;Lkotlin/jvm/internal/d0;Lt3/s0;FLjava/util/ArrayList;Ljava/util/ArrayList;Lkotlin/jvm/internal/d0;Ljava/util/ArrayList;Lkotlin/jvm/internal/d0;Lkotlin/jvm/internal/d0;)V

    .line 174
    .line 175
    .line 176
    :cond_4
    iget v3, v9, Lkotlin/jvm/internal/d0;->d:I

    .line 177
    .line 178
    invoke-static {v14, v15}, Lt4/a;->j(J)I

    .line 179
    .line 180
    .line 181
    move-result v4

    .line 182
    invoke-static {v3, v4}, Ljava/lang/Math;->max(II)I

    .line 183
    .line 184
    .line 185
    move-result v4

    .line 186
    iget v2, v2, Lkotlin/jvm/internal/d0;->d:I

    .line 187
    .line 188
    invoke-static {v14, v15}, Lt4/a;->i(J)I

    .line 189
    .line 190
    .line 191
    move-result v3

    .line 192
    invoke-static {v2, v3}, Ljava/lang/Math;->max(II)I

    .line 193
    .line 194
    .line 195
    move-result v6

    .line 196
    new-instance v2, Lh2/g;

    .line 197
    .line 198
    iget v3, v0, Lh2/h;->a:F

    .line 199
    .line 200
    move-object v0, v2

    .line 201
    move-object v5, v8

    .line 202
    move-object/from16 v2, p1

    .line 203
    .line 204
    invoke-direct/range {v0 .. v5}, Lh2/g;-><init>(Ljava/util/ArrayList;Lt3/s0;FILjava/util/ArrayList;)V

    .line 205
    .line 206
    .line 207
    move-object v3, v2

    .line 208
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    .line 209
    .line 210
    invoke-interface {v3, v4, v6, v1, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    return-object v0
.end method
