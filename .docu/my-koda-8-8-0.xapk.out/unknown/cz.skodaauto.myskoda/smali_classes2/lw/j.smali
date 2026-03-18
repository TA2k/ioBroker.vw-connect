.class public final synthetic Llw/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Ljava/lang/Double;

.field public final synthetic e:D

.field public final synthetic f:F

.field public final synthetic g:D

.field public final synthetic h:F

.field public final synthetic i:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Double;DFDFI)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llw/j;->d:Ljava/lang/Double;

    .line 5
    .line 6
    iput-wide p2, p0, Llw/j;->e:D

    .line 7
    .line 8
    iput p4, p0, Llw/j;->f:F

    .line 9
    .line 10
    iput-wide p5, p0, Llw/j;->g:D

    .line 11
    .line 12
    iput p7, p0, Llw/j;->h:F

    .line 13
    .line 14
    iput p8, p0, Llw/j;->i:I

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 6
    .line 7
    .line 8
    iget-object v2, v0, Llw/j;->d:Ljava/lang/Double;

    .line 9
    .line 10
    iget-wide v3, v0, Llw/j;->e:D

    .line 11
    .line 12
    const/4 v5, 0x1

    .line 13
    if-eqz v2, :cond_0

    .line 14
    .line 15
    invoke-virtual {v2}, Ljava/lang/Double;->doubleValue()D

    .line 16
    .line 17
    .line 18
    move-result-wide v6

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    invoke-static {v3, v4}, Ljava/lang/Math;->log10(D)D

    .line 21
    .line 22
    .line 23
    move-result-wide v6

    .line 24
    invoke-static {v6, v7}, Ljava/lang/Math;->floor(D)D

    .line 25
    .line 26
    .line 27
    move-result-wide v6

    .line 28
    int-to-double v8, v5

    .line 29
    sub-double/2addr v6, v8

    .line 30
    const-wide/high16 v8, 0x4024000000000000L    # 10.0

    .line 31
    .line 32
    invoke-static {v8, v9, v6, v7}, Ljava/lang/Math;->pow(DD)D

    .line 33
    .line 34
    .line 35
    move-result-wide v6

    .line 36
    :goto_0
    const/4 v2, 0x0

    .line 37
    iget v8, v0, Llw/j;->f:F

    .line 38
    .line 39
    cmpg-float v2, v8, v2

    .line 40
    .line 41
    const/4 v9, 0x0

    .line 42
    iget-wide v10, v0, Llw/j;->g:D

    .line 43
    .line 44
    if-nez v2, :cond_1

    .line 45
    .line 46
    goto/16 :goto_4

    .line 47
    .line 48
    :cond_1
    sub-double v12, v3, v10

    .line 49
    .line 50
    iget v2, v0, Llw/j;->h:F

    .line 51
    .line 52
    div-float/2addr v2, v8

    .line 53
    float-to-double v14, v2

    .line 54
    invoke-static {v14, v15}, Ljava/lang/Math;->floor(D)D

    .line 55
    .line 56
    .line 57
    move-result-wide v14

    .line 58
    double-to-float v2, v14

    .line 59
    float-to-double v14, v2

    .line 60
    div-double v14, v12, v14

    .line 61
    .line 62
    div-double/2addr v12, v6

    .line 63
    invoke-static {v12, v13}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    invoke-static {v12, v13}, Ljava/lang/Math;->floor(D)D

    .line 68
    .line 69
    .line 70
    move-result-wide v16

    .line 71
    cmpg-double v8, v12, v16

    .line 72
    .line 73
    const/4 v12, 0x0

    .line 74
    if-nez v8, :cond_2

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_2
    move-object v2, v12

    .line 78
    :goto_1
    if-eqz v2, :cond_7

    .line 79
    .line 80
    move v8, v5

    .line 81
    move-wide/from16 v16, v6

    .line 82
    .line 83
    invoke-virtual {v2}, Ljava/lang/Double;->doubleValue()D

    .line 84
    .line 85
    .line 86
    move-result-wide v5

    .line 87
    double-to-int v2, v5

    .line 88
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 89
    .line 90
    .line 91
    move-result-object v5

    .line 92
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 93
    .line 94
    .line 95
    move-result-object v6

    .line 96
    invoke-virtual {v5, v6}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    int-to-float v6, v2

    .line 100
    float-to-double v6, v6

    .line 101
    invoke-static {v6, v7}, Ljava/lang/Math;->sqrt(D)D

    .line 102
    .line 103
    .line 104
    move-result-wide v6

    .line 105
    double-to-float v6, v6

    .line 106
    float-to-int v6, v6

    .line 107
    const/4 v7, 0x2

    .line 108
    if-gt v7, v6, :cond_4

    .line 109
    .line 110
    :goto_2
    rem-int v8, v2, v7

    .line 111
    .line 112
    if-nez v8, :cond_3

    .line 113
    .line 114
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object v8

    .line 118
    invoke-virtual {v5, v8}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    div-int v8, v2, v7

    .line 122
    .line 123
    if-eq v8, v7, :cond_3

    .line 124
    .line 125
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 126
    .line 127
    .line 128
    move-result-object v8

    .line 129
    invoke-virtual {v5, v8}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    :cond_3
    if-eq v7, v6, :cond_4

    .line 133
    .line 134
    add-int/lit8 v7, v7, 0x1

    .line 135
    .line 136
    goto :goto_2

    .line 137
    :cond_4
    invoke-static {v5}, Lmx0/q;->m0(Ljava/util/List;)V

    .line 138
    .line 139
    .line 140
    invoke-static {v5}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 141
    .line 142
    .line 143
    move-result-object v2

    .line 144
    if-eqz v2, :cond_8

    .line 145
    .line 146
    invoke-virtual {v2, v9}, Lnx0/c;->listIterator(I)Ljava/util/ListIterator;

    .line 147
    .line 148
    .line 149
    move-result-object v2

    .line 150
    :cond_5
    move-object v5, v2

    .line 151
    check-cast v5, Lnx0/a;

    .line 152
    .line 153
    invoke-virtual {v5}, Lnx0/a;->hasNext()Z

    .line 154
    .line 155
    .line 156
    move-result v6

    .line 157
    if-eqz v6, :cond_6

    .line 158
    .line 159
    invoke-virtual {v5}, Lnx0/a;->next()Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v5

    .line 163
    move-object v6, v5

    .line 164
    check-cast v6, Ljava/lang/Number;

    .line 165
    .line 166
    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    .line 167
    .line 168
    .line 169
    move-result v6

    .line 170
    int-to-double v6, v6

    .line 171
    mul-double v6, v6, v16

    .line 172
    .line 173
    cmpl-double v6, v6, v14

    .line 174
    .line 175
    if-ltz v6, :cond_5

    .line 176
    .line 177
    move-object v12, v5

    .line 178
    :cond_6
    check-cast v12, Ljava/lang/Integer;

    .line 179
    .line 180
    if-eqz v12, :cond_8

    .line 181
    .line 182
    invoke-virtual {v12}, Ljava/lang/Number;->intValue()I

    .line 183
    .line 184
    .line 185
    move-result v2

    .line 186
    int-to-double v5, v2

    .line 187
    :goto_3
    mul-double v6, v5, v16

    .line 188
    .line 189
    goto :goto_4

    .line 190
    :cond_7
    move-wide/from16 v16, v6

    .line 191
    .line 192
    :cond_8
    div-double v14, v14, v16

    .line 193
    .line 194
    invoke-static {v14, v15}, Ljava/lang/Math;->ceil(D)D

    .line 195
    .line 196
    .line 197
    move-result-wide v5

    .line 198
    goto :goto_3

    .line 199
    :goto_4
    sub-double/2addr v3, v10

    .line 200
    div-double/2addr v3, v6

    .line 201
    double-to-int v2, v3

    .line 202
    :goto_5
    if-ge v9, v2, :cond_9

    .line 203
    .line 204
    iget v3, v0, Llw/j;->i:I

    .line 205
    .line 206
    int-to-double v3, v3

    .line 207
    add-int/lit8 v9, v9, 0x1

    .line 208
    .line 209
    int-to-double v12, v9

    .line 210
    mul-double/2addr v12, v6

    .line 211
    add-double/2addr v12, v10

    .line 212
    mul-double/2addr v12, v3

    .line 213
    invoke-static {v12, v13}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 214
    .line 215
    .line 216
    move-result-object v3

    .line 217
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    goto :goto_5

    .line 221
    :cond_9
    return-object v1
.end method
