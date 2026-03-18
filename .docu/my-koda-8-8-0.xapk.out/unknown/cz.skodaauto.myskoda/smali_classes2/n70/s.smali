.class public final synthetic Ln70/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:J

.field public final synthetic e:J

.field public final synthetic f:F


# direct methods
.method public synthetic constructor <init>(JJF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Ln70/s;->d:J

    .line 5
    .line 6
    iput-wide p3, p0, Ln70/s;->e:J

    .line 7
    .line 8
    iput p5, p0, Ln70/s;->f:F

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lg3/d;

    .line 6
    .line 7
    const-string v2, "$this$Canvas"

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-interface {v1}, Lg3/d;->e()J

    .line 17
    .line 18
    .line 19
    move-result-wide v3

    .line 20
    const/16 v11, 0x20

    .line 21
    .line 22
    shr-long/2addr v3, v11

    .line 23
    long-to-int v3, v3

    .line 24
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    const/4 v4, 0x2

    .line 29
    int-to-float v12, v4

    .line 30
    div-float/2addr v3, v12

    .line 31
    invoke-interface {v1}, Lg3/d;->e()J

    .line 32
    .line 33
    .line 34
    move-result-wide v4

    .line 35
    const-wide v13, 0xffffffffL

    .line 36
    .line 37
    .line 38
    .line 39
    .line 40
    and-long/2addr v4, v13

    .line 41
    long-to-int v4, v4

    .line 42
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 43
    .line 44
    .line 45
    move-result v4

    .line 46
    invoke-virtual {v2, v3, v4}, Le3/i;->h(FF)V

    .line 47
    .line 48
    .line 49
    invoke-interface {v1}, Lg3/d;->e()J

    .line 50
    .line 51
    .line 52
    move-result-wide v3

    .line 53
    shr-long/2addr v3, v11

    .line 54
    long-to-int v3, v3

    .line 55
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    const/4 v15, 0x0

    .line 60
    invoke-virtual {v2, v3, v15}, Le3/i;->g(FF)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v2, v15, v15}, Le3/i;->g(FF)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v2}, Le3/i;->e()V

    .line 67
    .line 68
    .line 69
    const/4 v6, 0x0

    .line 70
    const/16 v7, 0x3c

    .line 71
    .line 72
    iget-wide v3, v0, Ln70/s;->d:J

    .line 73
    .line 74
    const/4 v5, 0x0

    .line 75
    invoke-static/range {v1 .. v7}, Lg3/d;->K0(Lg3/d;Le3/i;JFLg3/e;I)V

    .line 76
    .line 77
    .line 78
    invoke-static {v15}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    int-to-long v2, v2

    .line 83
    invoke-static {v15}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 84
    .line 85
    .line 86
    move-result v4

    .line 87
    int-to-long v4, v4

    .line 88
    shl-long/2addr v2, v11

    .line 89
    and-long/2addr v4, v13

    .line 90
    or-long v3, v2, v4

    .line 91
    .line 92
    invoke-interface {v1}, Lg3/d;->e()J

    .line 93
    .line 94
    .line 95
    move-result-wide v5

    .line 96
    shr-long/2addr v5, v11

    .line 97
    long-to-int v2, v5

    .line 98
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    div-float/2addr v2, v12

    .line 103
    invoke-interface {v1}, Lg3/d;->e()J

    .line 104
    .line 105
    .line 106
    move-result-wide v5

    .line 107
    and-long/2addr v5, v13

    .line 108
    long-to-int v5, v5

    .line 109
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 110
    .line 111
    .line 112
    move-result v5

    .line 113
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    int-to-long v6, v2

    .line 118
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 119
    .line 120
    .line 121
    move-result v2

    .line 122
    int-to-long v8, v2

    .line 123
    shl-long v5, v6, v11

    .line 124
    .line 125
    and-long v7, v8, v13

    .line 126
    .line 127
    or-long/2addr v5, v7

    .line 128
    const/4 v9, 0x0

    .line 129
    const/16 v10, 0x1f0

    .line 130
    .line 131
    move-object v7, v1

    .line 132
    iget-wide v1, v0, Ln70/s;->e:J

    .line 133
    .line 134
    iget v0, v0, Ln70/s;->f:F

    .line 135
    .line 136
    const/4 v8, 0x0

    .line 137
    move-object/from16 v16, v7

    .line 138
    .line 139
    move v7, v0

    .line 140
    move-object/from16 v0, v16

    .line 141
    .line 142
    invoke-static/range {v0 .. v10}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 143
    .line 144
    .line 145
    invoke-interface {v0}, Lg3/d;->e()J

    .line 146
    .line 147
    .line 148
    move-result-wide v3

    .line 149
    shr-long/2addr v3, v11

    .line 150
    long-to-int v3, v3

    .line 151
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 152
    .line 153
    .line 154
    move-result v3

    .line 155
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 156
    .line 157
    .line 158
    move-result v3

    .line 159
    int-to-long v3, v3

    .line 160
    invoke-static {v15}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 161
    .line 162
    .line 163
    move-result v5

    .line 164
    int-to-long v5, v5

    .line 165
    shl-long/2addr v3, v11

    .line 166
    and-long/2addr v5, v13

    .line 167
    or-long/2addr v3, v5

    .line 168
    invoke-interface {v0}, Lg3/d;->e()J

    .line 169
    .line 170
    .line 171
    move-result-wide v5

    .line 172
    shr-long/2addr v5, v11

    .line 173
    long-to-int v5, v5

    .line 174
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 175
    .line 176
    .line 177
    move-result v5

    .line 178
    div-float/2addr v5, v12

    .line 179
    invoke-interface {v0}, Lg3/d;->e()J

    .line 180
    .line 181
    .line 182
    move-result-wide v8

    .line 183
    and-long/2addr v8, v13

    .line 184
    long-to-int v6, v8

    .line 185
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 186
    .line 187
    .line 188
    move-result v6

    .line 189
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 190
    .line 191
    .line 192
    move-result v5

    .line 193
    int-to-long v8, v5

    .line 194
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 195
    .line 196
    .line 197
    move-result v5

    .line 198
    int-to-long v5, v5

    .line 199
    shl-long/2addr v8, v11

    .line 200
    and-long/2addr v5, v13

    .line 201
    or-long/2addr v5, v8

    .line 202
    const/4 v9, 0x0

    .line 203
    const/4 v8, 0x0

    .line 204
    invoke-static/range {v0 .. v10}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 205
    .line 206
    .line 207
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 208
    .line 209
    return-object v0
.end method
