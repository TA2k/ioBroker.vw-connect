.class public final synthetic Lxf0/n3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I

.field public final synthetic f:J

.field public final synthetic g:F

.field public final synthetic h:F

.field public final synthetic i:J

.field public final synthetic j:J


# direct methods
.method public synthetic constructor <init>(IIJFFJJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lxf0/n3;->d:I

    .line 5
    .line 6
    iput p2, p0, Lxf0/n3;->e:I

    .line 7
    .line 8
    iput-wide p3, p0, Lxf0/n3;->f:J

    .line 9
    .line 10
    iput p5, p0, Lxf0/n3;->g:F

    .line 11
    .line 12
    iput p6, p0, Lxf0/n3;->h:F

    .line 13
    .line 14
    iput-wide p7, p0, Lxf0/n3;->i:J

    .line 15
    .line 16
    iput-wide p9, p0, Lxf0/n3;->j:J

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

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
    iget v9, v0, Lxf0/n3;->d:I

    .line 13
    .line 14
    iget v10, v0, Lxf0/n3;->e:I

    .line 15
    .line 16
    const/16 v11, 0x20

    .line 17
    .line 18
    const/4 v12, 0x2

    .line 19
    const-wide v13, 0xffffffffL

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    if-ge v9, v10, :cond_0

    .line 25
    .line 26
    invoke-interface {v1}, Lg3/d;->e()J

    .line 27
    .line 28
    .line 29
    move-result-wide v2

    .line 30
    and-long/2addr v2, v13

    .line 31
    long-to-int v2, v2

    .line 32
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    int-to-float v3, v12

    .line 37
    div-float/2addr v2, v3

    .line 38
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    int-to-long v3, v3

    .line 43
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    int-to-long v5, v2

    .line 48
    shl-long v2, v3, v11

    .line 49
    .line 50
    and-long v4, v5, v13

    .line 51
    .line 52
    or-long/2addr v2, v4

    .line 53
    :goto_0
    move-wide/from16 v18, v2

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_0
    const-wide/16 v2, 0x0

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :goto_1
    invoke-interface {v1}, Lg3/d;->e()J

    .line 60
    .line 61
    .line 62
    move-result-wide v2

    .line 63
    shr-long/2addr v2, v11

    .line 64
    long-to-int v2, v2

    .line 65
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    int-to-float v3, v10

    .line 70
    div-float v23, v2, v3

    .line 71
    .line 72
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    new-instance v15, Ld3/c;

    .line 77
    .line 78
    int-to-float v3, v9

    .line 79
    mul-float v3, v3, v23

    .line 80
    .line 81
    invoke-interface {v1}, Lg3/d;->e()J

    .line 82
    .line 83
    .line 84
    move-result-wide v4

    .line 85
    and-long/2addr v4, v13

    .line 86
    long-to-int v4, v4

    .line 87
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 88
    .line 89
    .line 90
    move-result v4

    .line 91
    const/4 v5, 0x0

    .line 92
    invoke-direct {v15, v5, v5, v3, v4}, Ld3/c;-><init>(FFFF)V

    .line 93
    .line 94
    .line 95
    const-wide/16 v16, 0x0

    .line 96
    .line 97
    const/16 v22, 0x12

    .line 98
    .line 99
    move-wide/from16 v20, v18

    .line 100
    .line 101
    invoke-static/range {v15 .. v22}, Ljp/df;->b(Ld3/c;JJJI)Ld3/d;

    .line 102
    .line 103
    .line 104
    move-result-object v3

    .line 105
    invoke-static {v2, v3}, Le3/i;->c(Le3/i;Ld3/d;)V

    .line 106
    .line 107
    .line 108
    const/4 v6, 0x0

    .line 109
    const/16 v7, 0x3c

    .line 110
    .line 111
    iget-wide v3, v0, Lxf0/n3;->f:J

    .line 112
    .line 113
    invoke-static/range {v1 .. v7}, Lg3/d;->K0(Lg3/d;Le3/i;JFLg3/e;I)V

    .line 114
    .line 115
    .line 116
    const/4 v2, 0x0

    .line 117
    :goto_2
    if-ge v2, v10, :cond_2

    .line 118
    .line 119
    add-int/lit8 v15, v2, 0x1

    .line 120
    .line 121
    int-to-float v3, v15

    .line 122
    mul-float v3, v3, v23

    .line 123
    .line 124
    iget v4, v0, Lxf0/n3;->g:F

    .line 125
    .line 126
    invoke-interface {v1, v4}, Lt4/c;->w0(F)F

    .line 127
    .line 128
    .line 129
    move-result v5

    .line 130
    int-to-float v6, v12

    .line 131
    div-float/2addr v5, v6

    .line 132
    sub-float/2addr v3, v5

    .line 133
    iget v5, v0, Lxf0/n3;->h:F

    .line 134
    .line 135
    invoke-interface {v1, v5}, Lt4/c;->w0(F)F

    .line 136
    .line 137
    .line 138
    move-result v5

    .line 139
    sub-float/2addr v3, v5

    .line 140
    invoke-interface {v1}, Lg3/d;->e()J

    .line 141
    .line 142
    .line 143
    move-result-wide v7

    .line 144
    and-long/2addr v7, v13

    .line 145
    long-to-int v5, v7

    .line 146
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 147
    .line 148
    .line 149
    move-result v5

    .line 150
    div-float/2addr v5, v6

    .line 151
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 152
    .line 153
    .line 154
    move-result v3

    .line 155
    int-to-long v6, v3

    .line 156
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 157
    .line 158
    .line 159
    move-result v3

    .line 160
    move/from16 p1, v11

    .line 161
    .line 162
    int-to-long v11, v3

    .line 163
    shl-long v5, v6, p1

    .line 164
    .line 165
    and-long v7, v11, v13

    .line 166
    .line 167
    or-long/2addr v5, v7

    .line 168
    if-ge v2, v9, :cond_1

    .line 169
    .line 170
    iget-wide v2, v0, Lxf0/n3;->i:J

    .line 171
    .line 172
    goto :goto_3

    .line 173
    :cond_1
    iget-wide v2, v0, Lxf0/n3;->j:J

    .line 174
    .line 175
    :goto_3
    invoke-interface {v1, v4}, Lt4/c;->w0(F)F

    .line 176
    .line 177
    .line 178
    move-result v4

    .line 179
    const/4 v7, 0x0

    .line 180
    const/16 v8, 0x78

    .line 181
    .line 182
    invoke-static/range {v1 .. v8}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 183
    .line 184
    .line 185
    move/from16 v11, p1

    .line 186
    .line 187
    move v2, v15

    .line 188
    const/4 v12, 0x2

    .line 189
    goto :goto_2

    .line 190
    :cond_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 191
    .line 192
    return-object v0
.end method
