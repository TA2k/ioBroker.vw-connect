.class public final Lf3/l;
.super Lf3/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(JLjava/lang/String;II)V
    .locals 0

    .line 1
    iput p5, p0, Lf3/l;->d:I

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3, p4}, Lf3/c;-><init>(JLjava/lang/String;I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(I)F
    .locals 0

    .line 1
    iget p0, p0, Lf3/l;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/high16 p0, 0x40000000    # 2.0f

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_0
    if-nez p1, :cond_0

    .line 10
    .line 11
    const/high16 p0, 0x42c80000    # 100.0f

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/high16 p0, 0x43000000    # 128.0f

    .line 15
    .line 16
    :goto_0
    return p0

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b(I)F
    .locals 0

    .line 1
    iget p0, p0, Lf3/l;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/high16 p0, -0x40000000    # -2.0f

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_0
    if-nez p1, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/high16 p0, -0x3d000000    # -128.0f

    .line 14
    .line 15
    :goto_0
    return p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final d(FFF)J
    .locals 2

    .line 1
    iget p0, p0, Lf3/l;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/high16 p0, -0x40000000    # -2.0f

    .line 7
    .line 8
    cmpg-float p3, p1, p0

    .line 9
    .line 10
    if-gez p3, :cond_0

    .line 11
    .line 12
    move p1, p0

    .line 13
    :cond_0
    const/high16 p3, 0x40000000    # 2.0f

    .line 14
    .line 15
    cmpl-float v0, p1, p3

    .line 16
    .line 17
    if-lez v0, :cond_1

    .line 18
    .line 19
    move p1, p3

    .line 20
    :cond_1
    cmpg-float v0, p2, p0

    .line 21
    .line 22
    if-gez v0, :cond_2

    .line 23
    .line 24
    move p2, p0

    .line 25
    :cond_2
    cmpl-float p0, p2, p3

    .line 26
    .line 27
    if-lez p0, :cond_3

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_3
    move p3, p2

    .line 31
    :goto_0
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    int-to-long p0, p0

    .line 36
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    int-to-long p2, p2

    .line 41
    const/16 v0, 0x20

    .line 42
    .line 43
    shl-long/2addr p0, v0

    .line 44
    const-wide v0, 0xffffffffL

    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    and-long/2addr p2, v0

    .line 50
    :goto_1
    or-long/2addr p0, p2

    .line 51
    return-wide p0

    .line 52
    :pswitch_0
    const/4 p0, 0x0

    .line 53
    cmpg-float p3, p1, p0

    .line 54
    .line 55
    if-gez p3, :cond_4

    .line 56
    .line 57
    move p1, p0

    .line 58
    :cond_4
    const/high16 p0, 0x42c80000    # 100.0f

    .line 59
    .line 60
    cmpl-float p3, p1, p0

    .line 61
    .line 62
    if-lez p3, :cond_5

    .line 63
    .line 64
    move p1, p0

    .line 65
    :cond_5
    const/high16 p0, -0x3d000000    # -128.0f

    .line 66
    .line 67
    cmpg-float p3, p2, p0

    .line 68
    .line 69
    if-gez p3, :cond_6

    .line 70
    .line 71
    move p2, p0

    .line 72
    :cond_6
    const/high16 p0, 0x43000000    # 128.0f

    .line 73
    .line 74
    cmpl-float p3, p2, p0

    .line 75
    .line 76
    if-lez p3, :cond_7

    .line 77
    .line 78
    move p2, p0

    .line 79
    :cond_7
    const/high16 p0, 0x41800000    # 16.0f

    .line 80
    .line 81
    add-float/2addr p1, p0

    .line 82
    const/high16 p0, 0x42e80000    # 116.0f

    .line 83
    .line 84
    div-float/2addr p1, p0

    .line 85
    const p0, 0x3b03126f    # 0.002f

    .line 86
    .line 87
    .line 88
    mul-float/2addr p2, p0

    .line 89
    add-float/2addr p2, p1

    .line 90
    const p0, 0x3e53dcb1

    .line 91
    .line 92
    .line 93
    cmpl-float p3, p2, p0

    .line 94
    .line 95
    const v0, 0x3e0d3dcb

    .line 96
    .line 97
    .line 98
    const v1, 0x3e038027

    .line 99
    .line 100
    .line 101
    if-lez p3, :cond_8

    .line 102
    .line 103
    mul-float p3, p2, p2

    .line 104
    .line 105
    mul-float/2addr p3, p2

    .line 106
    goto :goto_2

    .line 107
    :cond_8
    sub-float/2addr p2, v0

    .line 108
    mul-float p3, p2, v1

    .line 109
    .line 110
    :goto_2
    cmpl-float p0, p1, p0

    .line 111
    .line 112
    if-lez p0, :cond_9

    .line 113
    .line 114
    mul-float p0, p1, p1

    .line 115
    .line 116
    mul-float/2addr p0, p1

    .line 117
    goto :goto_3

    .line 118
    :cond_9
    sub-float/2addr p1, v0

    .line 119
    mul-float p0, p1, v1

    .line 120
    .line 121
    :goto_3
    const/4 p1, 0x0

    .line 122
    sget-object p2, Lf3/k;->e:[F

    .line 123
    .line 124
    aget p1, p2, p1

    .line 125
    .line 126
    mul-float/2addr p3, p1

    .line 127
    const/4 p1, 0x1

    .line 128
    aget p1, p2, p1

    .line 129
    .line 130
    mul-float/2addr p0, p1

    .line 131
    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 132
    .line 133
    .line 134
    move-result p1

    .line 135
    int-to-long p1, p1

    .line 136
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 137
    .line 138
    .line 139
    move-result p0

    .line 140
    int-to-long v0, p0

    .line 141
    const/16 p0, 0x20

    .line 142
    .line 143
    shl-long p0, p1, p0

    .line 144
    .line 145
    const-wide p2, 0xffffffffL

    .line 146
    .line 147
    .line 148
    .line 149
    .line 150
    and-long/2addr p2, v0

    .line 151
    goto :goto_1

    .line 152
    nop

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final e(FFF)F
    .locals 0

    .line 1
    iget p0, p0, Lf3/l;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/high16 p0, -0x40000000    # -2.0f

    .line 7
    .line 8
    cmpg-float p1, p3, p0

    .line 9
    .line 10
    if-gez p1, :cond_0

    .line 11
    .line 12
    move p3, p0

    .line 13
    :cond_0
    const/high16 p0, 0x40000000    # 2.0f

    .line 14
    .line 15
    cmpl-float p1, p3, p0

    .line 16
    .line 17
    if-lez p1, :cond_1

    .line 18
    .line 19
    move p3, p0

    .line 20
    :cond_1
    return p3

    .line 21
    :pswitch_0
    const/4 p0, 0x0

    .line 22
    cmpg-float p2, p1, p0

    .line 23
    .line 24
    if-gez p2, :cond_2

    .line 25
    .line 26
    move p1, p0

    .line 27
    :cond_2
    const/high16 p0, 0x42c80000    # 100.0f

    .line 28
    .line 29
    cmpl-float p2, p1, p0

    .line 30
    .line 31
    if-lez p2, :cond_3

    .line 32
    .line 33
    move p1, p0

    .line 34
    :cond_3
    const/high16 p0, -0x3d000000    # -128.0f

    .line 35
    .line 36
    cmpg-float p2, p3, p0

    .line 37
    .line 38
    if-gez p2, :cond_4

    .line 39
    .line 40
    move p3, p0

    .line 41
    :cond_4
    const/high16 p0, 0x43000000    # 128.0f

    .line 42
    .line 43
    cmpl-float p2, p3, p0

    .line 44
    .line 45
    if-lez p2, :cond_5

    .line 46
    .line 47
    move p3, p0

    .line 48
    :cond_5
    const/high16 p0, 0x41800000    # 16.0f

    .line 49
    .line 50
    add-float/2addr p1, p0

    .line 51
    const/high16 p0, 0x42e80000    # 116.0f

    .line 52
    .line 53
    div-float/2addr p1, p0

    .line 54
    const p0, 0x3ba3d70a    # 0.005f

    .line 55
    .line 56
    .line 57
    mul-float/2addr p3, p0

    .line 58
    sub-float/2addr p1, p3

    .line 59
    const p0, 0x3e53dcb1

    .line 60
    .line 61
    .line 62
    cmpl-float p0, p1, p0

    .line 63
    .line 64
    if-lez p0, :cond_6

    .line 65
    .line 66
    mul-float p0, p1, p1

    .line 67
    .line 68
    mul-float/2addr p0, p1

    .line 69
    goto :goto_0

    .line 70
    :cond_6
    const p0, 0x3e0d3dcb

    .line 71
    .line 72
    .line 73
    sub-float/2addr p1, p0

    .line 74
    const p0, 0x3e038027

    .line 75
    .line 76
    .line 77
    mul-float/2addr p0, p1

    .line 78
    :goto_0
    sget-object p1, Lf3/k;->e:[F

    .line 79
    .line 80
    const/4 p2, 0x2

    .line 81
    aget p1, p1, p2

    .line 82
    .line 83
    mul-float/2addr p0, p1

    .line 84
    return p0

    .line 85
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final f(FFFFLf3/c;)J
    .locals 5

    .line 1
    iget p0, p0, Lf3/l;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/high16 p0, -0x40000000    # -2.0f

    .line 7
    .line 8
    cmpg-float v0, p1, p0

    .line 9
    .line 10
    if-gez v0, :cond_0

    .line 11
    .line 12
    move p1, p0

    .line 13
    :cond_0
    const/high16 v0, 0x40000000    # 2.0f

    .line 14
    .line 15
    cmpl-float v1, p1, v0

    .line 16
    .line 17
    if-lez v1, :cond_1

    .line 18
    .line 19
    move p1, v0

    .line 20
    :cond_1
    cmpg-float v1, p2, p0

    .line 21
    .line 22
    if-gez v1, :cond_2

    .line 23
    .line 24
    move p2, p0

    .line 25
    :cond_2
    cmpl-float v1, p2, v0

    .line 26
    .line 27
    if-lez v1, :cond_3

    .line 28
    .line 29
    move p2, v0

    .line 30
    :cond_3
    cmpg-float v1, p3, p0

    .line 31
    .line 32
    if-gez v1, :cond_4

    .line 33
    .line 34
    move p3, p0

    .line 35
    :cond_4
    cmpl-float p0, p3, v0

    .line 36
    .line 37
    if-lez p0, :cond_5

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_5
    move v0, p3

    .line 41
    :goto_0
    invoke-static {p1, p2, v0, p4, p5}, Le3/j0;->b(FFFFLf3/c;)J

    .line 42
    .line 43
    .line 44
    move-result-wide p0

    .line 45
    return-wide p0

    .line 46
    :pswitch_0
    const/4 p0, 0x0

    .line 47
    sget-object v0, Lf3/k;->e:[F

    .line 48
    .line 49
    aget p0, v0, p0

    .line 50
    .line 51
    div-float/2addr p1, p0

    .line 52
    const/4 p0, 0x1

    .line 53
    aget p0, v0, p0

    .line 54
    .line 55
    div-float/2addr p2, p0

    .line 56
    const/4 p0, 0x2

    .line 57
    aget p0, v0, p0

    .line 58
    .line 59
    div-float/2addr p3, p0

    .line 60
    const p0, 0x3c111aa7

    .line 61
    .line 62
    .line 63
    cmpl-float v0, p1, p0

    .line 64
    .line 65
    const v1, 0x3e0d3dcb

    .line 66
    .line 67
    .line 68
    const v2, 0x40f92f68

    .line 69
    .line 70
    .line 71
    if-lez v0, :cond_6

    .line 72
    .line 73
    float-to-double v3, p1

    .line 74
    invoke-static {v3, v4}, Ljava/lang/Math;->cbrt(D)D

    .line 75
    .line 76
    .line 77
    move-result-wide v3

    .line 78
    double-to-float p1, v3

    .line 79
    goto :goto_1

    .line 80
    :cond_6
    mul-float/2addr p1, v2

    .line 81
    add-float/2addr p1, v1

    .line 82
    :goto_1
    cmpl-float v0, p2, p0

    .line 83
    .line 84
    if-lez v0, :cond_7

    .line 85
    .line 86
    float-to-double v3, p2

    .line 87
    invoke-static {v3, v4}, Ljava/lang/Math;->cbrt(D)D

    .line 88
    .line 89
    .line 90
    move-result-wide v3

    .line 91
    double-to-float p2, v3

    .line 92
    goto :goto_2

    .line 93
    :cond_7
    mul-float/2addr p2, v2

    .line 94
    add-float/2addr p2, v1

    .line 95
    :goto_2
    cmpl-float p0, p3, p0

    .line 96
    .line 97
    if-lez p0, :cond_8

    .line 98
    .line 99
    float-to-double v0, p3

    .line 100
    invoke-static {v0, v1}, Ljava/lang/Math;->cbrt(D)D

    .line 101
    .line 102
    .line 103
    move-result-wide v0

    .line 104
    double-to-float p0, v0

    .line 105
    goto :goto_3

    .line 106
    :cond_8
    mul-float/2addr p3, v2

    .line 107
    add-float p0, p3, v1

    .line 108
    .line 109
    :goto_3
    const/high16 p3, 0x42e80000    # 116.0f

    .line 110
    .line 111
    mul-float/2addr p3, p2

    .line 112
    const/high16 v0, 0x41800000    # 16.0f

    .line 113
    .line 114
    sub-float/2addr p3, v0

    .line 115
    const/high16 v0, 0x43fa0000    # 500.0f

    .line 116
    .line 117
    sub-float/2addr p1, p2

    .line 118
    mul-float/2addr p1, v0

    .line 119
    const/high16 v0, 0x43480000    # 200.0f

    .line 120
    .line 121
    sub-float/2addr p2, p0

    .line 122
    mul-float/2addr p2, v0

    .line 123
    const/4 p0, 0x0

    .line 124
    cmpg-float v0, p3, p0

    .line 125
    .line 126
    if-gez v0, :cond_9

    .line 127
    .line 128
    move p3, p0

    .line 129
    :cond_9
    const/high16 p0, 0x42c80000    # 100.0f

    .line 130
    .line 131
    cmpl-float v0, p3, p0

    .line 132
    .line 133
    if-lez v0, :cond_a

    .line 134
    .line 135
    move p3, p0

    .line 136
    :cond_a
    const/high16 p0, -0x3d000000    # -128.0f

    .line 137
    .line 138
    cmpg-float v0, p1, p0

    .line 139
    .line 140
    if-gez v0, :cond_b

    .line 141
    .line 142
    move p1, p0

    .line 143
    :cond_b
    const/high16 v0, 0x43000000    # 128.0f

    .line 144
    .line 145
    cmpl-float v1, p1, v0

    .line 146
    .line 147
    if-lez v1, :cond_c

    .line 148
    .line 149
    move p1, v0

    .line 150
    :cond_c
    cmpg-float v1, p2, p0

    .line 151
    .line 152
    if-gez v1, :cond_d

    .line 153
    .line 154
    move p2, p0

    .line 155
    :cond_d
    cmpl-float p0, p2, v0

    .line 156
    .line 157
    if-lez p0, :cond_e

    .line 158
    .line 159
    goto :goto_4

    .line 160
    :cond_e
    move v0, p2

    .line 161
    :goto_4
    invoke-static {p3, p1, v0, p4, p5}, Le3/j0;->b(FFFFLf3/c;)J

    .line 162
    .line 163
    .line 164
    move-result-wide p0

    .line 165
    return-wide p0

    .line 166
    nop

    .line 167
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
