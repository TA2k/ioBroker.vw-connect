.class public final Lxm/h;
.super Lxm/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic h:I

.field public final i:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/util/List;I)V
    .locals 2

    .line 1
    iput p2, p0, Lxm/h;->h:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, p1}, Lxm/e;-><init>(Ljava/util/List;)V

    .line 7
    .line 8
    .line 9
    const/4 p2, 0x0

    .line 10
    move v0, p2

    .line 11
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-ge p2, v1, :cond_1

    .line 16
    .line 17
    invoke-interface {p1, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Lhn/a;

    .line 22
    .line 23
    iget-object v1, v1, Lhn/a;->b:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast v1, Lcn/c;

    .line 26
    .line 27
    if-eqz v1, :cond_0

    .line 28
    .line 29
    iget-object v1, v1, Lcn/c;->b:[I

    .line 30
    .line 31
    array-length v1, v1

    .line 32
    invoke-static {v0, v1}, Ljava/lang/Math;->max(II)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    :cond_0
    add-int/lit8 p2, p2, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    new-instance p1, Lcn/c;

    .line 40
    .line 41
    new-array p2, v0, [F

    .line 42
    .line 43
    new-array v0, v0, [I

    .line 44
    .line 45
    invoke-direct {p1, p2, v0}, Lcn/c;-><init>([F[I)V

    .line 46
    .line 47
    .line 48
    iput-object p1, p0, Lxm/h;->i:Ljava/lang/Object;

    .line 49
    .line 50
    return-void

    .line 51
    :pswitch_0
    invoke-direct {p0, p1}, Lxm/e;-><init>(Ljava/util/List;)V

    .line 52
    .line 53
    .line 54
    new-instance p1, Lhn/b;

    .line 55
    .line 56
    const/high16 p2, 0x3f800000    # 1.0f

    .line 57
    .line 58
    invoke-direct {p1, p2, p2}, Lhn/b;-><init>(FF)V

    .line 59
    .line 60
    .line 61
    iput-object p1, p0, Lxm/h;->i:Ljava/lang/Object;

    .line 62
    .line 63
    return-void

    .line 64
    :pswitch_1
    invoke-direct {p0, p1}, Lxm/e;-><init>(Ljava/util/List;)V

    .line 65
    .line 66
    .line 67
    new-instance p1, Landroid/graphics/PointF;

    .line 68
    .line 69
    invoke-direct {p1}, Landroid/graphics/PointF;-><init>()V

    .line 70
    .line 71
    .line 72
    iput-object p1, p0, Lxm/h;->i:Ljava/lang/Object;

    .line 73
    .line 74
    return-void

    .line 75
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final e(Lhn/a;F)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lxm/h;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lxm/h;->i:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lhn/b;

    .line 9
    .line 10
    iget-object v0, p1, Lhn/a;->b:Ljava/lang/Object;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    iget-object p1, p1, Lhn/a;->c:Ljava/lang/Object;

    .line 15
    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    check-cast v0, Lhn/b;

    .line 19
    .line 20
    check-cast p1, Lhn/b;

    .line 21
    .line 22
    iget v1, v0, Lhn/b;->a:F

    .line 23
    .line 24
    iget v2, p1, Lhn/b;->a:F

    .line 25
    .line 26
    invoke-static {v1, v2, p2}, Lgn/f;->e(FFF)F

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    iget v0, v0, Lhn/b;->b:F

    .line 31
    .line 32
    iget p1, p1, Lhn/b;->b:F

    .line 33
    .line 34
    invoke-static {v0, p1, p2}, Lgn/f;->e(FFF)F

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    iput v1, p0, Lhn/b;->a:F

    .line 39
    .line 40
    iput p1, p0, Lhn/b;->b:F

    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "Missing values for keyframe."

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :pswitch_0
    invoke-virtual {p0, p1, p2, p2}, Lxm/h;->i(Lhn/a;FF)Landroid/graphics/PointF;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :pswitch_1
    iget-object p0, p0, Lxm/h;->i:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p0, Lcn/c;

    .line 59
    .line 60
    iget-object v0, p1, Lhn/a;->b:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v0, Lcn/c;

    .line 63
    .line 64
    iget-object p1, p1, Lhn/a;->c:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast p1, Lcn/c;

    .line 67
    .line 68
    iget-object v1, p0, Lcn/c;->b:[I

    .line 69
    .line 70
    iget-object v2, p0, Lcn/c;->a:[F

    .line 71
    .line 72
    invoke-virtual {v0, p1}, Lcn/c;->equals(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    iget-object v4, v0, Lcn/c;->b:[I

    .line 77
    .line 78
    if-eqz v3, :cond_1

    .line 79
    .line 80
    invoke-virtual {p0, v0}, Lcn/c;->a(Lcn/c;)V

    .line 81
    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_1
    const/4 v3, 0x0

    .line 85
    cmpg-float v3, p2, v3

    .line 86
    .line 87
    if-gtz v3, :cond_2

    .line 88
    .line 89
    invoke-virtual {p0, v0}, Lcn/c;->a(Lcn/c;)V

    .line 90
    .line 91
    .line 92
    goto :goto_2

    .line 93
    :cond_2
    const/high16 v3, 0x3f800000    # 1.0f

    .line 94
    .line 95
    cmpl-float v3, p2, v3

    .line 96
    .line 97
    if-ltz v3, :cond_3

    .line 98
    .line 99
    invoke-virtual {p0, p1}, Lcn/c;->a(Lcn/c;)V

    .line 100
    .line 101
    .line 102
    goto :goto_2

    .line 103
    :cond_3
    array-length v3, v4

    .line 104
    iget-object v5, p1, Lcn/c;->b:[I

    .line 105
    .line 106
    array-length v6, v5

    .line 107
    if-ne v3, v6, :cond_6

    .line 108
    .line 109
    const/4 v3, 0x0

    .line 110
    :goto_0
    array-length v6, v4

    .line 111
    if-ge v3, v6, :cond_4

    .line 112
    .line 113
    iget-object v6, v0, Lcn/c;->a:[F

    .line 114
    .line 115
    aget v6, v6, v3

    .line 116
    .line 117
    iget-object v7, p1, Lcn/c;->a:[F

    .line 118
    .line 119
    aget v7, v7, v3

    .line 120
    .line 121
    invoke-static {v6, v7, p2}, Lgn/f;->e(FFF)F

    .line 122
    .line 123
    .line 124
    move-result v6

    .line 125
    aput v6, v2, v3

    .line 126
    .line 127
    aget v6, v4, v3

    .line 128
    .line 129
    aget v7, v5, v3

    .line 130
    .line 131
    invoke-static {p2, v6, v7}, Lkp/b9;->d(FII)I

    .line 132
    .line 133
    .line 134
    move-result v6

    .line 135
    aput v6, v1, v3

    .line 136
    .line 137
    add-int/lit8 v3, v3, 0x1

    .line 138
    .line 139
    goto :goto_0

    .line 140
    :cond_4
    array-length p1, v4

    .line 141
    :goto_1
    array-length p2, v2

    .line 142
    if-ge p1, p2, :cond_5

    .line 143
    .line 144
    array-length p2, v4

    .line 145
    add-int/lit8 p2, p2, -0x1

    .line 146
    .line 147
    aget p2, v2, p2

    .line 148
    .line 149
    aput p2, v2, p1

    .line 150
    .line 151
    array-length p2, v4

    .line 152
    add-int/lit8 p2, p2, -0x1

    .line 153
    .line 154
    aget p2, v1, p2

    .line 155
    .line 156
    aput p2, v1, p1

    .line 157
    .line 158
    add-int/lit8 p1, p1, 0x1

    .line 159
    .line 160
    goto :goto_1

    .line 161
    :cond_5
    :goto_2
    return-object p0

    .line 162
    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 163
    .line 164
    new-instance p1, Ljava/lang/StringBuilder;

    .line 165
    .line 166
    const-string p2, "Cannot interpolate between gradients. Lengths vary ("

    .line 167
    .line 168
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    array-length p2, v4

    .line 172
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 173
    .line 174
    .line 175
    const-string p2, " vs "

    .line 176
    .line 177
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    array-length p2, v5

    .line 181
    const-string v0, ")"

    .line 182
    .line 183
    invoke-static {p2, v0, p1}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object p1

    .line 187
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    throw p0

    .line 191
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public bridge synthetic f(Lhn/a;FFF)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lxm/h;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2, p3, p4}, Lxm/e;->f(Lhn/a;FFF)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    invoke-virtual {p0, p1, p3, p4}, Lxm/h;->i(Lhn/a;FF)Landroid/graphics/PointF;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public i(Lhn/a;FF)Landroid/graphics/PointF;
    .locals 3

    .line 1
    iget-object p0, p0, Lxm/h;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/graphics/PointF;

    .line 4
    .line 5
    iget-object v0, p1, Lhn/a;->b:Ljava/lang/Object;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object p1, p1, Lhn/a;->c:Ljava/lang/Object;

    .line 10
    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    check-cast v0, Landroid/graphics/PointF;

    .line 14
    .line 15
    check-cast p1, Landroid/graphics/PointF;

    .line 16
    .line 17
    iget v1, v0, Landroid/graphics/PointF;->x:F

    .line 18
    .line 19
    iget v2, p1, Landroid/graphics/PointF;->x:F

    .line 20
    .line 21
    invoke-static {v2, v1, p2, v1}, La7/g0;->b(FFFF)F

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    iget v0, v0, Landroid/graphics/PointF;->y:F

    .line 26
    .line 27
    iget p1, p1, Landroid/graphics/PointF;->y:F

    .line 28
    .line 29
    invoke-static {p1, v0, p3, v0}, La7/g0;->b(FFFF)F

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    invoke-virtual {p0, p2, p1}, Landroid/graphics/PointF;->set(FF)V

    .line 34
    .line 35
    .line 36
    return-object p0

    .line 37
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    const-string p1, "Missing values for keyframe."

    .line 40
    .line 41
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0
.end method
