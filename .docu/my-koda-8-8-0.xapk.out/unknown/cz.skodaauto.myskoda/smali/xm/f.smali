.class public final Lxm/f;
.super Lxm/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic h:I


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;I)V
    .locals 0

    .line 1
    iput p2, p0, Lxm/f;->h:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lxm/e;-><init>(Ljava/util/List;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static j(Lhn/a;F)F
    .locals 3

    .line 1
    iget-object v0, p0, Lhn/a;->b:Ljava/lang/Object;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    iget-object v1, p0, Lhn/a;->c:Ljava/lang/Object;

    .line 6
    .line 7
    if-eqz v1, :cond_2

    .line 8
    .line 9
    iget v1, p0, Lhn/a;->i:F

    .line 10
    .line 11
    const v2, -0x358c9d09

    .line 12
    .line 13
    .line 14
    cmpl-float v1, v1, v2

    .line 15
    .line 16
    if-nez v1, :cond_0

    .line 17
    .line 18
    check-cast v0, Ljava/lang/Float;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iput v0, p0, Lhn/a;->i:F

    .line 25
    .line 26
    :cond_0
    iget v0, p0, Lhn/a;->i:F

    .line 27
    .line 28
    iget v1, p0, Lhn/a;->j:F

    .line 29
    .line 30
    cmpl-float v1, v1, v2

    .line 31
    .line 32
    if-nez v1, :cond_1

    .line 33
    .line 34
    iget-object v1, p0, Lhn/a;->c:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v1, Ljava/lang/Float;

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    iput v1, p0, Lhn/a;->j:F

    .line 43
    .line 44
    :cond_1
    iget p0, p0, Lhn/a;->j:F

    .line 45
    .line 46
    invoke-static {v0, p0, p1}, Lgn/f;->e(FFF)F

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    return p0

    .line 51
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "Missing values for keyframe."

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0
.end method


# virtual methods
.method public final e(Lhn/a;F)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lxm/f;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/high16 p0, 0x3f800000    # 1.0f

    .line 7
    .line 8
    cmpl-float p0, p2, p0

    .line 9
    .line 10
    if-nez p0, :cond_1

    .line 11
    .line 12
    iget-object p0, p1, Lhn/a;->c:Ljava/lang/Object;

    .line 13
    .line 14
    if-nez p0, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    check-cast p0, Lan/b;

    .line 18
    .line 19
    goto :goto_1

    .line 20
    :cond_1
    :goto_0
    iget-object p0, p1, Lhn/a;->b:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Lan/b;

    .line 23
    .line 24
    :goto_1
    return-object p0

    .line 25
    :pswitch_0
    iget-object p0, p1, Lhn/a;->b:Ljava/lang/Object;

    .line 26
    .line 27
    if-eqz p0, :cond_6

    .line 28
    .line 29
    iget-object v0, p1, Lhn/a;->c:Ljava/lang/Object;

    .line 30
    .line 31
    const v1, 0x2ec8fb09

    .line 32
    .line 33
    .line 34
    if-nez v0, :cond_3

    .line 35
    .line 36
    iget v0, p1, Lhn/a;->k:I

    .line 37
    .line 38
    if-ne v0, v1, :cond_2

    .line 39
    .line 40
    move-object v0, p0

    .line 41
    check-cast v0, Ljava/lang/Integer;

    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    iput v0, p1, Lhn/a;->k:I

    .line 48
    .line 49
    :cond_2
    iget v0, p1, Lhn/a;->k:I

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_3
    iget v2, p1, Lhn/a;->l:I

    .line 53
    .line 54
    if-ne v2, v1, :cond_4

    .line 55
    .line 56
    check-cast v0, Ljava/lang/Integer;

    .line 57
    .line 58
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iput v0, p1, Lhn/a;->l:I

    .line 63
    .line 64
    :cond_4
    iget v0, p1, Lhn/a;->l:I

    .line 65
    .line 66
    :goto_2
    iget v2, p1, Lhn/a;->k:I

    .line 67
    .line 68
    if-ne v2, v1, :cond_5

    .line 69
    .line 70
    check-cast p0, Ljava/lang/Integer;

    .line 71
    .line 72
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    iput p0, p1, Lhn/a;->k:I

    .line 77
    .line 78
    :cond_5
    iget p0, p1, Lhn/a;->k:I

    .line 79
    .line 80
    sget-object p1, Lgn/f;->a:Landroid/graphics/PointF;

    .line 81
    .line 82
    int-to-float p1, p0

    .line 83
    sub-int/2addr v0, p0

    .line 84
    int-to-float p0, v0

    .line 85
    mul-float/2addr p2, p0

    .line 86
    add-float/2addr p2, p1

    .line 87
    float-to-int p0, p2

    .line 88
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0

    .line 93
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 94
    .line 95
    const-string p1, "Missing values for keyframe."

    .line 96
    .line 97
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    throw p0

    .line 101
    :pswitch_1
    invoke-static {p1, p2}, Lxm/f;->j(Lhn/a;F)F

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    return-object p0

    .line 110
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lxm/f;->k(Lhn/a;F)I

    .line 111
    .line 112
    .line 113
    move-result p0

    .line 114
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    return-object p0

    .line 119
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public i()F
    .locals 1

    .line 1
    iget-object v0, p0, Lxm/e;->c:Lxm/b;

    .line 2
    .line 3
    invoke-interface {v0}, Lxm/b;->c()Lhn/a;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p0}, Lxm/e;->b()F

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    invoke-static {v0, p0}, Lxm/f;->j(Lhn/a;F)F

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public k(Lhn/a;F)I
    .locals 1

    .line 1
    iget-object p0, p1, Lhn/a;->b:Ljava/lang/Object;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    iget-object p0, p1, Lhn/a;->c:Ljava/lang/Object;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    const/high16 v0, 0x3f800000    # 1.0f

    .line 11
    .line 12
    invoke-static {p2, p0, v0}, Lgn/f;->b(FFF)F

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    iget-object p2, p1, Lhn/a;->b:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p2, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    iget-object p1, p1, Lhn/a;->c:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p1, Ljava/lang/Integer;

    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    invoke-static {p0, p2, p1}, Lkp/b9;->d(FII)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    return p0

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
