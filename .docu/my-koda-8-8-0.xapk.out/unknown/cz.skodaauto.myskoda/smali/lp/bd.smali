.class public abstract Llp/bd;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ljava/util/List;Lw71/c;)Ljava/util/List;
    .locals 3

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Ljava/util/Collection;

    .line 3
    .line 4
    const-wide v1, 0x3fb999999999999aL    # 0.1

    .line 5
    .line 6
    .line 7
    .line 8
    .line 9
    invoke-static {p1, v0, v1, v2}, Lw71/d;->e(Lw71/c;Ljava/util/Collection;D)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    invoke-static {v0, p1}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static b(ILandroid/graphics/Rect;Landroid/graphics/Rect;Landroid/graphics/Rect;)Z
    .locals 8

    .line 1
    invoke-static {p0, p1, p2}, Llp/bd;->c(ILandroid/graphics/Rect;Landroid/graphics/Rect;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p0, p1, p3}, Llp/bd;->c(ILandroid/graphics/Rect;Landroid/graphics/Rect;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_b

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    goto/16 :goto_4

    .line 14
    .line 15
    :cond_0
    const-string v0, "direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}."

    .line 16
    .line 17
    const/16 v1, 0x82

    .line 18
    .line 19
    const/16 v2, 0x21

    .line 20
    .line 21
    const/16 v3, 0x42

    .line 22
    .line 23
    const/16 v4, 0x11

    .line 24
    .line 25
    const/4 v5, 0x1

    .line 26
    if-eq p0, v4, :cond_4

    .line 27
    .line 28
    if-eq p0, v2, :cond_3

    .line 29
    .line 30
    if-eq p0, v3, :cond_2

    .line 31
    .line 32
    if-ne p0, v1, :cond_1

    .line 33
    .line 34
    iget v6, p1, Landroid/graphics/Rect;->bottom:I

    .line 35
    .line 36
    iget v7, p3, Landroid/graphics/Rect;->top:I

    .line 37
    .line 38
    if-gt v6, v7, :cond_a

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 42
    .line 43
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_2
    iget v6, p1, Landroid/graphics/Rect;->right:I

    .line 48
    .line 49
    iget v7, p3, Landroid/graphics/Rect;->left:I

    .line 50
    .line 51
    if-gt v6, v7, :cond_a

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_3
    iget v6, p1, Landroid/graphics/Rect;->top:I

    .line 55
    .line 56
    iget v7, p3, Landroid/graphics/Rect;->bottom:I

    .line 57
    .line 58
    if-lt v6, v7, :cond_a

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_4
    iget v6, p1, Landroid/graphics/Rect;->left:I

    .line 62
    .line 63
    iget v7, p3, Landroid/graphics/Rect;->right:I

    .line 64
    .line 65
    if-lt v6, v7, :cond_a

    .line 66
    .line 67
    :goto_0
    if-eq p0, v4, :cond_a

    .line 68
    .line 69
    if-ne p0, v3, :cond_5

    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_5
    invoke-static {p0, p1, p2}, Llp/bd;->h(ILandroid/graphics/Rect;Landroid/graphics/Rect;)I

    .line 73
    .line 74
    .line 75
    move-result p2

    .line 76
    if-eq p0, v4, :cond_9

    .line 77
    .line 78
    if-eq p0, v2, :cond_8

    .line 79
    .line 80
    if-eq p0, v3, :cond_7

    .line 81
    .line 82
    if-ne p0, v1, :cond_6

    .line 83
    .line 84
    iget p0, p3, Landroid/graphics/Rect;->bottom:I

    .line 85
    .line 86
    iget p1, p1, Landroid/graphics/Rect;->bottom:I

    .line 87
    .line 88
    :goto_1
    sub-int/2addr p0, p1

    .line 89
    goto :goto_2

    .line 90
    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 91
    .line 92
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw p0

    .line 96
    :cond_7
    iget p0, p3, Landroid/graphics/Rect;->right:I

    .line 97
    .line 98
    iget p1, p1, Landroid/graphics/Rect;->right:I

    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_8
    iget p0, p1, Landroid/graphics/Rect;->top:I

    .line 102
    .line 103
    iget p1, p3, Landroid/graphics/Rect;->top:I

    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_9
    iget p0, p1, Landroid/graphics/Rect;->left:I

    .line 107
    .line 108
    iget p1, p3, Landroid/graphics/Rect;->left:I

    .line 109
    .line 110
    goto :goto_1

    .line 111
    :goto_2
    invoke-static {v5, p0}, Ljava/lang/Math;->max(II)I

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    if-ge p2, p0, :cond_b

    .line 116
    .line 117
    :cond_a
    :goto_3
    return v5

    .line 118
    :cond_b
    :goto_4
    const/4 p0, 0x0

    .line 119
    return p0
.end method

.method public static c(ILandroid/graphics/Rect;Landroid/graphics/Rect;)Z
    .locals 1

    .line 1
    const/16 v0, 0x11

    .line 2
    .line 3
    if-eq p0, v0, :cond_2

    .line 4
    .line 5
    const/16 v0, 0x21

    .line 6
    .line 7
    if-eq p0, v0, :cond_1

    .line 8
    .line 9
    const/16 v0, 0x42

    .line 10
    .line 11
    if-eq p0, v0, :cond_2

    .line 12
    .line 13
    const/16 v0, 0x82

    .line 14
    .line 15
    if-ne p0, v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 19
    .line 20
    const-string p1, "direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}."

    .line 21
    .line 22
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    :goto_0
    iget p0, p2, Landroid/graphics/Rect;->right:I

    .line 27
    .line 28
    iget v0, p1, Landroid/graphics/Rect;->left:I

    .line 29
    .line 30
    if-lt p0, v0, :cond_3

    .line 31
    .line 32
    iget p0, p2, Landroid/graphics/Rect;->left:I

    .line 33
    .line 34
    iget p1, p1, Landroid/graphics/Rect;->right:I

    .line 35
    .line 36
    if-gt p0, p1, :cond_3

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_2
    iget p0, p2, Landroid/graphics/Rect;->bottom:I

    .line 40
    .line 41
    iget v0, p1, Landroid/graphics/Rect;->top:I

    .line 42
    .line 43
    if-lt p0, v0, :cond_3

    .line 44
    .line 45
    iget p0, p2, Landroid/graphics/Rect;->top:I

    .line 46
    .line 47
    iget p1, p1, Landroid/graphics/Rect;->bottom:I

    .line 48
    .line 49
    if-gt p0, p1, :cond_3

    .line 50
    .line 51
    :goto_1
    const/4 p0, 0x1

    .line 52
    return p0

    .line 53
    :cond_3
    const/4 p0, 0x0

    .line 54
    return p0
.end method

.method public static final d(ILjava/util/List;)Llx0/l;
    .locals 1

    .line 1
    invoke-static {p0, p1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lw71/c;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    add-int/lit8 p0, p0, 0x1

    .line 10
    .line 11
    invoke-static {p0, p1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lw71/c;

    .line 16
    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    new-instance p1, Llx0/l;

    .line 20
    .line 21
    invoke-direct {p1, v0, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    return-object p1

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return-object p0
.end method

.method public static final e(ILjava/util/List;)Llx0/l;
    .locals 1

    .line 1
    invoke-static {p0, p1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lw71/c;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    add-int/lit8 p0, p0, -0x1

    .line 10
    .line 11
    invoke-static {p0, p1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lw71/c;

    .line 16
    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    new-instance p1, Llx0/l;

    .line 20
    .line 21
    invoke-direct {p1, v0, p0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    return-object p1

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    return-object p0
.end method

.method public static final f(ILjava/util/List;)Lw71/c;
    .locals 1

    .line 1
    if-ltz p0, :cond_0

    .line 2
    .line 3
    move-object v0, p1

    .line 4
    check-cast v0, Ljava/util/Collection;

    .line 5
    .line 6
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-ge p0, v0, :cond_0

    .line 11
    .line 12
    invoke-interface {p1, p0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Lw71/c;

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return-object p0
.end method

.method public static g(ILandroid/graphics/Rect;Landroid/graphics/Rect;)Z
    .locals 1

    .line 1
    const/16 v0, 0x11

    .line 2
    .line 3
    if-eq p0, v0, :cond_6

    .line 4
    .line 5
    const/16 v0, 0x21

    .line 6
    .line 7
    if-eq p0, v0, :cond_4

    .line 8
    .line 9
    const/16 v0, 0x42

    .line 10
    .line 11
    if-eq p0, v0, :cond_2

    .line 12
    .line 13
    const/16 v0, 0x82

    .line 14
    .line 15
    if-ne p0, v0, :cond_1

    .line 16
    .line 17
    iget p0, p1, Landroid/graphics/Rect;->top:I

    .line 18
    .line 19
    iget v0, p2, Landroid/graphics/Rect;->top:I

    .line 20
    .line 21
    if-lt p0, v0, :cond_0

    .line 22
    .line 23
    iget p0, p1, Landroid/graphics/Rect;->bottom:I

    .line 24
    .line 25
    if-gt p0, v0, :cond_8

    .line 26
    .line 27
    :cond_0
    iget p0, p1, Landroid/graphics/Rect;->bottom:I

    .line 28
    .line 29
    iget p1, p2, Landroid/graphics/Rect;->bottom:I

    .line 30
    .line 31
    if-ge p0, p1, :cond_8

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 35
    .line 36
    const-string p1, "direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}."

    .line 37
    .line 38
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_2
    iget p0, p1, Landroid/graphics/Rect;->left:I

    .line 43
    .line 44
    iget v0, p2, Landroid/graphics/Rect;->left:I

    .line 45
    .line 46
    if-lt p0, v0, :cond_3

    .line 47
    .line 48
    iget p0, p1, Landroid/graphics/Rect;->right:I

    .line 49
    .line 50
    if-gt p0, v0, :cond_8

    .line 51
    .line 52
    :cond_3
    iget p0, p1, Landroid/graphics/Rect;->right:I

    .line 53
    .line 54
    iget p1, p2, Landroid/graphics/Rect;->right:I

    .line 55
    .line 56
    if-ge p0, p1, :cond_8

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_4
    iget p0, p1, Landroid/graphics/Rect;->bottom:I

    .line 60
    .line 61
    iget v0, p2, Landroid/graphics/Rect;->bottom:I

    .line 62
    .line 63
    if-gt p0, v0, :cond_5

    .line 64
    .line 65
    iget p0, p1, Landroid/graphics/Rect;->top:I

    .line 66
    .line 67
    if-lt p0, v0, :cond_8

    .line 68
    .line 69
    :cond_5
    iget p0, p1, Landroid/graphics/Rect;->top:I

    .line 70
    .line 71
    iget p1, p2, Landroid/graphics/Rect;->top:I

    .line 72
    .line 73
    if-le p0, p1, :cond_8

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_6
    iget p0, p1, Landroid/graphics/Rect;->right:I

    .line 77
    .line 78
    iget v0, p2, Landroid/graphics/Rect;->right:I

    .line 79
    .line 80
    if-gt p0, v0, :cond_7

    .line 81
    .line 82
    iget p0, p1, Landroid/graphics/Rect;->left:I

    .line 83
    .line 84
    if-lt p0, v0, :cond_8

    .line 85
    .line 86
    :cond_7
    iget p0, p1, Landroid/graphics/Rect;->left:I

    .line 87
    .line 88
    iget p1, p2, Landroid/graphics/Rect;->left:I

    .line 89
    .line 90
    if-le p0, p1, :cond_8

    .line 91
    .line 92
    :goto_0
    const/4 p0, 0x1

    .line 93
    return p0

    .line 94
    :cond_8
    const/4 p0, 0x0

    .line 95
    return p0
.end method

.method public static h(ILandroid/graphics/Rect;Landroid/graphics/Rect;)I
    .locals 1

    .line 1
    const/16 v0, 0x11

    .line 2
    .line 3
    if-eq p0, v0, :cond_3

    .line 4
    .line 5
    const/16 v0, 0x21

    .line 6
    .line 7
    if-eq p0, v0, :cond_2

    .line 8
    .line 9
    const/16 v0, 0x42

    .line 10
    .line 11
    if-eq p0, v0, :cond_1

    .line 12
    .line 13
    const/16 v0, 0x82

    .line 14
    .line 15
    if-ne p0, v0, :cond_0

    .line 16
    .line 17
    iget p0, p2, Landroid/graphics/Rect;->top:I

    .line 18
    .line 19
    iget p1, p1, Landroid/graphics/Rect;->bottom:I

    .line 20
    .line 21
    :goto_0
    sub-int/2addr p0, p1

    .line 22
    goto :goto_1

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 24
    .line 25
    const-string p1, "direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}."

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    iget p0, p2, Landroid/graphics/Rect;->left:I

    .line 32
    .line 33
    iget p1, p1, Landroid/graphics/Rect;->right:I

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_2
    iget p0, p1, Landroid/graphics/Rect;->top:I

    .line 37
    .line 38
    iget p1, p2, Landroid/graphics/Rect;->bottom:I

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_3
    iget p0, p1, Landroid/graphics/Rect;->left:I

    .line 42
    .line 43
    iget p1, p2, Landroid/graphics/Rect;->right:I

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :goto_1
    const/4 p1, 0x0

    .line 47
    invoke-static {p1, p0}, Ljava/lang/Math;->max(II)I

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    return p0
.end method

.method public static i(ILandroid/graphics/Rect;Landroid/graphics/Rect;)I
    .locals 1

    .line 1
    const/16 v0, 0x11

    .line 2
    .line 3
    if-eq p0, v0, :cond_2

    .line 4
    .line 5
    const/16 v0, 0x21

    .line 6
    .line 7
    if-eq p0, v0, :cond_1

    .line 8
    .line 9
    const/16 v0, 0x42

    .line 10
    .line 11
    if-eq p0, v0, :cond_2

    .line 12
    .line 13
    const/16 v0, 0x82

    .line 14
    .line 15
    if-ne p0, v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 19
    .line 20
    const-string p1, "direction must be one of {FOCUS_UP, FOCUS_DOWN, FOCUS_LEFT, FOCUS_RIGHT}."

    .line 21
    .line 22
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    :goto_0
    iget p0, p1, Landroid/graphics/Rect;->left:I

    .line 27
    .line 28
    invoke-virtual {p1}, Landroid/graphics/Rect;->width()I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    div-int/lit8 p1, p1, 0x2

    .line 33
    .line 34
    add-int/2addr p1, p0

    .line 35
    iget p0, p2, Landroid/graphics/Rect;->left:I

    .line 36
    .line 37
    invoke-virtual {p2}, Landroid/graphics/Rect;->width()I

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    div-int/lit8 p2, p2, 0x2

    .line 42
    .line 43
    add-int/2addr p2, p0

    .line 44
    sub-int/2addr p1, p2

    .line 45
    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    return p0

    .line 50
    :cond_2
    iget p0, p1, Landroid/graphics/Rect;->top:I

    .line 51
    .line 52
    invoke-virtual {p1}, Landroid/graphics/Rect;->height()I

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    div-int/lit8 p1, p1, 0x2

    .line 57
    .line 58
    add-int/2addr p1, p0

    .line 59
    iget p0, p2, Landroid/graphics/Rect;->top:I

    .line 60
    .line 61
    invoke-virtual {p2}, Landroid/graphics/Rect;->height()I

    .line 62
    .line 63
    .line 64
    move-result p2

    .line 65
    div-int/lit8 p2, p2, 0x2

    .line 66
    .line 67
    add-int/2addr p2, p0

    .line 68
    sub-int/2addr p1, p2

    .line 69
    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    return p0
.end method
