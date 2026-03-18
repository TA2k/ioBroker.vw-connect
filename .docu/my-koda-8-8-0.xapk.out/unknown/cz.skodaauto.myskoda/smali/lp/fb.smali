.class public abstract Llp/fb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lm9/f;III)I
    .locals 4

    .line 1
    invoke-static {p1, p2}, Ljava/lang/Math;->max(II)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {v0, p3}, Ljava/lang/Math;->max(II)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/16 v1, 0x1f

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    if-gt v0, v1, :cond_0

    .line 13
    .line 14
    move v0, v2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 v0, 0x0

    .line 17
    :goto_0
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 18
    .line 19
    .line 20
    shl-int v0, v2, p1

    .line 21
    .line 22
    sub-int/2addr v0, v2

    .line 23
    shl-int v1, v2, p2

    .line 24
    .line 25
    sub-int/2addr v1, v2

    .line 26
    invoke-static {v0, v1}, Llp/oc;->c(II)I

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    shl-int/2addr v2, p3

    .line 31
    invoke-static {v3, v2}, Llp/oc;->c(II)I

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Lm9/f;->b()I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    if-ge v2, p1, :cond_1

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    invoke-virtual {p0, p1}, Lm9/f;->i(I)I

    .line 42
    .line 43
    .line 44
    move-result p1

    .line 45
    if-ne p1, v0, :cond_4

    .line 46
    .line 47
    invoke-virtual {p0}, Lm9/f;->b()I

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-ge v0, p2, :cond_2

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_2
    invoke-virtual {p0, p2}, Lm9/f;->i(I)I

    .line 55
    .line 56
    .line 57
    move-result p2

    .line 58
    add-int/2addr p1, p2

    .line 59
    if-ne p2, v1, :cond_4

    .line 60
    .line 61
    invoke-virtual {p0}, Lm9/f;->b()I

    .line 62
    .line 63
    .line 64
    move-result p2

    .line 65
    if-ge p2, p3, :cond_3

    .line 66
    .line 67
    :goto_1
    const/4 p0, -0x1

    .line 68
    return p0

    .line 69
    :cond_3
    invoke-virtual {p0, p3}, Lm9/f;->i(I)I

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    add-int/2addr p0, p1

    .line 74
    return p0

    .line 75
    :cond_4
    return p1
.end method

.method public static final b(Lpw/d;FLtw/l;FLl2/o;II)Lqw/a;
    .locals 9

    .line 1
    check-cast p4, Ll2/t;

    .line 2
    .line 3
    const v0, -0x3f6c2707

    .line 4
    .line 5
    .line 6
    invoke-virtual {p4, v0}, Ll2/t;->Z(I)V

    .line 7
    .line 8
    .line 9
    const/16 v0, 0x20

    .line 10
    .line 11
    and-int/2addr p6, v0

    .line 12
    const/4 v1, 0x0

    .line 13
    if-eqz p6, :cond_0

    .line 14
    .line 15
    int-to-float p3, v1

    .line 16
    :cond_0
    move v8, p3

    .line 17
    const p3, 0x71053196

    .line 18
    .line 19
    .line 20
    invoke-virtual {p4, p3}, Ll2/t;->Z(I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result p3

    .line 27
    invoke-virtual {p4, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result p6

    .line 31
    or-int/2addr p3, p6

    .line 32
    and-int/lit8 p6, p5, 0x70

    .line 33
    .line 34
    xor-int/lit8 p6, p6, 0x30

    .line 35
    .line 36
    if-le p6, v0, :cond_1

    .line 37
    .line 38
    invoke-virtual {p4, p1}, Ll2/t;->d(F)Z

    .line 39
    .line 40
    .line 41
    move-result p6

    .line 42
    if-nez p6, :cond_2

    .line 43
    .line 44
    :cond_1
    and-int/lit8 p5, p5, 0x30

    .line 45
    .line 46
    if-ne p5, v0, :cond_3

    .line 47
    .line 48
    :cond_2
    const/4 p5, 0x1

    .line 49
    goto :goto_0

    .line 50
    :cond_3
    move p5, v1

    .line 51
    :goto_0
    or-int/2addr p3, p5

    .line 52
    sget-object v6, Lpw/c;->e:Lpw/c;

    .line 53
    .line 54
    invoke-virtual {p4, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result p5

    .line 58
    or-int/2addr p3, p5

    .line 59
    sget-object v7, Lpw/d;->c:Lpw/d;

    .line 60
    .line 61
    invoke-virtual {p4, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result p5

    .line 65
    or-int/2addr p3, p5

    .line 66
    invoke-virtual {p4, v8}, Ll2/t;->d(F)Z

    .line 67
    .line 68
    .line 69
    move-result p5

    .line 70
    or-int/2addr p3, p5

    .line 71
    const/4 p5, 0x0

    .line 72
    invoke-virtual {p4, p5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result p5

    .line 76
    or-int/2addr p3, p5

    .line 77
    invoke-virtual {p4}, Ll2/t;->L()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p5

    .line 81
    if-nez p3, :cond_4

    .line 82
    .line 83
    sget-object p3, Ll2/n;->a:Ll2/x0;

    .line 84
    .line 85
    if-ne p5, p3, :cond_5

    .line 86
    .line 87
    :cond_4
    new-instance v2, Lqw/a;

    .line 88
    .line 89
    move-object v3, p0

    .line 90
    move v4, p1

    .line 91
    move-object v5, p2

    .line 92
    invoke-direct/range {v2 .. v8}, Lqw/a;-><init>(Lpw/d;FLtw/l;Lpw/c;Lpw/d;F)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p4, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    move-object p5, v2

    .line 99
    :cond_5
    check-cast p5, Lqw/a;

    .line 100
    .line 101
    invoke-virtual {p4, v1}, Ll2/t;->q(Z)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {p4, v1}, Ll2/t;->q(Z)V

    .line 105
    .line 106
    .line 107
    return-object p5
.end method

.method public static final c(Lpw/d;Ltw/f;Lpw/d;FLl2/o;II)Lqw/b;
    .locals 6

    .line 1
    check-cast p4, Ll2/t;

    .line 2
    .line 3
    const v0, -0x441aaccf

    .line 4
    .line 5
    .line 6
    invoke-virtual {p4, v0}, Ll2/t;->Z(I)V

    .line 7
    .line 8
    .line 9
    and-int/lit8 v0, p6, 0x8

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    sget-object p2, Lpw/d;->c:Lpw/d;

    .line 14
    .line 15
    :cond_0
    move-object v4, p2

    .line 16
    and-int/lit8 p2, p6, 0x10

    .line 17
    .line 18
    const/4 p6, 0x0

    .line 19
    if-eqz p2, :cond_1

    .line 20
    .line 21
    int-to-float p3, p6

    .line 22
    :cond_1
    move v5, p3

    .line 23
    const p2, -0x724d0642

    .line 24
    .line 25
    .line 26
    invoke-virtual {p4, p2}, Ll2/t;->Z(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {p4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p2

    .line 33
    invoke-virtual {p4, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result p3

    .line 37
    or-int/2addr p2, p3

    .line 38
    sget-object v3, Lpw/c;->e:Lpw/c;

    .line 39
    .line 40
    invoke-virtual {p4, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result p3

    .line 44
    or-int/2addr p2, p3

    .line 45
    invoke-virtual {p4, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result p3

    .line 49
    or-int/2addr p2, p3

    .line 50
    const p3, 0xe000

    .line 51
    .line 52
    .line 53
    and-int/2addr p3, p5

    .line 54
    xor-int/lit16 p3, p3, 0x6000

    .line 55
    .line 56
    const/16 v0, 0x4000

    .line 57
    .line 58
    if-le p3, v0, :cond_2

    .line 59
    .line 60
    invoke-virtual {p4, v5}, Ll2/t;->d(F)Z

    .line 61
    .line 62
    .line 63
    move-result p3

    .line 64
    if-nez p3, :cond_3

    .line 65
    .line 66
    :cond_2
    and-int/lit16 p3, p5, 0x6000

    .line 67
    .line 68
    if-ne p3, v0, :cond_4

    .line 69
    .line 70
    :cond_3
    const/4 p3, 0x1

    .line 71
    goto :goto_0

    .line 72
    :cond_4
    move p3, p6

    .line 73
    :goto_0
    or-int/2addr p2, p3

    .line 74
    const/4 p3, 0x0

    .line 75
    invoke-virtual {p4, p3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result p3

    .line 79
    or-int/2addr p2, p3

    .line 80
    invoke-virtual {p4}, Ll2/t;->L()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p3

    .line 84
    if-nez p2, :cond_5

    .line 85
    .line 86
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 87
    .line 88
    if-ne p3, p2, :cond_6

    .line 89
    .line 90
    :cond_5
    new-instance v0, Lqw/b;

    .line 91
    .line 92
    move-object v1, p0

    .line 93
    move-object v2, p1

    .line 94
    invoke-direct/range {v0 .. v5}, Lqw/b;-><init>(Lpw/d;Ltw/l;Lpw/c;Lpw/d;F)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {p4, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    move-object p3, v0

    .line 101
    :cond_6
    check-cast p3, Lqw/b;

    .line 102
    .line 103
    invoke-virtual {p4, p6}, Ll2/t;->q(Z)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {p4, p6}, Ll2/t;->q(Z)V

    .line 107
    .line 108
    .line 109
    return-object p3
.end method

.method public static d(Lm9/f;)V
    .locals 2

    .line 1
    const/4 v0, 0x3

    .line 2
    invoke-virtual {p0, v0}, Lm9/f;->t(I)V

    .line 3
    .line 4
    .line 5
    const/16 v0, 0x8

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Lm9/f;->t(I)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lm9/f;->h()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    invoke-virtual {p0}, Lm9/f;->h()Z

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x5

    .line 21
    invoke-virtual {p0, v0}, Lm9/f;->t(I)V

    .line 22
    .line 23
    .line 24
    :cond_0
    if-eqz v1, :cond_1

    .line 25
    .line 26
    const/4 v0, 0x6

    .line 27
    invoke-virtual {p0, v0}, Lm9/f;->t(I)V

    .line 28
    .line 29
    .line 30
    :cond_1
    return-void
.end method

.method public static e(Lm9/f;)V
    .locals 12

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-virtual {p0, v0}, Lm9/f;->i(I)I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    const/4 v2, 0x6

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0, v2}, Lm9/f;->t(I)V

    .line 10
    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    const/16 v3, 0x10

    .line 14
    .line 15
    const/4 v4, 0x5

    .line 16
    const/16 v5, 0x8

    .line 17
    .line 18
    invoke-static {p0, v4, v5, v3}, Llp/fb;->a(Lm9/f;III)I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    const/4 v6, 0x1

    .line 23
    add-int/2addr v3, v6

    .line 24
    const/4 v7, 0x7

    .line 25
    if-ne v1, v6, :cond_1

    .line 26
    .line 27
    mul-int/2addr v3, v7

    .line 28
    invoke-virtual {p0, v3}, Lm9/f;->t(I)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :cond_1
    if-ne v1, v0, :cond_9

    .line 33
    .line 34
    invoke-virtual {p0}, Lm9/f;->h()Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_2

    .line 39
    .line 40
    move v8, v6

    .line 41
    goto :goto_0

    .line 42
    :cond_2
    move v8, v4

    .line 43
    :goto_0
    if-eqz v1, :cond_3

    .line 44
    .line 45
    move v4, v7

    .line 46
    :cond_3
    if-eqz v1, :cond_4

    .line 47
    .line 48
    move v2, v5

    .line 49
    :cond_4
    const/4 v1, 0x0

    .line 50
    move v5, v1

    .line 51
    :goto_1
    if-ge v5, v3, :cond_9

    .line 52
    .line 53
    invoke-virtual {p0}, Lm9/f;->h()Z

    .line 54
    .line 55
    .line 56
    move-result v9

    .line 57
    const/16 v10, 0xb4

    .line 58
    .line 59
    if-eqz v9, :cond_5

    .line 60
    .line 61
    invoke-virtual {p0, v7}, Lm9/f;->t(I)V

    .line 62
    .line 63
    .line 64
    move v9, v1

    .line 65
    goto :goto_2

    .line 66
    :cond_5
    invoke-virtual {p0, v0}, Lm9/f;->i(I)I

    .line 67
    .line 68
    .line 69
    move-result v9

    .line 70
    const/4 v11, 0x3

    .line 71
    if-ne v9, v11, :cond_6

    .line 72
    .line 73
    invoke-virtual {p0, v4}, Lm9/f;->i(I)I

    .line 74
    .line 75
    .line 76
    move-result v9

    .line 77
    mul-int/2addr v9, v8

    .line 78
    if-eqz v9, :cond_6

    .line 79
    .line 80
    invoke-virtual {p0}, Lm9/f;->s()V

    .line 81
    .line 82
    .line 83
    :cond_6
    invoke-virtual {p0, v2}, Lm9/f;->i(I)I

    .line 84
    .line 85
    .line 86
    move-result v9

    .line 87
    mul-int/2addr v9, v8

    .line 88
    if-eqz v9, :cond_7

    .line 89
    .line 90
    if-eq v9, v10, :cond_7

    .line 91
    .line 92
    invoke-virtual {p0}, Lm9/f;->s()V

    .line 93
    .line 94
    .line 95
    :cond_7
    invoke-virtual {p0}, Lm9/f;->s()V

    .line 96
    .line 97
    .line 98
    :goto_2
    if-eqz v9, :cond_8

    .line 99
    .line 100
    if-eq v9, v10, :cond_8

    .line 101
    .line 102
    invoke-virtual {p0}, Lm9/f;->h()Z

    .line 103
    .line 104
    .line 105
    move-result v9

    .line 106
    if-eqz v9, :cond_8

    .line 107
    .line 108
    add-int/lit8 v5, v5, 0x1

    .line 109
    .line 110
    :cond_8
    add-int/2addr v5, v6

    .line 111
    goto :goto_1

    .line 112
    :cond_9
    return-void
.end method
