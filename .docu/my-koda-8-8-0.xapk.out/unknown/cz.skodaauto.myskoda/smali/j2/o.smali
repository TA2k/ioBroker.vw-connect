.class public final Lj2/o;
.super Lv3/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo3/a;


# instance fields
.field public final A:Ll2/f1;

.field public t:Z

.field public u:Lay0/a;

.field public v:Z

.field public w:Lj2/p;

.field public x:F

.field public final y:Lo3/g;

.field public final z:Ll2/f1;


# direct methods
.method public constructor <init>(ZLay0/a;Lj2/p;F)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lv3/n;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lj2/o;->t:Z

    .line 5
    .line 6
    iput-object p2, p0, Lj2/o;->u:Lay0/a;

    .line 7
    .line 8
    const/4 p1, 0x1

    .line 9
    iput-boolean p1, p0, Lj2/o;->v:Z

    .line 10
    .line 11
    iput-object p3, p0, Lj2/o;->w:Lj2/p;

    .line 12
    .line 13
    iput p4, p0, Lj2/o;->x:F

    .line 14
    .line 15
    new-instance p1, Lo3/g;

    .line 16
    .line 17
    const/4 p2, 0x0

    .line 18
    invoke-direct {p1, p0, p2}, Lo3/g;-><init>(Lo3/a;Lo3/d;)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lj2/o;->y:Lo3/g;

    .line 22
    .line 23
    new-instance p1, Ll2/f1;

    .line 24
    .line 25
    const/4 p2, 0x0

    .line 26
    invoke-direct {p1, p2}, Ll2/f1;-><init>(F)V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lj2/o;->z:Ll2/f1;

    .line 30
    .line 31
    new-instance p1, Ll2/f1;

    .line 32
    .line 33
    invoke-direct {p1, p2}, Ll2/f1;-><init>(F)V

    .line 34
    .line 35
    .line 36
    iput-object p1, p0, Lj2/o;->A:Ll2/f1;

    .line 37
    .line 38
    return-void
.end method

.method public static final a1(Lj2/o;Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p1, Lj2/k;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Lj2/k;

    .line 10
    .line 11
    iget v1, v0, Lj2/k;->f:I

    .line 12
    .line 13
    const/high16 v2, -0x80000000

    .line 14
    .line 15
    and-int v3, v1, v2

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    sub-int/2addr v1, v2

    .line 20
    iput v1, v0, Lj2/k;->f:I

    .line 21
    .line 22
    :goto_0
    move-object v6, v0

    .line 23
    goto :goto_1

    .line 24
    :cond_0
    new-instance v0, Lj2/k;

    .line 25
    .line 26
    invoke-direct {v0, p0, p1}, Lj2/k;-><init>(Lj2/o;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :goto_1
    iget-object p1, v6, Lj2/k;->d:Ljava/lang/Object;

    .line 31
    .line 32
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    iget v1, v6, Lj2/k;->f:I

    .line 35
    .line 36
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    const/4 v2, 0x1

    .line 39
    if-eqz v1, :cond_2

    .line 40
    .line 41
    if-ne v1, v2, :cond_1

    .line 42
    .line 43
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    .line 45
    .line 46
    goto :goto_3

    .line 47
    :catchall_0
    move-exception v0

    .line 48
    move-object p1, v0

    .line 49
    goto :goto_4

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    :try_start_1
    iget-object p1, p0, Lj2/o;->w:Lj2/p;

    .line 62
    .line 63
    iput v2, v6, Lj2/k;->f:I

    .line 64
    .line 65
    iget-object v1, p1, Lj2/p;->a:Lc1/c;

    .line 66
    .line 67
    new-instance v2, Ljava/lang/Float;

    .line 68
    .line 69
    const/high16 p1, 0x3f800000    # 1.0f

    .line 70
    .line 71
    invoke-direct {v2, p1}, Ljava/lang/Float;-><init>(F)V

    .line 72
    .line 73
    .line 74
    const/4 v5, 0x0

    .line 75
    const/16 v7, 0xe

    .line 76
    .line 77
    const/4 v3, 0x0

    .line 78
    const/4 v4, 0x0

    .line 79
    invoke-static/range {v1 .. v7}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 83
    if-ne p1, v0, :cond_3

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_3
    move-object p1, v8

    .line 87
    :goto_2
    if-ne p1, v0, :cond_4

    .line 88
    .line 89
    return-object v0

    .line 90
    :cond_4
    :goto_3
    iget-boolean p1, p0, Lx2/r;->q:Z

    .line 91
    .line 92
    if-eqz p1, :cond_5

    .line 93
    .line 94
    invoke-virtual {p0}, Lj2/o;->d1()I

    .line 95
    .line 96
    .line 97
    move-result p1

    .line 98
    int-to-float p1, p1

    .line 99
    invoke-virtual {p0, p1}, Lj2/o;->f1(F)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p0}, Lj2/o;->d1()I

    .line 103
    .line 104
    .line 105
    move-result p1

    .line 106
    int-to-float p1, p1

    .line 107
    invoke-virtual {p0, p1}, Lj2/o;->g1(F)V

    .line 108
    .line 109
    .line 110
    :cond_5
    return-object v8

    .line 111
    :goto_4
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 112
    .line 113
    if-eqz v0, :cond_6

    .line 114
    .line 115
    invoke-virtual {p0}, Lj2/o;->d1()I

    .line 116
    .line 117
    .line 118
    move-result v0

    .line 119
    int-to-float v0, v0

    .line 120
    invoke-virtual {p0, v0}, Lj2/o;->f1(F)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {p0}, Lj2/o;->d1()I

    .line 124
    .line 125
    .line 126
    move-result v0

    .line 127
    int-to-float v0, v0

    .line 128
    invoke-virtual {p0, v0}, Lj2/o;->g1(F)V

    .line 129
    .line 130
    .line 131
    :cond_6
    throw p1
.end method


# virtual methods
.method public final M0()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final P(IJJ)J
    .locals 1

    .line 1
    iget-object p2, p0, Lj2/o;->w:Lj2/p;

    .line 2
    .line 3
    iget-object p2, p2, Lj2/p;->a:Lc1/c;

    .line 4
    .line 5
    invoke-virtual {p2}, Lc1/c;->e()Z

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    if-eqz p2, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-boolean p2, p0, Lj2/o;->v:Z

    .line 13
    .line 14
    if-nez p2, :cond_1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    const/4 p2, 0x1

    .line 18
    if-ne p1, p2, :cond_2

    .line 19
    .line 20
    invoke-virtual {p0, p4, p5}, Lj2/o;->c1(J)J

    .line 21
    .line 22
    .line 23
    move-result-wide p1

    .line 24
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 25
    .line 26
    .line 27
    move-result-object p3

    .line 28
    new-instance p4, Lj2/l;

    .line 29
    .line 30
    const/4 p5, 0x1

    .line 31
    const/4 v0, 0x0

    .line 32
    invoke-direct {p4, p0, v0, p5}, Lj2/l;-><init>(Lj2/o;Lkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    const/4 p0, 0x3

    .line 36
    invoke-static {p3, v0, v0, p4, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 37
    .line 38
    .line 39
    return-wide p1

    .line 40
    :cond_2
    :goto_0
    const-wide/16 p0, 0x0

    .line 41
    .line 42
    return-wide p0
.end method

.method public final P0()V
    .locals 4

    .line 1
    iget-object v0, p0, Lj2/o;->y:Lo3/g;

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lx2/r;->L0()Lvy0/b0;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    new-instance v1, Lj2/l;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-direct {v1, p0, v3, v2}, Lj2/l;-><init>(Lj2/o;Lkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    const/4 v2, 0x3

    .line 18
    invoke-static {v0, v3, v3, v1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 19
    .line 20
    .line 21
    iget-boolean v0, p0, Lj2/o;->t:Z

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    invoke-virtual {p0}, Lj2/o;->d1()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    int-to-float v0, v0

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v0, 0x0

    .line 32
    :goto_0
    invoke-virtual {p0, v0}, Lj2/o;->g1(F)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public final b1(Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p1, Lj2/j;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lj2/j;

    .line 7
    .line 8
    iget v1, v0, Lj2/j;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lj2/j;->f:I

    .line 18
    .line 19
    :goto_0
    move-object v6, v0

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v0, Lj2/j;

    .line 22
    .line 23
    invoke-direct {v0, p0, p1}, Lj2/j;-><init>(Lj2/o;Lrx0/c;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :goto_1
    iget-object p1, v6, Lj2/j;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v1, v6, Lj2/j;->f:I

    .line 32
    .line 33
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    const/4 v2, 0x1

    .line 36
    const/4 v9, 0x0

    .line 37
    if-eqz v1, :cond_2

    .line 38
    .line 39
    if-ne v1, v2, :cond_1

    .line 40
    .line 41
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    .line 43
    .line 44
    goto :goto_3

    .line 45
    :catchall_0
    move-exception v0

    .line 46
    move-object p1, v0

    .line 47
    goto :goto_4

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :try_start_1
    iget-object p1, p0, Lj2/o;->w:Lj2/p;

    .line 60
    .line 61
    iput v2, v6, Lj2/j;->f:I

    .line 62
    .line 63
    iget-object v1, p1, Lj2/p;->a:Lc1/c;

    .line 64
    .line 65
    new-instance v2, Ljava/lang/Float;

    .line 66
    .line 67
    invoke-direct {v2, v9}, Ljava/lang/Float;-><init>(F)V

    .line 68
    .line 69
    .line 70
    const/4 v5, 0x0

    .line 71
    const/16 v7, 0xe

    .line 72
    .line 73
    const/4 v3, 0x0

    .line 74
    const/4 v4, 0x0

    .line 75
    invoke-static/range {v1 .. v7}, Lc1/c;->b(Lc1/c;Ljava/lang/Object;Lc1/j;Ljava/lang/Float;Lay0/k;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 79
    if-ne p1, v0, :cond_3

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_3
    move-object p1, v8

    .line 83
    :goto_2
    if-ne p1, v0, :cond_4

    .line 84
    .line 85
    return-object v0

    .line 86
    :cond_4
    :goto_3
    invoke-virtual {p0, v9}, Lj2/o;->f1(F)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p0, v9}, Lj2/o;->g1(F)V

    .line 90
    .line 91
    .line 92
    return-object v8

    .line 93
    :goto_4
    invoke-virtual {p0, v9}, Lj2/o;->f1(F)V

    .line 94
    .line 95
    .line 96
    invoke-virtual {p0, v9}, Lj2/o;->g1(F)V

    .line 97
    .line 98
    .line 99
    throw p1
.end method

.method public final c1(J)J
    .locals 8

    .line 1
    iget-boolean v0, p0, Lj2/o;->t:Z

    .line 2
    .line 3
    const-wide v1, 0xffffffffL

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    const/4 v3, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    move p2, v3

    .line 12
    goto :goto_1

    .line 13
    :cond_0
    iget-object v0, p0, Lj2/o;->A:Ll2/f1;

    .line 14
    .line 15
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    and-long/2addr p1, v1

    .line 20
    long-to-int p1, p1

    .line 21
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    add-float/2addr p1, v4

    .line 26
    cmpg-float p2, p1, v3

    .line 27
    .line 28
    if-gez p2, :cond_1

    .line 29
    .line 30
    move p1, v3

    .line 31
    :cond_1
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    sub-float p2, p1, p2

    .line 36
    .line 37
    invoke-virtual {p0, p1}, Lj2/o;->f1(F)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    const/high16 v4, 0x3f000000    # 0.5f

    .line 45
    .line 46
    mul-float/2addr p1, v4

    .line 47
    invoke-virtual {p0}, Lj2/o;->d1()I

    .line 48
    .line 49
    .line 50
    move-result v5

    .line 51
    int-to-float v5, v5

    .line 52
    cmpg-float p1, p1, v5

    .line 53
    .line 54
    if-gtz p1, :cond_2

    .line 55
    .line 56
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    mul-float/2addr p1, v4

    .line 61
    goto :goto_0

    .line 62
    :cond_2
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 63
    .line 64
    .line 65
    move-result p1

    .line 66
    mul-float/2addr p1, v4

    .line 67
    invoke-virtual {p0}, Lj2/o;->d1()I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    int-to-float v0, v0

    .line 72
    div-float/2addr p1, v0

    .line 73
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 74
    .line 75
    .line 76
    move-result p1

    .line 77
    const/high16 v0, 0x3f800000    # 1.0f

    .line 78
    .line 79
    sub-float/2addr p1, v0

    .line 80
    const/high16 v0, 0x40000000    # 2.0f

    .line 81
    .line 82
    invoke-static {p1, v3, v0}, Lkp/r9;->d(FFF)F

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    float-to-double v4, p1

    .line 87
    const/4 v0, 0x2

    .line 88
    int-to-double v6, v0

    .line 89
    invoke-static {v4, v5, v6, v7}, Ljava/lang/Math;->pow(DD)D

    .line 90
    .line 91
    .line 92
    move-result-wide v4

    .line 93
    double-to-float v0, v4

    .line 94
    const/4 v4, 0x4

    .line 95
    int-to-float v4, v4

    .line 96
    div-float/2addr v0, v4

    .line 97
    sub-float/2addr p1, v0

    .line 98
    invoke-virtual {p0}, Lj2/o;->d1()I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    int-to-float v0, v0

    .line 103
    mul-float/2addr v0, p1

    .line 104
    invoke-virtual {p0}, Lj2/o;->d1()I

    .line 105
    .line 106
    .line 107
    move-result p1

    .line 108
    int-to-float p1, p1

    .line 109
    add-float/2addr p1, v0

    .line 110
    :goto_0
    invoke-virtual {p0, p1}, Lj2/o;->g1(F)V

    .line 111
    .line 112
    .line 113
    :goto_1
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 114
    .line 115
    .line 116
    move-result p0

    .line 117
    int-to-long p0, p0

    .line 118
    invoke-static {p2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 119
    .line 120
    .line 121
    move-result p2

    .line 122
    int-to-long v3, p2

    .line 123
    const/16 p2, 0x20

    .line 124
    .line 125
    shl-long/2addr p0, p2

    .line 126
    and-long v0, v3, v1

    .line 127
    .line 128
    or-long/2addr p0, v0

    .line 129
    return-wide p0
.end method

.method public final d1()I
    .locals 1

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v0, v0, Lv3/h0;->A:Lt4/c;

    .line 6
    .line 7
    iget p0, p0, Lj2/o;->x:F

    .line 8
    .line 9
    invoke-interface {v0, p0}, Lt4/c;->Q(F)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final e1(FLrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lj2/n;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lj2/n;

    .line 7
    .line 8
    iget v1, v0, Lj2/n;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lj2/n;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj2/n;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lj2/n;-><init>(Lj2/o;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lj2/n;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj2/n;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    iget p1, v0, Lj2/n;->d:F

    .line 38
    .line 39
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-boolean p2, p0, Lj2/o;->t:Z

    .line 55
    .line 56
    if-eqz p2, :cond_3

    .line 57
    .line 58
    new-instance p0, Ljava/lang/Float;

    .line 59
    .line 60
    invoke-direct {p0, v4}, Ljava/lang/Float;-><init>(F)V

    .line 61
    .line 62
    .line 63
    return-object p0

    .line 64
    :cond_3
    iget-object p2, p0, Lj2/o;->A:Ll2/f1;

    .line 65
    .line 66
    invoke-virtual {p2}, Ll2/f1;->o()F

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    const/high16 v5, 0x3f000000    # 0.5f

    .line 71
    .line 72
    mul-float/2addr v2, v5

    .line 73
    invoke-virtual {p0}, Lj2/o;->d1()I

    .line 74
    .line 75
    .line 76
    move-result v5

    .line 77
    int-to-float v5, v5

    .line 78
    cmpl-float v2, v2, v5

    .line 79
    .line 80
    if-lez v2, :cond_4

    .line 81
    .line 82
    iget-object v2, p0, Lj2/o;->u:Lay0/a;

    .line 83
    .line 84
    invoke-interface {v2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    :cond_4
    invoke-virtual {p2}, Ll2/f1;->o()F

    .line 88
    .line 89
    .line 90
    move-result p2

    .line 91
    cmpg-float p2, p2, v4

    .line 92
    .line 93
    if-nez p2, :cond_5

    .line 94
    .line 95
    :goto_1
    move p1, v4

    .line 96
    goto :goto_2

    .line 97
    :cond_5
    cmpg-float p2, p1, v4

    .line 98
    .line 99
    if-gez p2, :cond_6

    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_6
    :goto_2
    iput p1, v0, Lj2/n;->d:F

    .line 103
    .line 104
    iput v3, v0, Lj2/n;->g:I

    .line 105
    .line 106
    invoke-virtual {p0, v0}, Lj2/o;->b1(Lrx0/c;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p2

    .line 110
    if-ne p2, v1, :cond_7

    .line 111
    .line 112
    return-object v1

    .line 113
    :cond_7
    :goto_3
    invoke-virtual {p0, v4}, Lj2/o;->f1(F)V

    .line 114
    .line 115
    .line 116
    new-instance p0, Ljava/lang/Float;

    .line 117
    .line 118
    invoke-direct {p0, p1}, Ljava/lang/Float;-><init>(F)V

    .line 119
    .line 120
    .line 121
    return-object p0
.end method

.method public final f1(F)V
    .locals 0

    .line 1
    iget-object p0, p0, Lj2/o;->A:Ll2/f1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/f1;->p(F)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final g1(F)V
    .locals 0

    .line 1
    iget-object p0, p0, Lj2/o;->z:Ll2/f1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/f1;->p(F)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final y0(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p3, Lj2/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lj2/m;

    .line 7
    .line 8
    iget v1, v0, Lj2/m;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lj2/m;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj2/m;

    .line 21
    .line 22
    check-cast p3, Lrx0/c;

    .line 23
    .line 24
    invoke-direct {v0, p0, p3}, Lj2/m;-><init>(Lj2/o;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p3, v0, Lj2/m;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, v0, Lj2/m;->f:I

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v3, :cond_1

    .line 37
    .line 38
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    invoke-static {p1, p2}, Lt4/q;->c(J)F

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    iput v3, v0, Lj2/m;->f:I

    .line 58
    .line 59
    invoke-virtual {p0, p1, v0}, Lj2/o;->e1(FLrx0/c;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p3

    .line 63
    if-ne p3, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    :goto_1
    check-cast p3, Ljava/lang/Number;

    .line 67
    .line 68
    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    const/4 p1, 0x0

    .line 73
    invoke-static {p1, p0}, Lkp/g9;->a(FF)J

    .line 74
    .line 75
    .line 76
    move-result-wide p0

    .line 77
    new-instance p2, Lt4/q;

    .line 78
    .line 79
    invoke-direct {p2, p0, p1}, Lt4/q;-><init>(J)V

    .line 80
    .line 81
    .line 82
    return-object p2
.end method

.method public final z(IJ)J
    .locals 2

    .line 1
    iget-object v0, p0, Lj2/o;->w:Lj2/p;

    .line 2
    .line 3
    iget-object v0, v0, Lj2/p;->a:Lc1/c;

    .line 4
    .line 5
    invoke-virtual {v0}, Lc1/c;->e()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-boolean v0, p0, Lj2/o;->v:Z

    .line 13
    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    const/4 v0, 0x1

    .line 18
    if-ne p1, v0, :cond_2

    .line 19
    .line 20
    const-wide v0, 0xffffffffL

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    and-long/2addr v0, p2

    .line 26
    long-to-int p1, v0

    .line 27
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    const/4 v0, 0x0

    .line 32
    cmpg-float p1, p1, v0

    .line 33
    .line 34
    if-gez p1, :cond_2

    .line 35
    .line 36
    invoke-virtual {p0, p2, p3}, Lj2/o;->c1(J)J

    .line 37
    .line 38
    .line 39
    move-result-wide p0

    .line 40
    return-wide p0

    .line 41
    :cond_2
    :goto_0
    const-wide/16 p0, 0x0

    .line 42
    .line 43
    return-wide p0
.end method
