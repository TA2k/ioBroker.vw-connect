.class public final Lh1/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/j1;


# instance fields
.field public final a:Lh1/l;

.field public final b:Lc1/u;

.field public final c:Lc1/j;

.field public final d:Lg1/g2;


# direct methods
.method public constructor <init>(Lh1/l;Lc1/u;Lc1/j;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh1/g;->a:Lh1/l;

    .line 5
    .line 6
    iput-object p2, p0, Lh1/g;->b:Lc1/u;

    .line 7
    .line 8
    iput-object p3, p0, Lh1/g;->c:Lc1/j;

    .line 9
    .line 10
    sget-object p1, Landroidx/compose/foundation/gestures/b;->c:Lg1/g2;

    .line 11
    .line 12
    iput-object p1, p0, Lh1/g;->d:Lg1/g2;

    .line 13
    .line 14
    return-void
.end method

.method public static final b(Lh1/g;Lg1/e2;FFLh1/d;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p5, Lh1/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p5

    .line 6
    check-cast v0, Lh1/f;

    .line 7
    .line 8
    iget v1, v0, Lh1/f;->f:I

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
    iput v1, v0, Lh1/f;->f:I

    .line 18
    .line 19
    :goto_0
    move-object p5, v0

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v0, Lh1/f;

    .line 22
    .line 23
    invoke-direct {v0, p0, p5}, Lh1/f;-><init>(Lh1/g;Lrx0/c;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :goto_1
    iget-object v0, p5, Lh1/f;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, p5, Lh1/f;->f:I

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
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_5

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
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    const/4 v2, 0x0

    .line 58
    cmpg-float v0, v0, v2

    .line 59
    .line 60
    if-nez v0, :cond_3

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_3
    invoke-static {p3}, Ljava/lang/Math;->abs(F)F

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    cmpg-float v0, v0, v2

    .line 68
    .line 69
    if-nez v0, :cond_4

    .line 70
    .line 71
    :goto_2
    const/16 p0, 0x1c

    .line 72
    .line 73
    invoke-static {p2, p3, p0}, Lc1/d;->b(FFI)Lc1/k;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    return-object p0

    .line 78
    :cond_4
    iput v3, p5, Lh1/f;->f:I

    .line 79
    .line 80
    iget-object v0, p0, Lh1/g;->b:Lc1/u;

    .line 81
    .line 82
    invoke-static {v0, v2, p3}, Lc1/d;->k(Lc1/u;FF)F

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 91
    .line 92
    .line 93
    move-result v3

    .line 94
    cmpl-float v2, v2, v3

    .line 95
    .line 96
    if-ltz v2, :cond_5

    .line 97
    .line 98
    new-instance p0, La0/j;

    .line 99
    .line 100
    const/16 v2, 0x18

    .line 101
    .line 102
    invoke-direct {p0, v0, v2}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 103
    .line 104
    .line 105
    :goto_3
    move v0, p2

    .line 106
    goto :goto_4

    .line 107
    :cond_5
    new-instance v0, Lbu/c;

    .line 108
    .line 109
    iget-object p0, p0, Lh1/g;->c:Lc1/j;

    .line 110
    .line 111
    const/16 v2, 0x1d

    .line 112
    .line 113
    invoke-direct {v0, p0, v2}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 114
    .line 115
    .line 116
    move-object p0, v0

    .line 117
    goto :goto_3

    .line 118
    :goto_4
    new-instance p2, Ljava/lang/Float;

    .line 119
    .line 120
    invoke-direct {p2, v0}, Ljava/lang/Float;-><init>(F)V

    .line 121
    .line 122
    .line 123
    move v0, p3

    .line 124
    new-instance p3, Ljava/lang/Float;

    .line 125
    .line 126
    invoke-direct {p3, v0}, Ljava/lang/Float;-><init>(F)V

    .line 127
    .line 128
    .line 129
    invoke-interface/range {p0 .. p5}, Lh1/b;->I(Lg1/e2;Ljava/lang/Float;Ljava/lang/Float;Lay0/k;Lh1/f;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    if-ne v0, v1, :cond_6

    .line 134
    .line 135
    return-object v1

    .line 136
    :cond_6
    :goto_5
    check-cast v0, Lh1/a;

    .line 137
    .line 138
    iget-object p0, v0, Lh1/a;->b:Lc1/k;

    .line 139
    .line 140
    return-object p0
.end method


# virtual methods
.method public a(Lg1/e2;FLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p3, Lrx0/c;

    .line 2
    .line 3
    sget-object v0, Lg1/h3;->a:Lfw0/i0;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2, v0, p3}, Lh1/g;->d(Lg1/e2;FLay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final c(Lg1/e2;FLay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p4, Lh1/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Lh1/c;

    .line 7
    .line 8
    iget v1, v0, Lh1/c;->g:I

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
    iput v1, v0, Lh1/c;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lh1/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Lh1/c;-><init>(Lh1/g;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Lh1/c;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lh1/c;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p3, v0, Lh1/c;->d:Lay0/k;

    .line 37
    .line 38
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance v4, Lg1/c0;

    .line 54
    .line 55
    const/4 v9, 0x0

    .line 56
    move-object v5, p0

    .line 57
    move-object v8, p1

    .line 58
    move v6, p2

    .line 59
    move-object v7, p3

    .line 60
    invoke-direct/range {v4 .. v9}, Lg1/c0;-><init>(Lh1/g;FLay0/k;Lg1/e2;Lkotlin/coroutines/Continuation;)V

    .line 61
    .line 62
    .line 63
    iput-object v7, v0, Lh1/c;->d:Lay0/k;

    .line 64
    .line 65
    iput v3, v0, Lh1/c;->g:I

    .line 66
    .line 67
    iget-object p0, v5, Lh1/g;->d:Lg1/g2;

    .line 68
    .line 69
    invoke-static {p0, v4, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p4

    .line 73
    if-ne p4, v1, :cond_3

    .line 74
    .line 75
    return-object v1

    .line 76
    :cond_3
    move-object p3, v7

    .line 77
    :goto_1
    check-cast p4, Lh1/a;

    .line 78
    .line 79
    new-instance p0, Ljava/lang/Float;

    .line 80
    .line 81
    const/4 p1, 0x0

    .line 82
    invoke-direct {p0, p1}, Ljava/lang/Float;-><init>(F)V

    .line 83
    .line 84
    .line 85
    invoke-interface {p3, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    return-object p4
.end method

.method public final d(Lg1/e2;FLay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p4, Lh1/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Lh1/e;

    .line 7
    .line 8
    iget v1, v0, Lh1/e;->f:I

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
    iput v1, v0, Lh1/e;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lh1/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Lh1/e;-><init>(Lh1/g;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Lh1/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lh1/e;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iput v3, v0, Lh1/e;->f:I

    .line 52
    .line 53
    invoke-virtual {p0, p1, p2, p3, v0}, Lh1/g;->c(Lg1/e2;FLay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p4

    .line 57
    if-ne p4, v1, :cond_3

    .line 58
    .line 59
    return-object v1

    .line 60
    :cond_3
    :goto_1
    check-cast p4, Lh1/a;

    .line 61
    .line 62
    iget-object p0, p4, Lh1/a;->a:Ljava/lang/Float;

    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    iget-object p1, p4, Lh1/a;->b:Lc1/k;

    .line 69
    .line 70
    const/4 p2, 0x0

    .line 71
    cmpg-float p0, p0, p2

    .line 72
    .line 73
    if-nez p0, :cond_4

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_4
    invoke-virtual {p1}, Lc1/k;->a()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    check-cast p0, Ljava/lang/Number;

    .line 81
    .line 82
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 83
    .line 84
    .line 85
    move-result p2

    .line 86
    :goto_2
    new-instance p0, Ljava/lang/Float;

    .line 87
    .line 88
    invoke-direct {p0, p2}, Ljava/lang/Float;-><init>(F)V

    .line 89
    .line 90
    .line 91
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    instance-of v0, p1, Lh1/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    check-cast p1, Lh1/g;

    .line 7
    .line 8
    iget-object v0, p1, Lh1/g;->c:Lc1/j;

    .line 9
    .line 10
    iget-object v2, p0, Lh1/g;->c:Lc1/j;

    .line 11
    .line 12
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    iget-object v0, p1, Lh1/g;->b:Lc1/u;

    .line 19
    .line 20
    iget-object v2, p0, Lh1/g;->b:Lc1/u;

    .line 21
    .line 22
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    iget-object p1, p1, Lh1/g;->a:Lh1/l;

    .line 29
    .line 30
    iget-object p0, p0, Lh1/g;->a:Lh1/l;

    .line 31
    .line 32
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-eqz p0, :cond_0

    .line 37
    .line 38
    const/4 p0, 0x1

    .line 39
    return p0

    .line 40
    :cond_0
    return v1
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lh1/g;->c:Lc1/j;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lh1/g;->b:Lc1/u;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget-object p0, p0, Lh1/g;->a:Lh1/l;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    add-int/2addr p0, v1

    .line 25
    return p0
.end method
