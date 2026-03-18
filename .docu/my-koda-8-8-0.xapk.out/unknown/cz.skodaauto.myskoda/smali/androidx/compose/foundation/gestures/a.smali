.class public abstract Landroidx/compose/foundation/gestures/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lfw0/i0;

.field public static final b:Lc1/u;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lfw0/i0;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lfw0/i0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Landroidx/compose/foundation/gestures/a;->a:Lfw0/i0;

    .line 8
    .line 9
    new-instance v0, Ldv/a;

    .line 10
    .line 11
    const/4 v1, 0x6

    .line 12
    invoke-direct {v0, v1}, Ldv/a;-><init>(I)V

    .line 13
    .line 14
    .line 15
    new-instance v1, Lc1/u;

    .line 16
    .line 17
    invoke-direct {v1, v0}, Lc1/u;-><init>(Lc1/c0;)V

    .line 18
    .line 19
    .line 20
    sput-object v1, Landroidx/compose/foundation/gestures/a;->b:Lc1/u;

    .line 21
    .line 22
    return-void
.end method

.method public static final a(Lg1/q;FLg1/p;Lg1/z;Ljava/lang/Object;Lc1/j;Lrx0/i;)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-virtual {p3, p4}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 2
    .line 3
    .line 4
    move-result p3

    .line 5
    new-instance p4, Lkotlin/jvm/internal/c0;

    .line 6
    .line 7
    invoke-direct {p4}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lg1/q;->i:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Ll2/f1;

    .line 13
    .line 14
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    const/4 p0, 0x0

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    iget-object p0, p0, Lg1/q;->i:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast p0, Ll2/f1;

    .line 29
    .line 30
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    :goto_0
    iput p0, p4, Lkotlin/jvm/internal/c0;->d:F

    .line 35
    .line 36
    invoke-static {p3}, Ljava/lang/Float;->isNaN(F)Z

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    if-nez p0, :cond_2

    .line 41
    .line 42
    iget p0, p4, Lkotlin/jvm/internal/c0;->d:F

    .line 43
    .line 44
    cmpg-float v0, p0, p3

    .line 45
    .line 46
    if-nez v0, :cond_1

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    move-object v0, p4

    .line 50
    new-instance p4, Ld90/m;

    .line 51
    .line 52
    const/16 v1, 0x10

    .line 53
    .line 54
    invoke-direct {p4, v1, p2, v0}, Ld90/m;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    move p2, p1

    .line 58
    move p1, p3

    .line 59
    move-object p3, p5

    .line 60
    move-object p5, p6

    .line 61
    invoke-static/range {p0 .. p5}, Lc1/d;->c(FFFLc1/j;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 66
    .line 67
    if-ne p0, p1, :cond_2

    .line 68
    .line 69
    return-object p0

    .line 70
    :cond_2
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 71
    .line 72
    return-object p0
.end method

.method public static final b(Lay0/a;Lay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lg1/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lg1/e;

    .line 7
    .line 8
    iget v1, v0, Lg1/e;->e:I

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
    iput v1, v0, Lg1/e;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lg1/e;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lg1/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lg1/e;->e:I

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
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Lg1/a; {:try_start_0 .. :try_end_0} :catch_0

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    :try_start_1
    new-instance p2, Lg1/i;

    .line 52
    .line 53
    const/4 v2, 0x0

    .line 54
    const/4 v4, 0x0

    .line 55
    invoke-direct {p2, p0, p1, v2, v4}, Lg1/i;-><init>(Lay0/a;Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 56
    .line 57
    .line 58
    iput v3, v0, Lg1/e;->e:I

    .line 59
    .line 60
    invoke-static {p2, v0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0
    :try_end_1
    .catch Lg1/a; {:try_start_1 .. :try_end_1} :catch_0

    .line 64
    if-ne p0, v1, :cond_3

    .line 65
    .line 66
    return-object v1

    .line 67
    :catch_0
    :cond_3
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    return-object p0
.end method

.method public static c(Lx2/s;Lg1/q;ZLh1/g;)Lx2/s;
    .locals 1

    .line 1
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    new-instance v0, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;

    .line 4
    .line 5
    invoke-direct {v0, p1, p2, p3}, Landroidx/compose/foundation/gestures/AnchoredDraggableElement;-><init>(Lg1/q;ZLh1/g;)V

    .line 6
    .line 7
    .line 8
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public static final d(Lg1/q;Ljava/lang/Object;FLc1/j;Lc1/u;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v1, p5, Lg1/c;

    .line 2
    .line 3
    if-eqz v1, :cond_0

    .line 4
    .line 5
    move-object v1, p5

    .line 6
    check-cast v1, Lg1/c;

    .line 7
    .line 8
    iget v3, v1, Lg1/c;->g:I

    .line 9
    .line 10
    const/high16 v4, -0x80000000

    .line 11
    .line 12
    and-int v5, v3, v4

    .line 13
    .line 14
    if-eqz v5, :cond_0

    .line 15
    .line 16
    sub-int/2addr v3, v4

    .line 17
    iput v3, v1, Lg1/c;->g:I

    .line 18
    .line 19
    :goto_0
    move-object v7, v1

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v1, Lg1/c;

    .line 22
    .line 23
    invoke-direct {v1, p5}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :goto_1
    iget-object v0, v7, Lg1/c;->f:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v1, v7, Lg1/c;->g:I

    .line 32
    .line 33
    const/4 v9, 0x1

    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    if-ne v1, v9, :cond_1

    .line 37
    .line 38
    iget v1, v7, Lg1/c;->d:F

    .line 39
    .line 40
    iget-object v2, v7, Lg1/c;->e:Lkotlin/jvm/internal/c0;

    .line 41
    .line 42
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw v0

    .line 54
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    new-instance v4, Lkotlin/jvm/internal/c0;

    .line 58
    .line 59
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 60
    .line 61
    .line 62
    iput p2, v4, Lkotlin/jvm/internal/c0;->d:F

    .line 63
    .line 64
    new-instance v0, Lg1/d;

    .line 65
    .line 66
    const/4 v6, 0x0

    .line 67
    move-object v1, p0

    .line 68
    move v2, p2

    .line 69
    move-object v3, p3

    .line 70
    move-object v5, p4

    .line 71
    invoke-direct/range {v0 .. v6}, Lg1/d;-><init>(Lg1/q;FLc1/j;Lkotlin/jvm/internal/c0;Lc1/u;Lkotlin/coroutines/Continuation;)V

    .line 72
    .line 73
    .line 74
    iput-object v4, v7, Lg1/c;->e:Lkotlin/jvm/internal/c0;

    .line 75
    .line 76
    iput p2, v7, Lg1/c;->d:F

    .line 77
    .line 78
    iput v9, v7, Lg1/c;->g:I

    .line 79
    .line 80
    sget-object v1, Le1/w0;->d:Le1/w0;

    .line 81
    .line 82
    invoke-virtual {p0, p1, v1, v0, v7}, Lg1/q;->c(Ljava/lang/Object;Le1/w0;Lay0/p;Lrx0/c;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    if-ne v0, v8, :cond_3

    .line 87
    .line 88
    return-object v8

    .line 89
    :cond_3
    move v1, p2

    .line 90
    move-object v2, v4

    .line 91
    :goto_2
    iget v0, v2, Lkotlin/jvm/internal/c0;->d:F

    .line 92
    .line 93
    sub-float/2addr v1, v0

    .line 94
    new-instance v0, Ljava/lang/Float;

    .line 95
    .line 96
    invoke-direct {v0, v1}, Ljava/lang/Float;-><init>(F)V

    .line 97
    .line 98
    .line 99
    return-object v0
.end method

.method public static e(Lg1/q;Ljava/lang/Object;FLg1/j;)Ljava/lang/Object;
    .locals 8

    .line 1
    invoke-virtual {p0}, Lg1/q;->h()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    sget-object v5, Lg1/b;->a:Lc1/a2;

    .line 9
    .line 10
    invoke-virtual {p0}, Lg1/q;->h()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    sget-object v6, Lg1/b;->c:Lc1/u;

    .line 17
    .line 18
    move-object v2, p0

    .line 19
    move-object v3, p1

    .line 20
    move v4, p2

    .line 21
    move-object v7, p3

    .line 22
    invoke-static/range {v2 .. v7}, Landroidx/compose/foundation/gestures/a;->d(Lg1/q;Ljava/lang/Object;FLc1/j;Lc1/u;Lrx0/c;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_0
    const-string p0, "decayAnimationSpec"

    .line 28
    .line 29
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw v1

    .line 33
    :cond_1
    const-string p0, "snapAnimationSpec"

    .line 34
    .line 35
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw v1
.end method
