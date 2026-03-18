.class public final Lif0/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lme0/a;


# instance fields
.field public final a:Lti0/a;

.field public final b:Lti0/a;

.field public final c:Lti0/a;

.field public final d:Lti0/a;

.field public final e:Lti0/a;

.field public final f:Lny/d;

.field public final g:Lwe0/a;

.field public final h:Lwe0/a;

.field public final i:Lez0/c;

.field public final j:Lac/l;


# direct methods
.method public constructor <init>(Lti0/a;Lti0/a;Lti0/a;Lti0/a;Lti0/a;Lny/d;Lwe0/a;Lwe0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lif0/f0;->a:Lti0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lif0/f0;->b:Lti0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lif0/f0;->c:Lti0/a;

    .line 9
    .line 10
    iput-object p4, p0, Lif0/f0;->d:Lti0/a;

    .line 11
    .line 12
    iput-object p5, p0, Lif0/f0;->e:Lti0/a;

    .line 13
    .line 14
    iput-object p6, p0, Lif0/f0;->f:Lny/d;

    .line 15
    .line 16
    iput-object p7, p0, Lif0/f0;->g:Lwe0/a;

    .line 17
    .line 18
    iput-object p8, p0, Lif0/f0;->h:Lwe0/a;

    .line 19
    .line 20
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    iput-object p1, p0, Lif0/f0;->i:Lez0/c;

    .line 25
    .line 26
    new-instance p1, Lg1/y2;

    .line 27
    .line 28
    const/16 p2, 0x17

    .line 29
    .line 30
    const/4 p3, 0x0

    .line 31
    invoke-direct {p1, p0, p3, p2}, Lg1/y2;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    new-instance p2, Lyy0/m1;

    .line 35
    .line 36
    invoke-direct {p2, p1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 37
    .line 38
    .line 39
    new-instance p1, Lac/l;

    .line 40
    .line 41
    const/16 p3, 0x10

    .line 42
    .line 43
    invoke-direct {p1, p3, p2, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    iput-object p1, p0, Lif0/f0;->j:Lac/l;

    .line 47
    .line 48
    return-void
.end method

.method public static final b(Lif0/f0;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lif0/z;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lif0/z;

    .line 7
    .line 8
    iget v1, v0, Lif0/z;->g:I

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
    iput v1, v0, Lif0/z;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lif0/z;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lif0/z;-><init>(Lif0/f0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lif0/z;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lif0/z;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-object p2

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
    iget-object p1, v0, Lif0/z;->d:Ljava/lang/String;

    .line 52
    .line 53
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p0, p0, Lif0/f0;->b:Lti0/a;

    .line 61
    .line 62
    iput-object p1, v0, Lif0/z;->d:Ljava/lang/String;

    .line 63
    .line 64
    iput v4, v0, Lif0/z;->g:I

    .line 65
    .line 66
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    if-ne p2, v1, :cond_4

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    :goto_1
    check-cast p2, Lgp0/a;

    .line 74
    .line 75
    sget-object p0, Lhp0/f;->e:Lhp0/f;

    .line 76
    .line 77
    const/4 v2, 0x0

    .line 78
    iput-object v2, v0, Lif0/z;->d:Ljava/lang/String;

    .line 79
    .line 80
    iput v3, v0, Lif0/z;->g:I

    .line 81
    .line 82
    iget-object v2, p2, Lgp0/a;->a:Lla/u;

    .line 83
    .line 84
    new-instance v3, Laa/o;

    .line 85
    .line 86
    const/16 v5, 0x13

    .line 87
    .line 88
    invoke-direct {v3, p1, p2, p0, v5}, Laa/o;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 89
    .line 90
    .line 91
    invoke-static {v0, v2, v4, v4, v3}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    if-ne p0, v1, :cond_5

    .line 96
    .line 97
    :goto_2
    return-object v1

    .line 98
    :cond_5
    return-object p0
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Lge0/b;->a:Lcz0/e;

    .line 2
    .line 3
    new-instance v1, Lh40/h;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/16 v3, 0x13

    .line 7
    .line 8
    invoke-direct {v1, p0, v2, v3}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 9
    .line 10
    .line 11
    invoke-static {v0, v1, p1}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    if-ne p0, p1, :cond_0

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0
.end method

.method public final c(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lif0/y;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lif0/y;

    .line 7
    .line 8
    iget v1, v0, Lif0/y;->g:I

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
    iput v1, v0, Lif0/y;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lif0/y;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lif0/y;-><init>(Lif0/f0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lif0/y;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lif0/y;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_4

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    iget-object p1, v0, Lif0/y;->d:Ljava/lang/String;

    .line 54
    .line 55
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput-object p1, v0, Lif0/y;->d:Ljava/lang/String;

    .line 63
    .line 64
    iput v5, v0, Lif0/y;->g:I

    .line 65
    .line 66
    iget-object p0, p0, Lif0/f0;->a:Lti0/a;

    .line 67
    .line 68
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    if-ne p2, v1, :cond_4

    .line 73
    .line 74
    goto :goto_3

    .line 75
    :cond_4
    :goto_1
    check-cast p2, Lif0/m;

    .line 76
    .line 77
    const/4 p0, 0x0

    .line 78
    iput-object p0, v0, Lif0/y;->d:Ljava/lang/String;

    .line 79
    .line 80
    iput v4, v0, Lif0/y;->g:I

    .line 81
    .line 82
    iget-object p0, p2, Lif0/m;->a:Lla/u;

    .line 83
    .line 84
    new-instance p2, Lif0/d;

    .line 85
    .line 86
    const/4 v2, 0x2

    .line 87
    invoke-direct {p2, p1, v2}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 88
    .line 89
    .line 90
    const/4 p1, 0x0

    .line 91
    invoke-static {v0, p0, p1, v5, p2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    if-ne p0, v1, :cond_5

    .line 96
    .line 97
    goto :goto_2

    .line 98
    :cond_5
    move-object p0, v3

    .line 99
    :goto_2
    if-ne p0, v1, :cond_6

    .line 100
    .line 101
    :goto_3
    return-object v1

    .line 102
    :cond_6
    :goto_4
    return-object v3
.end method

.method public final d(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Lge0/b;->a:Lcz0/e;

    .line 2
    .line 3
    new-instance v1, Lg1/y2;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/16 v3, 0x16

    .line 7
    .line 8
    invoke-direct {v1, v3, p0, p1, v2}, Lg1/y2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    invoke-static {v0, v1, p2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final e(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lif0/a0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lif0/a0;

    .line 7
    .line 8
    iget v1, v0, Lif0/a0;->f:I

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
    iput v1, v0, Lif0/a0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lif0/a0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lif0/a0;-><init>(Lif0/f0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lif0/a0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lif0/a0;->f:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    iput v3, v0, Lif0/a0;->f:I

    .line 52
    .line 53
    invoke-virtual {p0, p1, v0}, Lif0/f0;->d(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    if-ne p2, v1, :cond_3

    .line 58
    .line 59
    return-object v1

    .line 60
    :cond_3
    :goto_1
    check-cast p2, Lss0/k;

    .line 61
    .line 62
    if-eqz p2, :cond_4

    .line 63
    .line 64
    iget-object p0, p2, Lss0/k;->i:Lss0/a0;

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_4
    const/4 p0, 0x0

    .line 68
    :goto_2
    if-eqz p0, :cond_5

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_5
    const/4 v3, 0x0

    .line 72
    :goto_3
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method

.method public final f(Lss0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Lge0/b;->a:Lcz0/e;

    .line 2
    .line 3
    new-instance v1, Lif0/d0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v1, v3, p0, p1, v2}, Lif0/d0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    invoke-static {v0, v1, p2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    if-ne p0, p1, :cond_0

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    return-object p0
.end method
