.class public final Lm20/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lme0/a;
.implements Lme0/b;


# instance fields
.field public final a:Lti0/a;

.field public final b:Lwe0/a;

.field public final c:Lez0/c;


# direct methods
.method public constructor <init>(Lti0/a;Lwe0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lm20/j;->a:Lti0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lm20/j;->b:Lwe0/a;

    .line 7
    .line 8
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lm20/j;->c:Lez0/c;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lm20/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lm20/e;

    .line 7
    .line 8
    iget v1, v0, Lm20/e;->f:I

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
    iput v1, v0, Lm20/e;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm20/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lm20/e;-><init>(Lm20/j;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lm20/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm20/e;->f:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v3

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p1, p0, Lm20/j;->b:Lwe0/a;

    .line 61
    .line 62
    check-cast p1, Lwe0/c;

    .line 63
    .line 64
    invoke-virtual {p1}, Lwe0/c;->a()V

    .line 65
    .line 66
    .line 67
    iput v5, v0, Lm20/e;->f:I

    .line 68
    .line 69
    iget-object p0, p0, Lm20/j;->a:Lti0/a;

    .line 70
    .line 71
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    if-ne p1, v1, :cond_4

    .line 76
    .line 77
    goto :goto_3

    .line 78
    :cond_4
    :goto_1
    check-cast p1, Lm20/a;

    .line 79
    .line 80
    iput v4, v0, Lm20/e;->f:I

    .line 81
    .line 82
    iget-object p0, p1, Lm20/a;->a:Lla/u;

    .line 83
    .line 84
    new-instance p1, Lkq0/a;

    .line 85
    .line 86
    const/16 v2, 0x1c

    .line 87
    .line 88
    invoke-direct {p1, v2}, Lkq0/a;-><init>(I)V

    .line 89
    .line 90
    .line 91
    const/4 v2, 0x0

    .line 92
    invoke-static {v0, p0, v2, v5, p1}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    if-ne p0, v1, :cond_5

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_5
    move-object p0, v3

    .line 100
    :goto_2
    if-ne p0, v1, :cond_6

    .line 101
    .line 102
    :goto_3
    return-object v1

    .line 103
    :cond_6
    return-object v3
.end method

.method public final b(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lm20/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lm20/f;

    .line 7
    .line 8
    iget v1, v0, Lm20/f;->g:I

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
    iput v1, v0, Lm20/f;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm20/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lm20/f;-><init>(Lm20/j;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lm20/f;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm20/f;->g:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v5, :cond_2

    .line 37
    .line 38
    if-ne v2, v4, :cond_1

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_3

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    iget-object p1, v0, Lm20/f;->d:Ljava/lang/String;

    .line 53
    .line 54
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iput-object p1, v0, Lm20/f;->d:Ljava/lang/String;

    .line 62
    .line 63
    iput v5, v0, Lm20/f;->g:I

    .line 64
    .line 65
    iget-object p0, p0, Lm20/j;->a:Lti0/a;

    .line 66
    .line 67
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    if-ne p2, v1, :cond_4

    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_4
    :goto_1
    check-cast p2, Lm20/a;

    .line 75
    .line 76
    const/4 p0, 0x0

    .line 77
    iput-object p0, v0, Lm20/f;->d:Ljava/lang/String;

    .line 78
    .line 79
    iput v4, v0, Lm20/f;->g:I

    .line 80
    .line 81
    iget-object p0, p2, Lm20/a;->a:Lla/u;

    .line 82
    .line 83
    new-instance p2, Lif0/d;

    .line 84
    .line 85
    const/16 v2, 0x8

    .line 86
    .line 87
    invoke-direct {p2, p1, v2}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 88
    .line 89
    .line 90
    invoke-static {v0, p0, v5, v3, p2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p2

    .line 94
    if-ne p2, v1, :cond_5

    .line 95
    .line 96
    :goto_2
    return-object v1

    .line 97
    :cond_5
    :goto_3
    if-eqz p2, :cond_6

    .line 98
    .line 99
    move v3, v5

    .line 100
    :cond_6
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    return-object p0
.end method

.method public final c(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lm20/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lm20/g;

    .line 7
    .line 8
    iget v1, v0, Lm20/g;->g:I

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
    iput v1, v0, Lm20/g;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm20/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lm20/g;-><init>(Lm20/j;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lm20/g;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm20/g;->g:I

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
    iget-object p1, v0, Lm20/g;->d:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iput-object p1, v0, Lm20/g;->d:Ljava/lang/String;

    .line 54
    .line 55
    iput v3, v0, Lm20/g;->g:I

    .line 56
    .line 57
    iget-object p0, p0, Lm20/j;->a:Lti0/a;

    .line 58
    .line 59
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    if-ne p2, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    :goto_1
    check-cast p2, Lm20/a;

    .line 67
    .line 68
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    const-string p0, "vin"

    .line 72
    .line 73
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    iget-object p0, p2, Lm20/a;->a:Lla/u;

    .line 77
    .line 78
    const-string p2, "fleet"

    .line 79
    .line 80
    filled-new-array {p2}, [Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p2

    .line 84
    new-instance v0, Lif0/d;

    .line 85
    .line 86
    const/16 v1, 0x9

    .line 87
    .line 88
    invoke-direct {v0, p1, v1}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 89
    .line 90
    .line 91
    const/4 p1, 0x0

    .line 92
    invoke-static {p0, p1, p2, v0}, Ljp/ga;->a(Lla/u;Z[Ljava/lang/String;Lay0/k;)Lna/j;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    new-instance p1, Lic0/i;

    .line 97
    .line 98
    const/4 p2, 0x2

    .line 99
    invoke-direct {p1, p0, p2}, Lic0/i;-><init>(Lna/j;I)V

    .line 100
    .line 101
    .line 102
    return-object p1
.end method

.method public final d(Ljava/lang/String;ZLrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, Lm20/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lm20/i;

    .line 7
    .line 8
    iget v1, v0, Lm20/i;->h:I

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
    iput v1, v0, Lm20/i;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm20/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lm20/i;-><init>(Lm20/j;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lm20/i;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm20/i;->h:I

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
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v3

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
    iget-boolean p2, v0, Lm20/i;->e:Z

    .line 54
    .line 55
    iget-object p1, v0, Lm20/i;->d:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iput-object p1, v0, Lm20/i;->d:Ljava/lang/String;

    .line 65
    .line 66
    iput-boolean p2, v0, Lm20/i;->e:Z

    .line 67
    .line 68
    iput v5, v0, Lm20/i;->h:I

    .line 69
    .line 70
    iget-object p0, p0, Lm20/j;->a:Lti0/a;

    .line 71
    .line 72
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p3

    .line 76
    if-ne p3, v1, :cond_4

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_4
    :goto_1
    check-cast p3, Lm20/a;

    .line 80
    .line 81
    const-string p0, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 82
    .line 83
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    new-instance p0, Lm20/b;

    .line 87
    .line 88
    invoke-direct {p0, p1, p2}, Lm20/b;-><init>(Ljava/lang/String;Z)V

    .line 89
    .line 90
    .line 91
    const/4 p1, 0x0

    .line 92
    iput-object p1, v0, Lm20/i;->d:Ljava/lang/String;

    .line 93
    .line 94
    iput-boolean p2, v0, Lm20/i;->e:Z

    .line 95
    .line 96
    iput v4, v0, Lm20/i;->h:I

    .line 97
    .line 98
    iget-object p1, p3, Lm20/a;->a:Lla/u;

    .line 99
    .line 100
    new-instance p2, Ll2/v1;

    .line 101
    .line 102
    const/4 v2, 0x4

    .line 103
    invoke-direct {p2, v2, p3, p0}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    const/4 p0, 0x0

    .line 107
    invoke-static {v0, p1, p0, v5, p2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    if-ne p0, v1, :cond_5

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_5
    move-object p0, v3

    .line 115
    :goto_2
    if-ne p0, v1, :cond_6

    .line 116
    .line 117
    :goto_3
    return-object v1

    .line 118
    :cond_6
    return-object v3
.end method
