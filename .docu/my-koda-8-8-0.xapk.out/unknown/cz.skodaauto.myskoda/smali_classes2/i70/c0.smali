.class public final Li70/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lme0/b;


# instance fields
.field public final a:Lwe0/a;

.field public final b:Lti0/a;

.field public final c:Lez0/c;

.field public final d:Lyy0/c2;

.field public final e:Lyy0/l1;


# direct methods
.method public constructor <init>(Lti0/a;Lwe0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Li70/c0;->a:Lwe0/a;

    .line 5
    .line 6
    iput-object p1, p0, Li70/c0;->b:Lti0/a;

    .line 7
    .line 8
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Li70/c0;->c:Lez0/c;

    .line 13
    .line 14
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 15
    .line 16
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iput-object p1, p0, Li70/c0;->d:Lyy0/c2;

    .line 21
    .line 22
    new-instance p2, Lyy0/l1;

    .line 23
    .line 24
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 25
    .line 26
    .line 27
    iput-object p2, p0, Li70/c0;->e:Lyy0/l1;

    .line 28
    .line 29
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Li70/x;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Li70/x;

    .line 7
    .line 8
    iget v1, v0, Li70/x;->f:I

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
    iput v1, v0, Li70/x;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li70/x;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Li70/x;-><init>(Li70/c0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Li70/x;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Li70/x;->f:I

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
    iget-object p1, p0, Li70/c0;->a:Lwe0/a;

    .line 61
    .line 62
    check-cast p1, Lwe0/c;

    .line 63
    .line 64
    invoke-virtual {p1}, Lwe0/c;->a()V

    .line 65
    .line 66
    .line 67
    iput v5, v0, Li70/x;->f:I

    .line 68
    .line 69
    iget-object p0, p0, Li70/c0;->b:Lti0/a;

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
    check-cast p1, Li70/f0;

    .line 79
    .line 80
    iput v4, v0, Li70/x;->f:I

    .line 81
    .line 82
    iget-object p0, p1, Li70/f0;->a:Lla/u;

    .line 83
    .line 84
    new-instance p1, Li70/q;

    .line 85
    .line 86
    const/4 v2, 0x5

    .line 87
    invoke-direct {p1, v2}, Li70/q;-><init>(I)V

    .line 88
    .line 89
    .line 90
    const/4 v2, 0x0

    .line 91
    invoke-static {v0, p0, v2, v5, p1}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

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
    return-object v3
.end method

.method public final b(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Li70/y;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Li70/y;

    .line 7
    .line 8
    iget v1, v0, Li70/y;->g:I

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
    iput v1, v0, Li70/y;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li70/y;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Li70/y;-><init>(Li70/c0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Li70/y;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Li70/y;->g:I

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
    iget-object p1, v0, Li70/y;->d:Ljava/lang/String;

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
    iput-object p1, v0, Li70/y;->d:Ljava/lang/String;

    .line 62
    .line 63
    iput v5, v0, Li70/y;->g:I

    .line 64
    .line 65
    iget-object p0, p0, Li70/c0;->b:Lti0/a;

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
    check-cast p2, Li70/f0;

    .line 75
    .line 76
    const/4 p0, 0x0

    .line 77
    iput-object p0, v0, Li70/y;->d:Ljava/lang/String;

    .line 78
    .line 79
    iput v4, v0, Li70/y;->g:I

    .line 80
    .line 81
    iget-object p0, p2, Li70/f0;->a:Lla/u;

    .line 82
    .line 83
    new-instance p2, Lac0/r;

    .line 84
    .line 85
    const/16 v2, 0x1a

    .line 86
    .line 87
    invoke-direct {p2, p1, v2}, Lac0/r;-><init>(Ljava/lang/String;I)V

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
    instance-of v0, p2, Li70/z;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Li70/z;

    .line 7
    .line 8
    iget v1, v0, Li70/z;->g:I

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
    iput v1, v0, Li70/z;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li70/z;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Li70/z;-><init>(Li70/c0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Li70/z;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Li70/z;->g:I

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
    iget-object p1, v0, Li70/z;->d:Ljava/lang/String;

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
    iput-object p1, v0, Li70/z;->d:Ljava/lang/String;

    .line 54
    .line 55
    iput v3, v0, Li70/z;->g:I

    .line 56
    .line 57
    iget-object p0, p0, Li70/c0;->b:Lti0/a;

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
    check-cast p2, Li70/f0;

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
    iget-object p0, p2, Li70/f0;->a:Lla/u;

    .line 77
    .line 78
    const-string p2, "trips_overview"

    .line 79
    .line 80
    filled-new-array {p2}, [Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p2

    .line 84
    new-instance v0, Lac0/r;

    .line 85
    .line 86
    const/16 v1, 0x19

    .line 87
    .line 88
    invoke-direct {v0, p1, v1}, Lac0/r;-><init>(Ljava/lang/String;I)V

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
    new-instance p1, Lrz/k;

    .line 97
    .line 98
    const/16 p2, 0x15

    .line 99
    .line 100
    invoke-direct {p1, p0, p2}, Lrz/k;-><init>(Lyy0/i;I)V

    .line 101
    .line 102
    .line 103
    new-instance p0, Lcp0/j;

    .line 104
    .line 105
    const/4 p2, 0x1

    .line 106
    invoke-direct {p0, p1, p2}, Lcp0/j;-><init>(Lrz/k;I)V

    .line 107
    .line 108
    .line 109
    return-object p0
.end method

.method public final d(Ljava/lang/String;Lne0/s;Lrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    instance-of v3, v2, Li70/b0;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Li70/b0;

    .line 13
    .line 14
    iget v4, v3, Li70/b0;->h:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Li70/b0;->h:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Li70/b0;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Li70/b0;-><init>(Li70/c0;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Li70/b0;->f:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Li70/b0;->h:I

    .line 36
    .line 37
    iget-object v6, v0, Li70/c0;->a:Lwe0/a;

    .line 38
    .line 39
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    const/4 v8, 0x2

    .line 42
    const/4 v9, 0x1

    .line 43
    if-eqz v5, :cond_3

    .line 44
    .line 45
    if-eq v5, v9, :cond_2

    .line 46
    .line 47
    if-ne v5, v8, :cond_1

    .line 48
    .line 49
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto/16 :goto_9

    .line 53
    .line 54
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 55
    .line 56
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 57
    .line 58
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw v0

    .line 62
    :cond_2
    iget-object v0, v3, Li70/b0;->e:Lne0/e;

    .line 63
    .line 64
    iget-object v1, v3, Li70/b0;->d:Ljava/lang/String;

    .line 65
    .line 66
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    move-object v11, v1

    .line 70
    goto :goto_1

    .line 71
    :cond_3
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    instance-of v2, v1, Lne0/e;

    .line 75
    .line 76
    if-eqz v2, :cond_b

    .line 77
    .line 78
    move-object/from16 v2, p1

    .line 79
    .line 80
    iput-object v2, v3, Li70/b0;->d:Ljava/lang/String;

    .line 81
    .line 82
    move-object v5, v1

    .line 83
    check-cast v5, Lne0/e;

    .line 84
    .line 85
    iput-object v5, v3, Li70/b0;->e:Lne0/e;

    .line 86
    .line 87
    iput v9, v3, Li70/b0;->h:I

    .line 88
    .line 89
    iget-object v0, v0, Li70/c0;->b:Lti0/a;

    .line 90
    .line 91
    invoke-interface {v0, v3}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    if-ne v0, v4, :cond_4

    .line 96
    .line 97
    goto/16 :goto_8

    .line 98
    .line 99
    :cond_4
    move-object v11, v2

    .line 100
    move-object v2, v0

    .line 101
    move-object v0, v1

    .line 102
    :goto_1
    check-cast v2, Li70/f0;

    .line 103
    .line 104
    check-cast v0, Lne0/e;

    .line 105
    .line 106
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v0, Ll70/z;

    .line 109
    .line 110
    const-string v1, "$this$toEntity"

    .line 111
    .line 112
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    const-string v1, "$v$c$cz-skodaauto-myskoda-library-vehicle-model-Vin$-vin$0"

    .line 116
    .line 117
    invoke-static {v11, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    new-instance v10, Li70/g0;

    .line 121
    .line 122
    iget-object v1, v0, Ll70/z;->a:Ll70/a0;

    .line 123
    .line 124
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v12

    .line 128
    iget-object v1, v0, Ll70/z;->b:Lqr0/d;

    .line 129
    .line 130
    const/4 v5, 0x0

    .line 131
    if-eqz v1, :cond_5

    .line 132
    .line 133
    iget-wide v13, v1, Lqr0/d;->a:D

    .line 134
    .line 135
    const-wide v15, 0x408f400000000000L    # 1000.0

    .line 136
    .line 137
    .line 138
    .line 139
    .line 140
    div-double/2addr v13, v15

    .line 141
    double-to-int v1, v13

    .line 142
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    move-object v13, v1

    .line 147
    goto :goto_2

    .line 148
    :cond_5
    move-object v13, v5

    .line 149
    :goto_2
    iget-object v1, v0, Ll70/z;->c:Lqr0/i;

    .line 150
    .line 151
    if-eqz v1, :cond_6

    .line 152
    .line 153
    iget-wide v14, v1, Lqr0/i;->a:D

    .line 154
    .line 155
    invoke-static {v14, v15}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    move-object v14, v1

    .line 160
    goto :goto_3

    .line 161
    :cond_6
    move-object v14, v5

    .line 162
    :goto_3
    iget-object v1, v0, Ll70/z;->d:Lqr0/g;

    .line 163
    .line 164
    move-object/from16 p0, v10

    .line 165
    .line 166
    if-eqz v1, :cond_7

    .line 167
    .line 168
    iget-wide v9, v1, Lqr0/g;->a:D

    .line 169
    .line 170
    invoke-static {v9, v10}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    move-object v15, v1

    .line 175
    goto :goto_4

    .line 176
    :cond_7
    move-object v15, v5

    .line 177
    :goto_4
    iget-object v0, v0, Ll70/z;->e:Lqr0/j;

    .line 178
    .line 179
    if-eqz v0, :cond_8

    .line 180
    .line 181
    iget-wide v0, v0, Lqr0/j;->a:D

    .line 182
    .line 183
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 184
    .line 185
    .line 186
    move-result-object v0

    .line 187
    move-object/from16 v16, v0

    .line 188
    .line 189
    :goto_5
    move-object/from16 v10, p0

    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_8
    move-object/from16 v16, v5

    .line 193
    .line 194
    goto :goto_5

    .line 195
    :goto_6
    invoke-direct/range {v10 .. v16}, Li70/g0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;)V

    .line 196
    .line 197
    .line 198
    iput-object v5, v3, Li70/b0;->d:Ljava/lang/String;

    .line 199
    .line 200
    iput-object v5, v3, Li70/b0;->e:Lne0/e;

    .line 201
    .line 202
    iput v8, v3, Li70/b0;->h:I

    .line 203
    .line 204
    iget-object v0, v2, Li70/f0;->a:Lla/u;

    .line 205
    .line 206
    new-instance v1, Li40/j0;

    .line 207
    .line 208
    const/4 v5, 0x4

    .line 209
    invoke-direct {v1, v5, v2, v10}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 210
    .line 211
    .line 212
    const/4 v2, 0x0

    .line 213
    const/4 v5, 0x1

    .line 214
    invoke-static {v3, v0, v2, v5, v1}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v0

    .line 218
    if-ne v0, v4, :cond_9

    .line 219
    .line 220
    goto :goto_7

    .line 221
    :cond_9
    move-object v0, v7

    .line 222
    :goto_7
    if-ne v0, v4, :cond_a

    .line 223
    .line 224
    :goto_8
    return-object v4

    .line 225
    :cond_a
    :goto_9
    check-cast v6, Lwe0/c;

    .line 226
    .line 227
    invoke-virtual {v6}, Lwe0/c;->c()V

    .line 228
    .line 229
    .line 230
    return-object v7

    .line 231
    :cond_b
    instance-of v0, v1, Lne0/c;

    .line 232
    .line 233
    if-eqz v0, :cond_c

    .line 234
    .line 235
    check-cast v6, Lwe0/c;

    .line 236
    .line 237
    invoke-virtual {v6}, Lwe0/c;->a()V

    .line 238
    .line 239
    .line 240
    return-object v7

    .line 241
    :cond_c
    sget-object v0, Lne0/d;->a:Lne0/d;

    .line 242
    .line 243
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 244
    .line 245
    .line 246
    move-result v0

    .line 247
    if-eqz v0, :cond_d

    .line 248
    .line 249
    return-object v7

    .line 250
    :cond_d
    new-instance v0, La8/r0;

    .line 251
    .line 252
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 253
    .line 254
    .line 255
    throw v0
.end method
