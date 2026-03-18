.class public final Lcp0/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lme0/a;


# instance fields
.field public final a:Lti0/a;


# direct methods
.method public constructor <init>(Lti0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcp0/q;->a:Lti0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lcp0/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lcp0/m;

    .line 7
    .line 8
    iget v1, v0, Lcp0/m;->f:I

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
    iput v1, v0, Lcp0/m;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcp0/m;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lcp0/m;-><init>(Lcp0/q;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lcp0/m;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcp0/m;->f:I

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
    iput v5, v0, Lcp0/m;->f:I

    .line 61
    .line 62
    iget-object p0, p0, Lcp0/q;->a:Lti0/a;

    .line 63
    .line 64
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-ne p1, v1, :cond_4

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_4
    :goto_1
    check-cast p1, Lcp0/t;

    .line 72
    .line 73
    iput v4, v0, Lcp0/m;->f:I

    .line 74
    .line 75
    iget-object p0, p1, Lcp0/t;->a:Lla/u;

    .line 76
    .line 77
    new-instance p1, Lck/b;

    .line 78
    .line 79
    const/4 v2, 0x3

    .line 80
    invoke-direct {p1, v2}, Lck/b;-><init>(I)V

    .line 81
    .line 82
    .line 83
    const/4 v2, 0x0

    .line 84
    invoke-static {v0, p0, v2, v5, p1}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    if-ne p0, v1, :cond_5

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_5
    move-object p0, v3

    .line 92
    :goto_2
    if-ne p0, v1, :cond_6

    .line 93
    .line 94
    :goto_3
    return-object v1

    .line 95
    :cond_6
    return-object v3
.end method

.method public final b(Ljava/lang/String;Lfp0/d;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, Lcp0/n;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lcp0/n;

    .line 7
    .line 8
    iget v1, v0, Lcp0/n;->h:I

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
    iput v1, v0, Lcp0/n;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcp0/n;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lcp0/n;-><init>(Lcp0/q;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lcp0/n;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcp0/n;->h:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    const/4 v5, 0x0

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v4, :cond_2

    .line 37
    .line 38
    if-ne v2, v3, :cond_1

    .line 39
    .line 40
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

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
    iget-object p2, v0, Lcp0/n;->e:Lfp0/d;

    .line 53
    .line 54
    iget-object p1, v0, Lcp0/n;->d:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iput-object p1, v0, Lcp0/n;->d:Ljava/lang/String;

    .line 64
    .line 65
    iput-object p2, v0, Lcp0/n;->e:Lfp0/d;

    .line 66
    .line 67
    iput v4, v0, Lcp0/n;->h:I

    .line 68
    .line 69
    iget-object p0, p0, Lcp0/q;->a:Lti0/a;

    .line 70
    .line 71
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p3

    .line 75
    if-ne p3, v1, :cond_4

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_4
    :goto_1
    check-cast p3, Lcp0/t;

    .line 79
    .line 80
    invoke-static {p2}, Ljp/ne;->d(Lfp0/d;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    iput-object v5, v0, Lcp0/n;->d:Ljava/lang/String;

    .line 85
    .line 86
    iput-object v5, v0, Lcp0/n;->e:Lfp0/d;

    .line 87
    .line 88
    iput v3, v0, Lcp0/n;->h:I

    .line 89
    .line 90
    iget-object p2, p3, Lcp0/t;->a:Lla/u;

    .line 91
    .line 92
    new-instance v2, Lcp0/s;

    .line 93
    .line 94
    invoke-direct {v2, p1, p0, p3}, Lcp0/s;-><init>(Ljava/lang/String;Ljava/lang/String;Lcp0/t;)V

    .line 95
    .line 96
    .line 97
    const/4 p0, 0x0

    .line 98
    invoke-static {v0, p2, v4, p0, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p3

    .line 102
    if-ne p3, v1, :cond_5

    .line 103
    .line 104
    :goto_2
    return-object v1

    .line 105
    :cond_5
    :goto_3
    check-cast p3, Lcp0/u;

    .line 106
    .line 107
    if-eqz p3, :cond_8

    .line 108
    .line 109
    iget-object p0, p3, Lcp0/u;->b:Ljava/lang/String;

    .line 110
    .line 111
    const-string p1, "fuel"

    .line 112
    .line 113
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 114
    .line 115
    .line 116
    move-result p1

    .line 117
    if-eqz p1, :cond_6

    .line 118
    .line 119
    sget-object p0, Lfp0/d;->d:Lfp0/d;

    .line 120
    .line 121
    goto :goto_4

    .line 122
    :cond_6
    const-string p1, "cng"

    .line 123
    .line 124
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result p0

    .line 128
    if-eqz p0, :cond_7

    .line 129
    .line 130
    sget-object p0, Lfp0/d;->e:Lfp0/d;

    .line 131
    .line 132
    goto :goto_4

    .line 133
    :cond_7
    move-object p0, v5

    .line 134
    :goto_4
    if-eqz p0, :cond_8

    .line 135
    .line 136
    new-instance p1, Lfp0/g;

    .line 137
    .line 138
    iget-object p2, p3, Lcp0/u;->a:Ljava/lang/String;

    .line 139
    .line 140
    const-string v0, "value"

    .line 141
    .line 142
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    iget v0, p3, Lcp0/u;->c:I

    .line 146
    .line 147
    iget-object p3, p3, Lcp0/u;->d:Ljava/time/LocalDate;

    .line 148
    .line 149
    invoke-direct {p1, p2, p0, v0, p3}, Lfp0/g;-><init>(Ljava/lang/String;Lfp0/d;ILjava/time/LocalDate;)V

    .line 150
    .line 151
    .line 152
    return-object p1

    .line 153
    :cond_8
    return-object v5
.end method

.method public final c(Lfp0/g;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lcp0/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lcp0/o;

    .line 7
    .line 8
    iget v1, v0, Lcp0/o;->g:I

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
    iput v1, v0, Lcp0/o;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcp0/o;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lcp0/o;-><init>(Lcp0/q;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lcp0/o;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcp0/o;->g:I

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
    iget-object p1, v0, Lcp0/o;->d:Lfp0/g;

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
    iput-object p1, v0, Lcp0/o;->d:Lfp0/g;

    .line 63
    .line 64
    iput v5, v0, Lcp0/o;->g:I

    .line 65
    .line 66
    iget-object p0, p0, Lcp0/q;->a:Lti0/a;

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
    check-cast p2, Lcp0/t;

    .line 76
    .line 77
    const-string p0, "<this>"

    .line 78
    .line 79
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    new-instance p0, Lcp0/u;

    .line 83
    .line 84
    iget-object v2, p1, Lfp0/g;->a:Ljava/lang/String;

    .line 85
    .line 86
    iget-object v6, p1, Lfp0/g;->b:Lfp0/d;

    .line 87
    .line 88
    invoke-static {v6}, Ljp/ne;->d(Lfp0/d;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v6

    .line 92
    iget v7, p1, Lfp0/g;->c:I

    .line 93
    .line 94
    iget-object p1, p1, Lfp0/g;->d:Ljava/time/LocalDate;

    .line 95
    .line 96
    invoke-direct {p0, v2, v6, v7, p1}, Lcp0/u;-><init>(Ljava/lang/String;Ljava/lang/String;ILjava/time/LocalDate;)V

    .line 97
    .line 98
    .line 99
    const/4 p1, 0x0

    .line 100
    iput-object p1, v0, Lcp0/o;->d:Lfp0/g;

    .line 101
    .line 102
    iput v4, v0, Lcp0/o;->g:I

    .line 103
    .line 104
    iget-object p1, p2, Lcp0/t;->a:Lla/u;

    .line 105
    .line 106
    new-instance v2, Laa/z;

    .line 107
    .line 108
    const/16 v4, 0x11

    .line 109
    .line 110
    invoke-direct {v2, v4, p2, p0}, Laa/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    const/4 p0, 0x0

    .line 114
    invoke-static {v0, p1, p0, v5, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    if-ne p0, v1, :cond_5

    .line 119
    .line 120
    goto :goto_2

    .line 121
    :cond_5
    move-object p0, v3

    .line 122
    :goto_2
    if-ne p0, v1, :cond_6

    .line 123
    .line 124
    :goto_3
    return-object v1

    .line 125
    :cond_6
    return-object v3
.end method

.method public final d(Ljava/lang/String;Lfp0/d;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, Lcp0/p;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lcp0/p;

    .line 7
    .line 8
    iget v1, v0, Lcp0/p;->h:I

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
    iput v1, v0, Lcp0/p;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcp0/p;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lcp0/p;-><init>(Lcp0/q;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lcp0/p;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcp0/p;->h:I

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
    iget-object p2, v0, Lcp0/p;->e:Lfp0/d;

    .line 54
    .line 55
    iget-object p1, v0, Lcp0/p;->d:Ljava/lang/String;

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
    iput-object p1, v0, Lcp0/p;->d:Ljava/lang/String;

    .line 65
    .line 66
    iput-object p2, v0, Lcp0/p;->e:Lfp0/d;

    .line 67
    .line 68
    iput v5, v0, Lcp0/p;->h:I

    .line 69
    .line 70
    iget-object p0, p0, Lcp0/q;->a:Lti0/a;

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
    check-cast p3, Lcp0/t;

    .line 80
    .line 81
    invoke-static {p2}, Ljp/ne;->d(Lfp0/d;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-static {}, Ljava/time/LocalDate;->now()Ljava/time/LocalDate;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    const-string v2, "now(...)"

    .line 90
    .line 91
    invoke-static {p2, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    const/4 v2, 0x0

    .line 95
    iput-object v2, v0, Lcp0/p;->d:Ljava/lang/String;

    .line 96
    .line 97
    iput-object v2, v0, Lcp0/p;->e:Lfp0/d;

    .line 98
    .line 99
    iput v4, v0, Lcp0/p;->h:I

    .line 100
    .line 101
    iget-object v2, p3, Lcp0/t;->a:Lla/u;

    .line 102
    .line 103
    new-instance v4, Laa/o;

    .line 104
    .line 105
    invoke-direct {v4, p3, p2, p1, p0}, Laa/o;-><init>(Lcp0/t;Ljava/time/LocalDate;Ljava/lang/String;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    const/4 p0, 0x0

    .line 109
    invoke-static {v0, v2, p0, v5, v4}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    if-ne p0, v1, :cond_5

    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_5
    move-object p0, v3

    .line 117
    :goto_2
    if-ne p0, v1, :cond_6

    .line 118
    .line 119
    :goto_3
    return-object v1

    .line 120
    :cond_6
    return-object v3
.end method
