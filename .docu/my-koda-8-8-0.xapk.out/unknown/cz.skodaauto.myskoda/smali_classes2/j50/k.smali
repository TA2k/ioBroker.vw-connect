.class public final Lj50/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lme0/a;


# instance fields
.field public final a:Lti0/a;

.field public final b:Lyy0/q1;

.field public final c:Lyy0/k1;

.field public final d:Lal0/i;

.field public final e:Lyy0/c2;

.field public final f:Lyy0/l1;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/l1;


# direct methods
.method public constructor <init>(Lti0/a;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lj50/k;->a:Lti0/a;

    .line 5
    .line 6
    const/4 p1, 0x5

    .line 7
    const/4 v0, 0x1

    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-static {v0, p1, v1}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    iput-object p1, p0, Lj50/k;->b:Lyy0/q1;

    .line 14
    .line 15
    new-instance v0, Lyy0/k1;

    .line 16
    .line 17
    invoke-direct {v0, p1}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lj50/k;->c:Lyy0/k1;

    .line 21
    .line 22
    new-instance p1, Lg1/y2;

    .line 23
    .line 24
    const/16 v0, 0x1b

    .line 25
    .line 26
    invoke-direct {p1, p0, v1, v0}, Lg1/y2;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    new-instance v0, Lyy0/m1;

    .line 30
    .line 31
    invoke-direct {v0, p1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 32
    .line 33
    .line 34
    new-instance p1, Lal0/i;

    .line 35
    .line 36
    const/4 v2, 0x4

    .line 37
    invoke-direct {p1, v0, v2}, Lal0/i;-><init>(Lyy0/m1;I)V

    .line 38
    .line 39
    .line 40
    iput-object p1, p0, Lj50/k;->d:Lal0/i;

    .line 41
    .line 42
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    iput-object p1, p0, Lj50/k;->e:Lyy0/c2;

    .line 47
    .line 48
    new-instance v0, Lyy0/l1;

    .line 49
    .line 50
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 51
    .line 52
    .line 53
    iput-object v0, p0, Lj50/k;->f:Lyy0/l1;

    .line 54
    .line 55
    invoke-static {v1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    iput-object p1, p0, Lj50/k;->g:Lyy0/c2;

    .line 60
    .line 61
    new-instance v0, Lyy0/l1;

    .line 62
    .line 63
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 64
    .line 65
    .line 66
    iput-object v0, p0, Lj50/k;->h:Lyy0/l1;

    .line 67
    .line 68
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lj50/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lj50/g;

    .line 7
    .line 8
    iget v1, v0, Lj50/g;->f:I

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
    iput v1, v0, Lj50/g;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj50/g;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lj50/g;-><init>(Lj50/k;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lj50/g;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj50/g;->f:I

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
    iput v5, v0, Lj50/g;->f:I

    .line 61
    .line 62
    iget-object p1, p0, Lj50/k;->a:Lti0/a;

    .line 63
    .line 64
    invoke-interface {p1, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    check-cast p1, Lj50/a;

    .line 72
    .line 73
    iput v4, v0, Lj50/g;->f:I

    .line 74
    .line 75
    iget-object p1, p1, Lj50/a;->a:Lla/u;

    .line 76
    .line 77
    new-instance v2, Lim0/b;

    .line 78
    .line 79
    const/16 v4, 0xa

    .line 80
    .line 81
    invoke-direct {v2, v4}, Lim0/b;-><init>(I)V

    .line 82
    .line 83
    .line 84
    const/4 v4, 0x0

    .line 85
    invoke-static {v0, p1, v4, v5, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    if-ne p1, v1, :cond_5

    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_5
    move-object p1, v3

    .line 93
    :goto_2
    if-ne p1, v1, :cond_6

    .line 94
    .line 95
    :goto_3
    return-object v1

    .line 96
    :cond_6
    :goto_4
    iget-object p1, p0, Lj50/k;->e:Lyy0/c2;

    .line 97
    .line 98
    const/4 v0, 0x0

    .line 99
    invoke-virtual {p1, v0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    iget-object p0, p0, Lj50/k;->g:Lyy0/c2;

    .line 103
    .line 104
    invoke-virtual {p0, v0}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    return-object v3
.end method

.method public final b(Lbl0/o;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lj50/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lj50/h;

    .line 7
    .line 8
    iget v1, v0, Lj50/h;->g:I

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
    iput v1, v0, Lj50/h;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj50/h;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lj50/h;-><init>(Lj50/k;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lj50/h;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj50/h;->g:I

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
    iget-object p1, v0, Lj50/h;->d:Lbl0/o;

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
    iput-object p1, v0, Lj50/h;->d:Lbl0/o;

    .line 63
    .line 64
    iput v5, v0, Lj50/h;->g:I

    .line 65
    .line 66
    iget-object p0, p0, Lj50/k;->a:Lti0/a;

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
    check-cast p2, Lj50/a;

    .line 76
    .line 77
    iget-object p0, p1, Lbl0/o;->a:Ljava/lang/String;

    .line 78
    .line 79
    const/4 p1, 0x0

    .line 80
    iput-object p1, v0, Lj50/h;->d:Lbl0/o;

    .line 81
    .line 82
    iput v4, v0, Lj50/h;->g:I

    .line 83
    .line 84
    iget-object p1, p2, Lj50/a;->a:Lla/u;

    .line 85
    .line 86
    new-instance p2, Lif0/d;

    .line 87
    .line 88
    const/4 v2, 0x5

    .line 89
    invoke-direct {p2, p0, v2}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 90
    .line 91
    .line 92
    const/4 p0, 0x0

    .line 93
    invoke-static {v0, p1, p0, v5, p2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    if-ne p0, v1, :cond_5

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_5
    move-object p0, v3

    .line 101
    :goto_2
    if-ne p0, v1, :cond_6

    .line 102
    .line 103
    :goto_3
    return-object v1

    .line 104
    :cond_6
    return-object v3
.end method

.method public final c(Lbl0/o;Lrx0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p2, Lj50/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lj50/i;

    .line 7
    .line 8
    iget v1, v0, Lj50/i;->g:I

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
    iput v1, v0, Lj50/i;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lj50/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lj50/i;-><init>(Lj50/k;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lj50/i;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lj50/i;->g:I

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
    iget-object p1, v0, Lj50/i;->d:Lbl0/o;

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
    iput-object p1, v0, Lj50/i;->d:Lbl0/o;

    .line 63
    .line 64
    iput v5, v0, Lj50/i;->g:I

    .line 65
    .line 66
    iget-object p0, p0, Lj50/k;->a:Lti0/a;

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
    check-cast p2, Lj50/a;

    .line 76
    .line 77
    const-string p0, "<this>"

    .line 78
    .line 79
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    new-instance v6, Lj50/d;

    .line 83
    .line 84
    iget-object v7, p1, Lbl0/o;->a:Ljava/lang/String;

    .line 85
    .line 86
    iget-object v8, p1, Lbl0/o;->c:Ljava/lang/String;

    .line 87
    .line 88
    iget-boolean p0, p1, Lbl0/o;->b:Z

    .line 89
    .line 90
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 91
    .line 92
    .line 93
    move-result-object v9

    .line 94
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    invoke-virtual {p0}, Ljava/time/Instant;->toEpochMilli()J

    .line 99
    .line 100
    .line 101
    move-result-wide v10

    .line 102
    invoke-direct/range {v6 .. v11}, Lj50/d;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;J)V

    .line 103
    .line 104
    .line 105
    const/4 p0, 0x0

    .line 106
    iput-object p0, v0, Lj50/i;->d:Lbl0/o;

    .line 107
    .line 108
    iput v4, v0, Lj50/i;->g:I

    .line 109
    .line 110
    iget-object p0, p2, Lj50/a;->a:Lla/u;

    .line 111
    .line 112
    new-instance p1, Li40/j0;

    .line 113
    .line 114
    const/16 v2, 0xd

    .line 115
    .line 116
    invoke-direct {p1, v2, p2, v6}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    const/4 p2, 0x0

    .line 120
    invoke-static {v0, p0, p2, v5, p1}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    if-ne p0, v1, :cond_5

    .line 125
    .line 126
    goto :goto_2

    .line 127
    :cond_5
    move-object p0, v3

    .line 128
    :goto_2
    if-ne p0, v1, :cond_6

    .line 129
    .line 130
    :goto_3
    return-object v1

    .line 131
    :cond_6
    return-object v3
.end method
