.class public final Las0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcs0/a;


# instance fields
.field public final a:Lve0/u;


# direct methods
.method public constructor <init>(Lve0/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Las0/d;->a:Lve0/u;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Las0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Las0/a;

    .line 7
    .line 8
    iget v1, v0, Las0/a;->g:I

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
    iput v1, v0, Las0/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Las0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Las0/a;-><init>(Las0/d;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Las0/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Las0/a;->g:I

    .line 30
    .line 31
    iget-object p0, p0, Las0/d;->a:Lve0/u;

    .line 32
    .line 33
    const/4 v3, 0x2

    .line 34
    const/4 v4, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    iget-object p0, v0, Las0/a;->d:Ljava/lang/Long;

    .line 42
    .line 43
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_3

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    iput v4, v0, Las0/a;->g:I

    .line 63
    .line 64
    const-string p1, "analytics_consent_timestamp"

    .line 65
    .line 66
    invoke-virtual {p0, p1, v0}, Lve0/u;->e(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-ne p1, v1, :cond_4

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_4
    :goto_1
    check-cast p1, Ljava/lang/Long;

    .line 74
    .line 75
    iput-object p1, v0, Las0/a;->d:Ljava/lang/Long;

    .line 76
    .line 77
    iput v3, v0, Las0/a;->g:I

    .line 78
    .line 79
    const-string v2, "analytics_consent"

    .line 80
    .line 81
    invoke-virtual {p0, v2, v0}, Lve0/u;->c(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    if-ne p0, v1, :cond_5

    .line 86
    .line 87
    :goto_2
    return-object v1

    .line 88
    :cond_5
    move-object v5, p1

    .line 89
    move-object p1, p0

    .line 90
    move-object p0, v5

    .line 91
    :goto_3
    check-cast p1, Ljava/lang/Boolean;

    .line 92
    .line 93
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 94
    .line 95
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    if-eqz v0, :cond_6

    .line 100
    .line 101
    if-eqz p0, :cond_6

    .line 102
    .line 103
    new-instance p1, Lds0/a;

    .line 104
    .line 105
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 106
    .line 107
    .line 108
    move-result-wide v0

    .line 109
    invoke-direct {p1, v0, v1}, Lds0/a;-><init>(J)V

    .line 110
    .line 111
    .line 112
    return-object p1

    .line 113
    :cond_6
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 114
    .line 115
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result p1

    .line 119
    if-eqz p1, :cond_7

    .line 120
    .line 121
    if-eqz p0, :cond_7

    .line 122
    .line 123
    new-instance p1, Lds0/c;

    .line 124
    .line 125
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 126
    .line 127
    .line 128
    move-result-wide v0

    .line 129
    invoke-direct {p1, v0, v1}, Lds0/c;-><init>(J)V

    .line 130
    .line 131
    .line 132
    return-object p1

    .line 133
    :cond_7
    const/4 p0, 0x0

    .line 134
    return-object p0
.end method

.method public final b(Lds0/b;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Las0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Las0/c;

    .line 7
    .line 8
    iget v1, v0, Las0/c;->g:I

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
    iput v1, v0, Las0/c;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Las0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Las0/c;-><init>(Las0/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Las0/c;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Las0/c;->g:I

    .line 30
    .line 31
    iget-object p0, p0, Las0/d;->a:Lve0/u;

    .line 32
    .line 33
    const/4 v3, 0x2

    .line 34
    const/4 v4, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

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
    iget-object p1, v0, Las0/c;->d:Lds0/b;

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
    invoke-interface {p1}, Lds0/b;->b()J

    .line 63
    .line 64
    .line 65
    move-result-wide v5

    .line 66
    iput-object p1, v0, Las0/c;->d:Lds0/b;

    .line 67
    .line 68
    iput v4, v0, Las0/c;->g:I

    .line 69
    .line 70
    const-string p2, "analytics_consent_timestamp"

    .line 71
    .line 72
    invoke-virtual {p0, p2, v5, v6, v0}, Lve0/u;->m(Ljava/lang/String;JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    if-ne p2, v1, :cond_4

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_4
    :goto_1
    instance-of p2, p1, Lds0/a;

    .line 80
    .line 81
    if-eqz p2, :cond_5

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_5
    instance-of p1, p1, Lds0/c;

    .line 85
    .line 86
    if-eqz p1, :cond_7

    .line 87
    .line 88
    const/4 v4, 0x0

    .line 89
    :goto_2
    const/4 p1, 0x0

    .line 90
    iput-object p1, v0, Las0/c;->d:Lds0/b;

    .line 91
    .line 92
    iput v3, v0, Las0/c;->g:I

    .line 93
    .line 94
    const-string p1, "analytics_consent"

    .line 95
    .line 96
    invoke-virtual {p0, v4, p1, v0}, Lve0/u;->l(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    if-ne p0, v1, :cond_6

    .line 101
    .line 102
    :goto_3
    return-object v1

    .line 103
    :cond_6
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object p0

    .line 106
    :cond_7
    new-instance p0, La8/r0;

    .line 107
    .line 108
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 109
    .line 110
    .line 111
    throw p0
.end method
