.class public final Lyy0/f2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final d:Lyy0/j;

.field public final e:Lrx0/i;


# direct methods
.method public constructor <init>(Lyy0/j;Lay0/n;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lyy0/f2;->d:Lyy0/j;

    .line 5
    .line 6
    check-cast p2, Lrx0/i;

    .line 7
    .line 8
    iput-object p2, p0, Lyy0/f2;->e:Lrx0/i;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Lyy0/e2;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lyy0/e2;

    .line 7
    .line 8
    iget v1, v0, Lyy0/e2;->h:I

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
    iput v1, v0, Lyy0/e2;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyy0/e2;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lyy0/e2;-><init>(Lyy0/f2;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lyy0/e2;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyy0/e2;->h:I

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
    iget-object p0, v0, Lyy0/e2;->e:Lzy0/r;

    .line 54
    .line 55
    iget-object v2, v0, Lyy0/e2;->d:Lyy0/f2;

    .line 56
    .line 57
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :catchall_0
    move-exception p1

    .line 62
    goto :goto_3

    .line 63
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    new-instance p1, Lzy0/r;

    .line 67
    .line 68
    iget-object v2, p0, Lyy0/f2;->d:Lyy0/j;

    .line 69
    .line 70
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 71
    .line 72
    .line 73
    move-result-object v6

    .line 74
    invoke-direct {p1, v2, v6}, Lzy0/r;-><init>(Lyy0/j;Lpx0/g;)V

    .line 75
    .line 76
    .line 77
    :try_start_1
    iget-object v2, p0, Lyy0/f2;->e:Lrx0/i;

    .line 78
    .line 79
    iput-object p0, v0, Lyy0/e2;->d:Lyy0/f2;

    .line 80
    .line 81
    iput-object p1, v0, Lyy0/e2;->e:Lzy0/r;

    .line 82
    .line 83
    iput v5, v0, Lyy0/e2;->h:I

    .line 84
    .line 85
    invoke-interface {v2, p1, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 89
    if-ne v2, v1, :cond_4

    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_4
    move-object v2, p0

    .line 93
    move-object p0, p1

    .line 94
    :goto_1
    invoke-virtual {p0}, Lrx0/c;->releaseIntercepted()V

    .line 95
    .line 96
    .line 97
    iget-object p0, v2, Lyy0/f2;->d:Lyy0/j;

    .line 98
    .line 99
    instance-of p1, p0, Lyy0/f2;

    .line 100
    .line 101
    if-eqz p1, :cond_5

    .line 102
    .line 103
    check-cast p0, Lyy0/f2;

    .line 104
    .line 105
    const/4 p1, 0x0

    .line 106
    iput-object p1, v0, Lyy0/e2;->d:Lyy0/f2;

    .line 107
    .line 108
    iput-object p1, v0, Lyy0/e2;->e:Lzy0/r;

    .line 109
    .line 110
    iput v4, v0, Lyy0/e2;->h:I

    .line 111
    .line 112
    invoke-virtual {p0, v0}, Lyy0/f2;->b(Lrx0/c;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    if-ne p0, v1, :cond_5

    .line 117
    .line 118
    :goto_2
    return-object v1

    .line 119
    :cond_5
    return-object v3

    .line 120
    :catchall_1
    move-exception p0

    .line 121
    move-object v7, p1

    .line 122
    move-object p1, p0

    .line 123
    move-object p0, v7

    .line 124
    :goto_3
    invoke-virtual {p0}, Lrx0/c;->releaseIntercepted()V

    .line 125
    .line 126
    .line 127
    throw p1
.end method

.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lyy0/f2;->d:Lyy0/j;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
