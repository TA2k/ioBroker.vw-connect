.class public final Lpq0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lyy0/q1;

.field public final b:Lyy0/k1;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    const/4 v1, 0x7

    .line 6
    const/4 v2, 0x0

    .line 7
    invoke-static {v2, v1, v0}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lpq0/b;->a:Lyy0/q1;

    .line 12
    .line 13
    new-instance v1, Lyy0/k1;

    .line 14
    .line 15
    invoke-direct {v1, v0}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 16
    .line 17
    .line 18
    iput-object v1, p0, Lpq0/b;->b:Lyy0/k1;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final a(Lsq0/c;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lpq0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lpq0/a;

    .line 7
    .line 8
    iget v1, v0, Lpq0/a;->g:I

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
    iput v1, v0, Lpq0/a;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lpq0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lpq0/a;-><init>(Lpq0/b;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lpq0/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lpq0/a;->g:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    return-object p2

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
    iget-object p0, v0, Lpq0/a;->d:Lyy0/q1;

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
    const/4 p2, 0x0

    .line 62
    const/4 v2, 0x6

    .line 63
    invoke-static {p2, v2, v5}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 64
    .line 65
    .line 66
    move-result-object p2

    .line 67
    new-instance v2, Lsq0/e;

    .line 68
    .line 69
    new-instance v6, Lpg/m;

    .line 70
    .line 71
    const/4 v7, 0x2

    .line 72
    invoke-direct {v6, p2, v7}, Lpg/m;-><init>(Ljava/lang/Object;I)V

    .line 73
    .line 74
    .line 75
    invoke-direct {v2, p1, v6}, Lsq0/e;-><init>(Lsq0/c;Lpg/m;)V

    .line 76
    .line 77
    .line 78
    iput-object p2, v0, Lpq0/a;->d:Lyy0/q1;

    .line 79
    .line 80
    iput v4, v0, Lpq0/a;->g:I

    .line 81
    .line 82
    iget-object p0, p0, Lpq0/b;->a:Lyy0/q1;

    .line 83
    .line 84
    invoke-virtual {p0, v2, v0}, Lyy0/q1;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    if-ne p0, v1, :cond_4

    .line 89
    .line 90
    goto :goto_2

    .line 91
    :cond_4
    move-object p0, p2

    .line 92
    :goto_1
    iput-object v5, v0, Lpq0/a;->d:Lyy0/q1;

    .line 93
    .line 94
    iput v3, v0, Lpq0/a;->g:I

    .line 95
    .line 96
    invoke-static {p0, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    if-ne p0, v1, :cond_5

    .line 101
    .line 102
    :goto_2
    return-object v1

    .line 103
    :cond_5
    return-object p0
.end method
