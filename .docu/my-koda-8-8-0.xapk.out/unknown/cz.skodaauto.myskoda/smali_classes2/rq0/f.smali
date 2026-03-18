.class public final Lrq0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lpq0/b;


# direct methods
.method public constructor <init>(Lpq0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrq0/f;->a:Lpq0/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lsq0/c;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p0, p1, v0, p2}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method

.method public final b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;
    .locals 4

    .line 1
    instance-of v0, p3, Lrq0/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lrq0/e;

    .line 7
    .line 8
    iget v1, v0, Lrq0/e;->g:I

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
    iput v1, v0, Lrq0/e;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lrq0/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lrq0/e;-><init>(Lrq0/f;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lrq0/e;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lrq0/e;->g:I

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
    iget-boolean p2, v0, Lrq0/e;->d:Z

    .line 37
    .line 38
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :catch_0
    move-exception p1

    .line 43
    goto :goto_2

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
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    :try_start_1
    iget-object p3, p0, Lrq0/f;->a:Lpq0/b;

    .line 56
    .line 57
    iput-boolean p2, v0, Lrq0/e;->d:Z

    .line 58
    .line 59
    iput v3, v0, Lrq0/e;->g:I

    .line 60
    .line 61
    invoke-virtual {p3, p1, v0}, Lpq0/b;->a(Lsq0/c;Lrx0/c;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p3

    .line 65
    if-ne p3, v1, :cond_3

    .line 66
    .line 67
    return-object v1

    .line 68
    :cond_3
    :goto_1
    check-cast p3, Lsq0/d;
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    .line 69
    .line 70
    return-object p3

    .line 71
    :goto_2
    new-instance p3, Lr1/b;

    .line 72
    .line 73
    const/16 v0, 0xb

    .line 74
    .line 75
    invoke-direct {p3, p1, v0}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 76
    .line 77
    .line 78
    const/4 p1, 0x0

    .line 79
    invoke-static {p1, p0, p3}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 80
    .line 81
    .line 82
    if-nez p2, :cond_4

    .line 83
    .line 84
    sget-object p2, Lge0/a;->d:Lge0/a;

    .line 85
    .line 86
    new-instance p3, Lrp0/a;

    .line 87
    .line 88
    const/4 v0, 0x1

    .line 89
    invoke-direct {p3, p0, p1, v0}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 90
    .line 91
    .line 92
    const/4 p0, 0x3

    .line 93
    invoke-static {p2, p1, p1, p3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 94
    .line 95
    .line 96
    :cond_4
    sget-object p0, Lsq0/d;->e:Lsq0/d;

    .line 97
    .line 98
    return-object p0
.end method
