.class public final Lny/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


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
    iput-object p1, p0, Lny/d;->a:Lti0/a;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lay0/k;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lny/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lny/c;

    .line 7
    .line 8
    iget v1, v0, Lny/c;->g:I

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
    iput v1, v0, Lny/c;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lny/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lny/c;-><init>(Lny/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lny/c;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lny/c;->g:I

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
    goto :goto_3

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
    iget-object p0, v0, Lny/c;->d:Lrx0/i;

    .line 52
    .line 53
    move-object p1, p0

    .line 54
    check-cast p1, Lay0/k;

    .line 55
    .line 56
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    move-object p2, p1

    .line 64
    check-cast p2, Lrx0/i;

    .line 65
    .line 66
    iput-object p2, v0, Lny/c;->d:Lrx0/i;

    .line 67
    .line 68
    iput v4, v0, Lny/c;->g:I

    .line 69
    .line 70
    iget-object p0, p0, Lny/d;->a:Lti0/a;

    .line 71
    .line 72
    invoke-interface {p0, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    if-ne p2, v1, :cond_4

    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_4
    :goto_1
    check-cast p2, Lla/u;

    .line 80
    .line 81
    const/4 p0, 0x0

    .line 82
    iput-object p0, v0, Lny/c;->d:Lrx0/i;

    .line 83
    .line 84
    iput v3, v0, Lny/c;->g:I

    .line 85
    .line 86
    new-instance v2, Lla/v;

    .line 87
    .line 88
    const/4 v3, 0x0

    .line 89
    invoke-direct {v2, v3, p1, p0, p2}, Lla/v;-><init>(ILay0/k;Lkotlin/coroutines/Continuation;Lla/u;)V

    .line 90
    .line 91
    .line 92
    invoke-static {v2, v0, p2}, Llp/gf;->c(Lay0/k;Lkotlin/coroutines/Continuation;Lla/u;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    if-ne p0, v1, :cond_5

    .line 97
    .line 98
    :goto_2
    return-object v1

    .line 99
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    return-object p0
.end method
