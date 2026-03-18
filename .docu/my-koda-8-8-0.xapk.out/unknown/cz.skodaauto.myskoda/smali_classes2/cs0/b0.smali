.class public final Lcs0/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Las0/g;

.field public final b:Las0/e;


# direct methods
.method public constructor <init>(Las0/g;Las0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcs0/b0;->a:Las0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lcs0/b0;->b:Las0/e;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lcs0/b0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lcs0/a0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lcs0/a0;

    .line 7
    .line 8
    iget v1, v0, Lcs0/a0;->f:I

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
    iput v1, v0, Lcs0/a0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcs0/a0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lcs0/a0;-><init>(Lcs0/b0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lcs0/a0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcs0/a0;->f:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iget-object p1, p0, Lcs0/b0;->a:Las0/g;

    .line 60
    .line 61
    iget-object p1, p1, Las0/g;->b:Lal0/i;

    .line 62
    .line 63
    iput v4, v0, Lcs0/a0;->f:I

    .line 64
    .line 65
    invoke-static {p1, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    if-ne p1, v1, :cond_4

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_4
    :goto_1
    check-cast p1, Lds0/e;

    .line 73
    .line 74
    iput v3, v0, Lcs0/a0;->f:I

    .line 75
    .line 76
    iget-object v2, p0, Lcs0/b0;->b:Las0/e;

    .line 77
    .line 78
    iget-object v3, v2, Las0/e;->a:Lxl0/f;

    .line 79
    .line 80
    new-instance v4, La2/c;

    .line 81
    .line 82
    const/4 v6, 0x4

    .line 83
    invoke-direct {v4, v6, v2, p1, v5}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v3, v4, v0}, Lxl0/f;->i(Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    if-ne p1, v1, :cond_5

    .line 91
    .line 92
    :goto_2
    return-object v1

    .line 93
    :cond_5
    :goto_3
    check-cast p1, Lne0/t;

    .line 94
    .line 95
    instance-of p1, p1, Lne0/c;

    .line 96
    .line 97
    if-eqz p1, :cond_6

    .line 98
    .line 99
    new-instance p1, Lc91/u;

    .line 100
    .line 101
    const/16 v0, 0x17

    .line 102
    .line 103
    invoke-direct {p1, v0}, Lc91/u;-><init>(I)V

    .line 104
    .line 105
    .line 106
    invoke-static {v5, p0, p1}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 107
    .line 108
    .line 109
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 110
    .line 111
    return-object p0
.end method
