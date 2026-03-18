.class public final Lcs0/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Las0/g;

.field public final b:Lcs0/b0;


# direct methods
.method public constructor <init>(Las0/g;Lcs0/b0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcs0/h0;->a:Las0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lcs0/h0;->b:Lcs0/b0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lqr0/s;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lcs0/h0;->b(Lqr0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lqr0/s;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p2, Lcs0/g0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lcs0/g0;

    .line 7
    .line 8
    iget v1, v0, Lcs0/g0;->g:I

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
    iput v1, v0, Lcs0/g0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcs0/g0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lcs0/g0;-><init>(Lcs0/h0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lcs0/g0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcs0/g0;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    iget-object v4, p0, Lcs0/h0;->a:Las0/g;

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    const/4 v6, 0x2

    .line 37
    const/4 v7, 0x1

    .line 38
    const/4 v8, 0x0

    .line 39
    if-eqz v2, :cond_4

    .line 40
    .line 41
    if-eq v2, v7, :cond_3

    .line 42
    .line 43
    if-eq v2, v6, :cond_2

    .line 44
    .line 45
    if-ne v2, v5, :cond_1

    .line 46
    .line 47
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    return-object v3

    .line 51
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 52
    .line 53
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 54
    .line 55
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0

    .line 59
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_3
    iget-object p1, v0, Lcs0/g0;->d:Lqr0/s;

    .line 64
    .line 65
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    iget-object p2, v4, Las0/g;->b:Lal0/i;

    .line 73
    .line 74
    iput-object p1, v0, Lcs0/g0;->d:Lqr0/s;

    .line 75
    .line 76
    iput v7, v0, Lcs0/g0;->g:I

    .line 77
    .line 78
    invoke-static {p2, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    if-ne p2, v1, :cond_5

    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_5
    :goto_1
    check-cast p2, Lds0/e;

    .line 86
    .line 87
    const/4 v2, 0x0

    .line 88
    const/4 v7, 0x5

    .line 89
    invoke-static {p2, v8, p1, v2, v7}, Lds0/e;->a(Lds0/e;Lds0/d;Lqr0/s;ZI)Lds0/e;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    iput-object v8, v0, Lcs0/g0;->d:Lqr0/s;

    .line 94
    .line 95
    iput v6, v0, Lcs0/g0;->g:I

    .line 96
    .line 97
    invoke-virtual {v4, p1, v0}, Las0/g;->b(Lds0/e;Lrx0/c;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    if-ne p1, v1, :cond_6

    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_6
    :goto_2
    iput-object v8, v0, Lcs0/g0;->d:Lqr0/s;

    .line 105
    .line 106
    iput v5, v0, Lcs0/g0;->g:I

    .line 107
    .line 108
    iget-object p0, p0, Lcs0/h0;->b:Lcs0/b0;

    .line 109
    .line 110
    invoke-virtual {p0, v0}, Lcs0/b0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    if-ne p0, v1, :cond_7

    .line 115
    .line 116
    :goto_3
    return-object v1

    .line 117
    :cond_7
    return-object v3
.end method
