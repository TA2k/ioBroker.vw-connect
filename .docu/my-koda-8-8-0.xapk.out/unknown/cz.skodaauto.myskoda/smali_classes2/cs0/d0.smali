.class public final Lcs0/d0;
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
    iput-object p1, p0, Lcs0/d0;->a:Las0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lcs0/d0;->b:Lcs0/b0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/Boolean;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {p0, p1, p2}, Lcs0/d0;->b(ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final b(ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lcs0/c0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lcs0/c0;

    .line 7
    .line 8
    iget v1, v0, Lcs0/c0;->g:I

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
    iput v1, v0, Lcs0/c0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcs0/c0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lcs0/c0;-><init>(Lcs0/d0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lcs0/c0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcs0/c0;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    iget-object v4, p0, Lcs0/d0;->a:Las0/g;

    .line 34
    .line 35
    const/4 v5, 0x3

    .line 36
    const/4 v6, 0x2

    .line 37
    const/4 v7, 0x1

    .line 38
    if-eqz v2, :cond_4

    .line 39
    .line 40
    if-eq v2, v7, :cond_3

    .line 41
    .line 42
    if-eq v2, v6, :cond_2

    .line 43
    .line 44
    if-ne v2, v5, :cond_1

    .line 45
    .line 46
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    return-object v3

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    iget-boolean p1, v0, Lcs0/c0;->d:Z

    .line 59
    .line 60
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_3
    iget-boolean p1, v0, Lcs0/c0;->d:Z

    .line 65
    .line 66
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    iget-object p2, v4, Las0/g;->b:Lal0/i;

    .line 74
    .line 75
    iput-boolean p1, v0, Lcs0/c0;->d:Z

    .line 76
    .line 77
    iput v7, v0, Lcs0/c0;->g:I

    .line 78
    .line 79
    invoke-static {p2, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p2

    .line 83
    if-ne p2, v1, :cond_5

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_5
    :goto_1
    check-cast p2, Lds0/e;

    .line 87
    .line 88
    const/4 v2, 0x0

    .line 89
    invoke-static {p2, v2, v2, p1, v5}, Lds0/e;->a(Lds0/e;Lds0/d;Lqr0/s;ZI)Lds0/e;

    .line 90
    .line 91
    .line 92
    move-result-object p2

    .line 93
    iput-boolean p1, v0, Lcs0/c0;->d:Z

    .line 94
    .line 95
    iput v6, v0, Lcs0/c0;->g:I

    .line 96
    .line 97
    invoke-virtual {v4, p2, v0}, Las0/g;->b(Lds0/e;Lrx0/c;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object p2

    .line 101
    if-ne p2, v1, :cond_6

    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_6
    :goto_2
    iput-boolean p1, v0, Lcs0/c0;->d:Z

    .line 105
    .line 106
    iput v5, v0, Lcs0/c0;->g:I

    .line 107
    .line 108
    iget-object p0, p0, Lcs0/d0;->b:Lcs0/b0;

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
