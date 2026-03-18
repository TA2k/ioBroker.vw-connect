.class public final Lcs0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Las0/g;

.field public final b:Llm0/c;


# direct methods
.method public constructor <init>(Las0/g;Llm0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcs0/p;->a:Las0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lcs0/p;->b:Llm0/c;

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
    invoke-virtual {p0, p2}, Lcs0/p;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lcs0/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lcs0/o;

    .line 7
    .line 8
    iget v1, v0, Lcs0/o;->g:I

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
    iput v1, v0, Lcs0/o;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcs0/o;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lcs0/o;-><init>(Lcs0/p;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lcs0/o;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcs0/o;->g:I

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
    iget-object p0, v0, Lcs0/o;->d:Lds0/d;

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
    iget-object p1, p0, Lcs0/p;->a:Las0/g;

    .line 61
    .line 62
    iget-object p1, p1, Las0/g;->b:Lal0/i;

    .line 63
    .line 64
    iput v4, v0, Lcs0/o;->g:I

    .line 65
    .line 66
    invoke-static {p1, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-ne p1, v1, :cond_4

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_4
    :goto_1
    check-cast p1, Lds0/e;

    .line 74
    .line 75
    if-eqz p1, :cond_5

    .line 76
    .line 77
    iget-object p1, p1, Lds0/e;->a:Lds0/d;

    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_5
    sget-object p1, Lds0/d;->d:Lds0/d;

    .line 81
    .line 82
    :goto_2
    iput-object p1, v0, Lcs0/o;->d:Lds0/d;

    .line 83
    .line 84
    iput v3, v0, Lcs0/o;->g:I

    .line 85
    .line 86
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 87
    .line 88
    iget-object p0, p0, Lcs0/p;->b:Llm0/c;

    .line 89
    .line 90
    invoke-virtual {p0, v2, v0}, Llm0/c;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    if-ne p0, v1, :cond_6

    .line 95
    .line 96
    :goto_3
    return-object v1

    .line 97
    :cond_6
    move-object v5, p1

    .line 98
    move-object p1, p0

    .line 99
    move-object p0, v5

    .line 100
    :goto_4
    check-cast p1, Lmm0/a;

    .line 101
    .line 102
    sget-object v0, Lds0/d;->d:Lds0/d;

    .line 103
    .line 104
    if-eq p0, v0, :cond_7

    .line 105
    .line 106
    invoke-static {p0}, Ljp/ig;->b(Lds0/d;)Lmm0/a;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    if-eq p0, p1, :cond_7

    .line 111
    .line 112
    goto :goto_5

    .line 113
    :cond_7
    const/4 v4, 0x0

    .line 114
    :goto_5
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    return-object p0
.end method
