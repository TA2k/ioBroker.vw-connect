.class public final Lcs0/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Las0/g;

.field public final b:Lcs0/b0;

.field public final c:Lcs0/c;


# direct methods
.method public constructor <init>(Las0/g;Lcs0/b0;Lcs0/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcs0/f0;->a:Las0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lcs0/f0;->b:Lcs0/b0;

    .line 7
    .line 8
    iput-object p3, p0, Lcs0/f0;->c:Lcs0/c;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lds0/d;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lcs0/f0;->b(Lds0/d;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lds0/d;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Lcs0/e0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lcs0/e0;

    .line 7
    .line 8
    iget v1, v0, Lcs0/e0;->g:I

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
    iput v1, v0, Lcs0/e0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lcs0/e0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lcs0/e0;-><init>(Lcs0/f0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lcs0/e0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lcs0/e0;->g:I

    .line 30
    .line 31
    iget-object v3, p0, Lcs0/f0;->a:Las0/g;

    .line 32
    .line 33
    const/4 v4, 0x4

    .line 34
    const/4 v5, 0x3

    .line 35
    const/4 v6, 0x2

    .line 36
    const/4 v7, 0x1

    .line 37
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    const/4 v9, 0x0

    .line 40
    if-eqz v2, :cond_5

    .line 41
    .line 42
    if-eq v2, v7, :cond_4

    .line 43
    .line 44
    if-eq v2, v6, :cond_3

    .line 45
    .line 46
    if-eq v2, v5, :cond_2

    .line 47
    .line 48
    if-ne v2, v4, :cond_1

    .line 49
    .line 50
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    return-object v8

    .line 54
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 55
    .line 56
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 57
    .line 58
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    goto :goto_2

    .line 70
    :cond_4
    iget-object p1, v0, Lcs0/e0;->d:Lds0/d;

    .line 71
    .line 72
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_5
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    iget-object p2, v3, Las0/g;->b:Lal0/i;

    .line 80
    .line 81
    iput-object p1, v0, Lcs0/e0;->d:Lds0/d;

    .line 82
    .line 83
    iput v7, v0, Lcs0/e0;->g:I

    .line 84
    .line 85
    invoke-static {p2, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    if-ne p2, v1, :cond_6

    .line 90
    .line 91
    goto :goto_4

    .line 92
    :cond_6
    :goto_1
    check-cast p2, Lds0/e;

    .line 93
    .line 94
    const/4 v2, 0x0

    .line 95
    const/4 v7, 0x6

    .line 96
    invoke-static {p2, p1, v9, v2, v7}, Lds0/e;->a(Lds0/e;Lds0/d;Lqr0/s;ZI)Lds0/e;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    iput-object v9, v0, Lcs0/e0;->d:Lds0/d;

    .line 101
    .line 102
    iput v6, v0, Lcs0/e0;->g:I

    .line 103
    .line 104
    invoke-virtual {v3, p1, v0}, Las0/g;->b(Lds0/e;Lrx0/c;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    if-ne p1, v1, :cond_7

    .line 109
    .line 110
    goto :goto_4

    .line 111
    :cond_7
    :goto_2
    iput-object v9, v0, Lcs0/e0;->d:Lds0/d;

    .line 112
    .line 113
    iput v5, v0, Lcs0/e0;->g:I

    .line 114
    .line 115
    iget-object p1, p0, Lcs0/f0;->b:Lcs0/b0;

    .line 116
    .line 117
    invoke-virtual {p1, v0}, Lcs0/b0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    if-ne p1, v1, :cond_8

    .line 122
    .line 123
    goto :goto_4

    .line 124
    :cond_8
    :goto_3
    iput-object v9, v0, Lcs0/e0;->d:Lds0/d;

    .line 125
    .line 126
    iput v4, v0, Lcs0/e0;->g:I

    .line 127
    .line 128
    iget-object p0, p0, Lcs0/f0;->c:Lcs0/c;

    .line 129
    .line 130
    invoke-virtual {p0, v0}, Lcs0/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    if-ne p0, v1, :cond_9

    .line 135
    .line 136
    :goto_4
    return-object v1

    .line 137
    :cond_9
    return-object v8
.end method
