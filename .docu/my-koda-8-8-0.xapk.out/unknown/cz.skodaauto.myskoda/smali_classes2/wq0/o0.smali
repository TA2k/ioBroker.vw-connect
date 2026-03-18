.class public final Lwq0/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lwq0/a;

.field public final b:Lwq0/m0;


# direct methods
.method public constructor <init>(Lwq0/a;Lwq0/m0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwq0/o0;->a:Lwq0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lwq0/o0;->b:Lwq0/m0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lyq0/k;

    .line 2
    .line 3
    iget-object p1, p1, Lyq0/k;->a:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lwq0/o0;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lwq0/n0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lwq0/n0;

    .line 7
    .line 8
    iget v1, v0, Lwq0/n0;->g:I

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
    iput v1, v0, Lwq0/n0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwq0/n0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lwq0/n0;-><init>(Lwq0/o0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lwq0/n0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwq0/n0;->g:I

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
    iget-object p0, v0, Lwq0/n0;->d:Lne0/e;

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_3

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iput v4, v0, Lwq0/n0;->g:I

    .line 61
    .line 62
    iget-object p2, p0, Lwq0/o0;->a:Lwq0/a;

    .line 63
    .line 64
    check-cast p2, Luq0/a;

    .line 65
    .line 66
    iget-object v2, p2, Luq0/a;->f:Lyy0/q1;

    .line 67
    .line 68
    invoke-virtual {v2}, Lyy0/q1;->q()V

    .line 69
    .line 70
    .line 71
    iget-object p2, p2, Luq0/a;->d:Lyy0/q1;

    .line 72
    .line 73
    new-instance v4, Lyq0/k;

    .line 74
    .line 75
    invoke-direct {v4, p1}, Lyq0/k;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p2, v4}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    invoke-static {v2, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p2

    .line 85
    if-ne p2, v1, :cond_4

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_4
    :goto_1
    move-object p1, p2

    .line 89
    check-cast p1, Lne0/t;

    .line 90
    .line 91
    instance-of p2, p1, Lne0/e;

    .line 92
    .line 93
    if-eqz p2, :cond_6

    .line 94
    .line 95
    move-object p2, p1

    .line 96
    check-cast p2, Lne0/e;

    .line 97
    .line 98
    iget-object v2, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v2, Lyq0/g;

    .line 101
    .line 102
    iput-object p2, v0, Lwq0/n0;->d:Lne0/e;

    .line 103
    .line 104
    iput v3, v0, Lwq0/n0;->g:I

    .line 105
    .line 106
    iget-object p0, p0, Lwq0/o0;->b:Lwq0/m0;

    .line 107
    .line 108
    check-cast p0, Ltq0/i;

    .line 109
    .line 110
    invoke-virtual {p0, v2, v0}, Ltq0/i;->d(Lyq0/g;Lrx0/c;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    if-ne p0, v1, :cond_5

    .line 115
    .line 116
    :goto_2
    return-object v1

    .line 117
    :cond_5
    move-object p0, p1

    .line 118
    :goto_3
    move-object p1, p0

    .line 119
    :cond_6
    new-instance p0, Lw81/d;

    .line 120
    .line 121
    const/4 p2, 0x7

    .line 122
    invoke-direct {p0, p2}, Lw81/d;-><init>(I)V

    .line 123
    .line 124
    .line 125
    invoke-static {p1, p0}, Lbb/j0;->c(Lne0/t;Lay0/k;)Lne0/t;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0
.end method
