.class public final Lwq0/i;
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
    iput-object p1, p0, Lwq0/i;->a:Lwq0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lwq0/i;->b:Lwq0/m0;

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
    invoke-virtual {p0, p2}, Lwq0/i;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p1, Lwq0/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lwq0/h;

    .line 7
    .line 8
    iget v1, v0, Lwq0/h;->f:I

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
    iput v1, v0, Lwq0/h;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwq0/h;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lwq0/h;-><init>(Lwq0/i;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lwq0/h;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwq0/h;->f:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-object p1

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iput v4, v0, Lwq0/h;->f:I

    .line 59
    .line 60
    iget-object p1, p0, Lwq0/i;->b:Lwq0/m0;

    .line 61
    .line 62
    check-cast p1, Ltq0/i;

    .line 63
    .line 64
    invoke-virtual {p1, v0}, Ltq0/i;->b(Lrx0/c;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-ne p1, v1, :cond_4

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_4
    :goto_1
    check-cast p1, Lyq0/g;

    .line 72
    .line 73
    if-nez p1, :cond_5

    .line 74
    .line 75
    new-instance v4, Lne0/c;

    .line 76
    .line 77
    new-instance v5, Lyq0/i;

    .line 78
    .line 79
    const-string p0, "No spin saved"

    .line 80
    .line 81
    invoke-direct {v5, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    const/4 v8, 0x0

    .line 85
    const/16 v9, 0x1e

    .line 86
    .line 87
    const/4 v6, 0x0

    .line 88
    const/4 v7, 0x0

    .line 89
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 90
    .line 91
    .line 92
    return-object v4

    .line 93
    :cond_5
    new-instance v2, Lvd/i;

    .line 94
    .line 95
    const/16 v4, 0x1a

    .line 96
    .line 97
    invoke-direct {v2, v4}, Lvd/i;-><init>(I)V

    .line 98
    .line 99
    .line 100
    invoke-static {p0, v2}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 101
    .line 102
    .line 103
    iput v3, v0, Lwq0/h;->f:I

    .line 104
    .line 105
    iget-object p0, p0, Lwq0/i;->a:Lwq0/a;

    .line 106
    .line 107
    check-cast p0, Luq0/a;

    .line 108
    .line 109
    iget-object v2, p0, Luq0/a;->i:Lyy0/q1;

    .line 110
    .line 111
    invoke-virtual {v2}, Lyy0/q1;->q()V

    .line 112
    .line 113
    .line 114
    iget-object p0, p0, Luq0/a;->g:Lyy0/q1;

    .line 115
    .line 116
    invoke-virtual {p0, p1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    invoke-static {v2, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    if-ne p0, v1, :cond_6

    .line 124
    .line 125
    :goto_2
    return-object v1

    .line 126
    :cond_6
    return-object p0
.end method
