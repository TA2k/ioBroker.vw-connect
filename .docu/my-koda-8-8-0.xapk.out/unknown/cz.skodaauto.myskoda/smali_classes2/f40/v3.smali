.class public final Lf40/v3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lf40/d1;


# direct methods
.method public constructor <init>(Lf40/d1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf40/v3;->a:Lf40/d1;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lf40/v3;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lf40/u3;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lf40/u3;

    .line 7
    .line 8
    iget v1, v0, Lf40/u3;->g:I

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
    iput v1, v0, Lf40/u3;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lf40/u3;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lf40/u3;-><init>(Lf40/v3;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lf40/u3;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lf40/u3;->g:I

    .line 30
    .line 31
    iget-object p0, p0, Lf40/v3;->a:Lf40/d1;

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v3, :cond_1

    .line 37
    .line 38
    iget-object p1, v0, Lf40/u3;->d:Ljava/lang/String;

    .line 39
    .line 40
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    move-object p2, p0

    .line 56
    check-cast p2, Ld40/f;

    .line 57
    .line 58
    iget-object p2, p2, Ld40/f;->d:Lyy0/l1;

    .line 59
    .line 60
    new-instance v2, La50/h;

    .line 61
    .line 62
    const/16 v4, 0x15

    .line 63
    .line 64
    invoke-direct {v2, p2, v4}, La50/h;-><init>(Lyy0/i;I)V

    .line 65
    .line 66
    .line 67
    iput-object p1, v0, Lf40/u3;->d:Ljava/lang/String;

    .line 68
    .line 69
    iput v3, v0, Lf40/u3;->g:I

    .line 70
    .line 71
    invoke-static {v2, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p2

    .line 75
    if-ne p2, v1, :cond_3

    .line 76
    .line 77
    return-object v1

    .line 78
    :cond_3
    :goto_1
    const-string v0, "null cannot be cast to non-null type cz.skodaauto.myskoda.library.data.infrastructure.Data.Success<cz.skodaauto.myskoda.feature.loyaltyprogram.model.Rewards>"

    .line 79
    .line 80
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    check-cast p2, Lne0/e;

    .line 84
    .line 85
    iget-object p2, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast p2, Lg40/t0;

    .line 88
    .line 89
    iget-object p2, p2, Lg40/t0;->f:Ljava/util/ArrayList;

    .line 90
    .line 91
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 92
    .line 93
    .line 94
    move-result-object p2

    .line 95
    :cond_4
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    if-eqz v0, :cond_5

    .line 100
    .line 101
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    move-object v1, v0

    .line 106
    check-cast v1, Lg40/b0;

    .line 107
    .line 108
    iget-object v1, v1, Lg40/b0;->a:Ljava/lang/String;

    .line 109
    .line 110
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v1

    .line 114
    if-eqz v1, :cond_4

    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_5
    const/4 v0, 0x0

    .line 118
    :goto_2
    check-cast v0, Lg40/b0;

    .line 119
    .line 120
    check-cast p0, Ld40/f;

    .line 121
    .line 122
    iput-object v0, p0, Ld40/f;->h:Lg40/b0;

    .line 123
    .line 124
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 125
    .line 126
    return-object p0
.end method
