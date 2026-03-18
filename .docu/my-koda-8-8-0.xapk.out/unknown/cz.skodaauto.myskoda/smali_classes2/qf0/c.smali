.class public final Lqf0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lqf0/a;

.field public final b:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Lqf0/a;Ljava/util/ArrayList;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqf0/c;->a:Lqf0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lqf0/c;->b:Ljava/util/ArrayList;

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
    invoke-virtual {p0, p2}, Lqf0/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lqf0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lqf0/b;

    .line 7
    .line 8
    iget v1, v0, Lqf0/b;->h:I

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
    iput v1, v0, Lqf0/b;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lqf0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lqf0/b;-><init>(Lqf0/c;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lqf0/b;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lqf0/b;->h:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    iget p0, v0, Lqf0/b;->e:I

    .line 42
    .line 43
    iget-object v2, v0, Lqf0/b;->d:Ljava/util/Iterator;

    .line 44
    .line 45
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_3

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iput v5, v0, Lqf0/b;->h:I

    .line 65
    .line 66
    iget-object p1, p0, Lqf0/c;->a:Lqf0/a;

    .line 67
    .line 68
    check-cast p1, Lof0/b;

    .line 69
    .line 70
    iget-object p1, p1, Lof0/b;->a:Lve0/u;

    .line 71
    .line 72
    const-string v2, "PREF_DEMO_ENABLED"

    .line 73
    .line 74
    invoke-virtual {p1, v5, v2, v0}, Lve0/u;->l(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    if-ne p1, v1, :cond_4

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_4
    move-object p1, v3

    .line 82
    :goto_1
    if-ne p1, v1, :cond_5

    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_5
    :goto_2
    new-instance p1, Lpd/f0;

    .line 86
    .line 87
    const/16 v2, 0x1c

    .line 88
    .line 89
    invoke-direct {p1, v2}, Lpd/f0;-><init>(I)V

    .line 90
    .line 91
    .line 92
    invoke-static {p0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 93
    .line 94
    .line 95
    new-instance p1, Lpd/f0;

    .line 96
    .line 97
    const/16 v2, 0x1d

    .line 98
    .line 99
    invoke-direct {p1, v2}, Lpd/f0;-><init>(I)V

    .line 100
    .line 101
    .line 102
    invoke-static {p0, p1}, Llp/nd;->n(Ljava/lang/Object;Lay0/a;)V

    .line 103
    .line 104
    .line 105
    iget-object p0, p0, Lqf0/c;->b:Ljava/util/ArrayList;

    .line 106
    .line 107
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    const/4 p1, 0x0

    .line 112
    move-object v2, p0

    .line 113
    move p0, p1

    .line 114
    :cond_6
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 115
    .line 116
    .line 117
    move-result p1

    .line 118
    if-eqz p1, :cond_7

    .line 119
    .line 120
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    check-cast p1, Lme0/a;

    .line 125
    .line 126
    iput-object v2, v0, Lqf0/b;->d:Ljava/util/Iterator;

    .line 127
    .line 128
    iput p0, v0, Lqf0/b;->e:I

    .line 129
    .line 130
    iput v4, v0, Lqf0/b;->h:I

    .line 131
    .line 132
    invoke-interface {p1, v0}, Lme0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p1

    .line 136
    if-ne p1, v1, :cond_6

    .line 137
    .line 138
    :goto_4
    return-object v1

    .line 139
    :cond_7
    return-object v3
.end method
