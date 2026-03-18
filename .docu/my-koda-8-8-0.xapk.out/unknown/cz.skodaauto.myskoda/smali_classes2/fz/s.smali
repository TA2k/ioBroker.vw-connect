.class public final Lfz/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lfz/u;


# direct methods
.method public constructor <init>(Lfz/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfz/s;->a:Lfz/u;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lfz/s;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Lfz/r;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lfz/r;

    .line 7
    .line 8
    iget v1, v0, Lfz/r;->f:I

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
    iput v1, v0, Lfz/r;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lfz/r;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lfz/r;-><init>(Lfz/s;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lfz/r;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lfz/r;->f:I

    .line 30
    .line 31
    iget-object p0, p0, Lfz/s;->a:Lfz/u;

    .line 32
    .line 33
    const/4 v3, 0x2

    .line 34
    const/4 v4, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

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
    iput v4, v0, Lfz/r;->f:I

    .line 61
    .line 62
    move-object p1, p0

    .line 63
    check-cast p1, Ldz/g;

    .line 64
    .line 65
    invoke-virtual {p1, v0}, Ldz/g;->b(Lrx0/c;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    if-ne p1, v1, :cond_4

    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_4
    :goto_1
    check-cast p1, Ljava/time/Instant;

    .line 73
    .line 74
    if-eqz p1, :cond_5

    .line 75
    .line 76
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    const-wide/16 v0, 0x7

    .line 81
    .line 82
    sget-object v2, Ljava/time/temporal/ChronoUnit;->DAYS:Ljava/time/temporal/ChronoUnit;

    .line 83
    .line 84
    invoke-virtual {p0, v0, v1, v2}, Ljava/time/Instant;->minus(JLjava/time/temporal/TemporalUnit;)Ljava/time/Instant;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-virtual {p1, p0}, Ljava/time/Instant;->isBefore(Ljava/time/Instant;)Z

    .line 89
    .line 90
    .line 91
    move-result p0

    .line 92
    goto :goto_5

    .line 93
    :cond_5
    iput v3, v0, Lfz/r;->f:I

    .line 94
    .line 95
    check-cast p0, Ldz/g;

    .line 96
    .line 97
    iget-object p0, p0, Ldz/g;->a:Lve0/u;

    .line 98
    .line 99
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    invoke-virtual {p1}, Ljava/time/Instant;->toEpochMilli()J

    .line 104
    .line 105
    .line 106
    move-result-wide v2

    .line 107
    const-string p1, "PREF_FIRST_CHECK_TIMESTAMP"

    .line 108
    .line 109
    invoke-virtual {p0, p1, v2, v3, v0}, Lve0/u;->m(Ljava/lang/String;JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    if-ne p0, v1, :cond_6

    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 117
    .line 118
    :goto_2
    if-ne p0, v1, :cond_7

    .line 119
    .line 120
    :goto_3
    return-object v1

    .line 121
    :cond_7
    :goto_4
    const/4 p0, 0x0

    .line 122
    :goto_5
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    return-object p0
.end method
