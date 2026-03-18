.class public final Lfz/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lfz/s;

.field public final b:Lje0/a;


# direct methods
.method public constructor <init>(Lfz/s;Lje0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfz/g;->a:Lfz/s;

    .line 5
    .line 6
    iput-object p2, p0, Lfz/g;->b:Lje0/a;

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
    invoke-virtual {p0, p2}, Lfz/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lfz/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lfz/f;

    .line 7
    .line 8
    iget v1, v0, Lfz/f;->f:I

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
    iput v1, v0, Lfz/f;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lfz/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lfz/f;-><init>(Lfz/g;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lfz/f;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lfz/f;->f:I

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
    goto :goto_3

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
    iput v4, v0, Lfz/f;->f:I

    .line 59
    .line 60
    iget-object p1, p0, Lfz/g;->a:Lfz/s;

    .line 61
    .line 62
    invoke-virtual {p1, v0}, Lfz/s;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    if-ne p1, v1, :cond_4

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_4
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 70
    .line 71
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    if-nez p1, :cond_5

    .line 76
    .line 77
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 78
    .line 79
    return-object p0

    .line 80
    :cond_5
    iput v3, v0, Lfz/f;->f:I

    .line 81
    .line 82
    iget-object p0, p0, Lfz/g;->b:Lje0/a;

    .line 83
    .line 84
    iget-object p0, p0, Lje0/a;->a:Lje0/b;

    .line 85
    .line 86
    check-cast p0, Lhe0/b;

    .line 87
    .line 88
    invoke-virtual {p0, v0}, Lhe0/b;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    if-ne p1, v1, :cond_6

    .line 93
    .line 94
    :goto_2
    return-object v1

    .line 95
    :cond_6
    :goto_3
    check-cast p1, Ljava/time/Instant;

    .line 96
    .line 97
    const/4 p0, 0x0

    .line 98
    if-eqz p1, :cond_7

    .line 99
    .line 100
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 101
    .line 102
    .line 103
    move-result-object v0

    .line 104
    const-wide/16 v1, 0x5

    .line 105
    .line 106
    sget-object v3, Ljava/time/temporal/ChronoUnit;->DAYS:Ljava/time/temporal/ChronoUnit;

    .line 107
    .line 108
    invoke-virtual {v0, v1, v2, v3}, Ljava/time/Instant;->minus(JLjava/time/temporal/TemporalUnit;)Ljava/time/Instant;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    invoke-virtual {p1, v0}, Ljava/time/Instant;->isAfter(Ljava/time/Instant;)Z

    .line 113
    .line 114
    .line 115
    move-result p1

    .line 116
    if-ne p1, v4, :cond_7

    .line 117
    .line 118
    goto :goto_4

    .line 119
    :cond_7
    move v4, p0

    .line 120
    :goto_4
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    return-object p0
.end method
