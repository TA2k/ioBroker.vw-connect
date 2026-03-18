.class public final Li70/u;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:I

.field public final synthetic e:Li70/v;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ll70/w;

.field public final synthetic h:I


# direct methods
.method public constructor <init>(Li70/v;Ljava/lang/String;Ll70/w;ILkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Li70/u;->e:Li70/v;

    .line 2
    .line 3
    iput-object p2, p0, Li70/u;->f:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p3, p0, Li70/u;->g:Ll70/w;

    .line 6
    .line 7
    iput p4, p0, Li70/u;->h:I

    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6

    .line 1
    new-instance v0, Li70/u;

    .line 2
    .line 3
    iget-object v3, p0, Li70/u;->g:Ll70/w;

    .line 4
    .line 5
    iget v4, p0, Li70/u;->h:I

    .line 6
    .line 7
    iget-object v1, p0, Li70/u;->e:Li70/v;

    .line 8
    .line 9
    iget-object v2, p0, Li70/u;->f:Ljava/lang/String;

    .line 10
    .line 11
    move-object v5, p1

    .line 12
    invoke-direct/range {v0 .. v5}, Li70/u;-><init>(Li70/v;Ljava/lang/String;Ll70/w;ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Li70/u;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Li70/u;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Li70/u;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Li70/u;->d:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x1

    .line 7
    if-eqz v1, :cond_2

    .line 8
    .line 9
    if-eq v1, v3, :cond_1

    .line 10
    .line 11
    if-ne v1, v2, :cond_0

    .line 12
    .line 13
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 18
    .line 19
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 20
    .line 21
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p1, p0, Li70/u;->e:Li70/v;

    .line 33
    .line 34
    iget-object p1, p1, Li70/v;->b:Lti0/a;

    .line 35
    .line 36
    iput v3, p0, Li70/u;->d:I

    .line 37
    .line 38
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    if-ne p1, v0, :cond_3

    .line 43
    .line 44
    goto :goto_3

    .line 45
    :cond_3
    :goto_0
    move-object v4, p1

    .line 46
    check-cast v4, Lcz/myskoda/api/bff/v1/TripStatisticsApi;

    .line 47
    .line 48
    const-string p1, "<this>"

    .line 49
    .line 50
    iget-object v1, p0, Li70/u;->g:Ll70/w;

    .line 51
    .line 52
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    if-eqz p1, :cond_6

    .line 60
    .line 61
    if-eq p1, v3, :cond_5

    .line 62
    .line 63
    if-ne p1, v2, :cond_4

    .line 64
    .line 65
    sget-object p1, Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;->YEAR:Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;

    .line 66
    .line 67
    :goto_1
    move-object v6, p1

    .line 68
    goto :goto_2

    .line 69
    :cond_4
    new-instance p0, La8/r0;

    .line 70
    .line 71
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 72
    .line 73
    .line 74
    throw p0

    .line 75
    :cond_5
    sget-object p1, Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;->MONTH:Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_6
    sget-object p1, Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;->WEEK:Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :goto_2
    invoke-static {}, Ljava/time/ZoneId;->systemDefault()Ljava/time/ZoneId;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    invoke-virtual {p1}, Ljava/time/ZoneId;->getId()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v8

    .line 89
    iput v2, p0, Li70/u;->d:I

    .line 90
    .line 91
    iget-object v5, p0, Li70/u;->f:Ljava/lang/String;

    .line 92
    .line 93
    iget v7, p0, Li70/u;->h:I

    .line 94
    .line 95
    move-object v9, p0

    .line 96
    invoke-interface/range {v4 .. v9}, Lcz/myskoda/api/bff/v1/TripStatisticsApi;->getTripStatistics(Ljava/lang/String;Lcz/myskoda/api/bff/v1/TripStatisticsApi$OffsetTypeGetTripStatistics;ILjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    if-ne p0, v0, :cond_7

    .line 101
    .line 102
    :goto_3
    return-object v0

    .line 103
    :cond_7
    return-object p0
.end method
