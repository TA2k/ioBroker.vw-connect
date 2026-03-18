.class public final Ls40/c;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

.field public e:I

.field public final synthetic f:Ljava/lang/Double;

.field public final synthetic g:Ljava/lang/Double;

.field public final synthetic h:Ls40/d;

.field public final synthetic i:Z

.field public final synthetic j:Ljava/lang/String;

.field public final synthetic k:Ljava/lang/String;

.field public final synthetic l:Ljava/time/OffsetDateTime;

.field public final synthetic m:Ljava/lang/String;

.field public final synthetic n:Ljava/lang/String;

.field public final synthetic o:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/Double;Ljava/lang/Double;Ls40/d;ZLjava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ls40/c;->f:Ljava/lang/Double;

    .line 2
    .line 3
    iput-object p2, p0, Ls40/c;->g:Ljava/lang/Double;

    .line 4
    .line 5
    iput-object p3, p0, Ls40/c;->h:Ls40/d;

    .line 6
    .line 7
    iput-boolean p4, p0, Ls40/c;->i:Z

    .line 8
    .line 9
    iput-object p5, p0, Ls40/c;->j:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p6, p0, Ls40/c;->k:Ljava/lang/String;

    .line 12
    .line 13
    iput-object p7, p0, Ls40/c;->l:Ljava/time/OffsetDateTime;

    .line 14
    .line 15
    iput-object p8, p0, Ls40/c;->m:Ljava/lang/String;

    .line 16
    .line 17
    iput-object p9, p0, Ls40/c;->n:Ljava/lang/String;

    .line 18
    .line 19
    iput-object p10, p0, Ls40/c;->o:Ljava/lang/String;

    .line 20
    .line 21
    const/4 p1, 0x1

    .line 22
    invoke-direct {p0, p1, p11}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 12

    .line 1
    new-instance v0, Ls40/c;

    .line 2
    .line 3
    iget-object v9, p0, Ls40/c;->n:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v10, p0, Ls40/c;->o:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v1, p0, Ls40/c;->f:Ljava/lang/Double;

    .line 8
    .line 9
    iget-object v2, p0, Ls40/c;->g:Ljava/lang/Double;

    .line 10
    .line 11
    iget-object v3, p0, Ls40/c;->h:Ls40/d;

    .line 12
    .line 13
    iget-boolean v4, p0, Ls40/c;->i:Z

    .line 14
    .line 15
    iget-object v5, p0, Ls40/c;->j:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v6, p0, Ls40/c;->k:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v7, p0, Ls40/c;->l:Ljava/time/OffsetDateTime;

    .line 20
    .line 21
    iget-object v8, p0, Ls40/c;->m:Ljava/lang/String;

    .line 22
    .line 23
    move-object v11, p1

    .line 24
    invoke-direct/range {v0 .. v11}, Ls40/c;-><init>(Ljava/lang/Double;Ljava/lang/Double;Ls40/d;ZLjava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ls40/c;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ls40/c;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Ls40/c;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Ls40/c;->e:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x2

    .line 7
    const/4 v4, 0x1

    .line 8
    if-eqz v1, :cond_3

    .line 9
    .line 10
    if-eq v1, v4, :cond_1

    .line 11
    .line 12
    if-ne v1, v3, :cond_0

    .line 13
    .line 14
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-object p1

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 21
    .line 22
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    iget-object v1, p0, Ls40/c;->d:Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    .line 27
    .line 28
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    :cond_2
    move-object v12, v1

    .line 32
    goto :goto_1

    .line 33
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, p0, Ls40/c;->f:Ljava/lang/Double;

    .line 37
    .line 38
    if-eqz p1, :cond_4

    .line 39
    .line 40
    iget-object v1, p0, Ls40/c;->g:Ljava/lang/Double;

    .line 41
    .line 42
    if-eqz v1, :cond_4

    .line 43
    .line 44
    new-instance v5, Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    .line 45
    .line 46
    invoke-virtual {p1}, Ljava/lang/Double;->doubleValue()D

    .line 47
    .line 48
    .line 49
    move-result-wide v6

    .line 50
    invoke-virtual {v1}, Ljava/lang/Double;->doubleValue()D

    .line 51
    .line 52
    .line 53
    move-result-wide v8

    .line 54
    invoke-direct {v5, v6, v7, v8, v9}, Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;-><init>(DD)V

    .line 55
    .line 56
    .line 57
    move-object v1, v5

    .line 58
    goto :goto_0

    .line 59
    :cond_4
    move-object v1, v2

    .line 60
    :goto_0
    iget-object p1, p0, Ls40/c;->h:Ls40/d;

    .line 61
    .line 62
    iget-object p1, p1, Ls40/d;->b:Lti0/a;

    .line 63
    .line 64
    iput-object v1, p0, Ls40/c;->d:Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    .line 65
    .line 66
    iput v4, p0, Ls40/c;->e:I

    .line 67
    .line 68
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    if-ne p1, v0, :cond_2

    .line 73
    .line 74
    goto :goto_4

    .line 75
    :goto_1
    check-cast p1, Lcz/myskoda/api/bff/v1/ParkingApi;

    .line 76
    .line 77
    iget-boolean v1, p0, Ls40/c;->i:Z

    .line 78
    .line 79
    if-eqz v1, :cond_5

    .line 80
    .line 81
    const-string v1, "PAY_PARKING_ZONE"

    .line 82
    .line 83
    :goto_2
    move-object v9, v1

    .line 84
    goto :goto_3

    .line 85
    :cond_5
    const-string v1, "PAY_PARKING"

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :goto_3
    new-instance v4, Lcz/myskoda/api/bff/v1/ParkingSessionPayloadDto;

    .line 89
    .line 90
    iget-object v10, p0, Ls40/c;->n:Ljava/lang/String;

    .line 91
    .line 92
    iget-object v11, p0, Ls40/c;->o:Ljava/lang/String;

    .line 93
    .line 94
    iget-object v5, p0, Ls40/c;->l:Ljava/time/OffsetDateTime;

    .line 95
    .line 96
    iget-object v6, p0, Ls40/c;->m:Ljava/lang/String;

    .line 97
    .line 98
    iget-object v7, p0, Ls40/c;->j:Ljava/lang/String;

    .line 99
    .line 100
    iget-object v8, p0, Ls40/c;->k:Ljava/lang/String;

    .line 101
    .line 102
    invoke-direct/range {v4 .. v12}, Lcz/myskoda/api/bff/v1/ParkingSessionPayloadDto;-><init>(Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;)V

    .line 103
    .line 104
    .line 105
    iput-object v2, p0, Ls40/c;->d:Lcz/myskoda/api/bff/v1/GpsCoordinatesDto;

    .line 106
    .line 107
    iput v3, p0, Ls40/c;->e:I

    .line 108
    .line 109
    invoke-interface {p1, v4, p0}, Lcz/myskoda/api/bff/v1/ParkingApi;->startParkingSession(Lcz/myskoda/api/bff/v1/ParkingSessionPayloadDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    if-ne p0, v0, :cond_6

    .line 114
    .line 115
    :goto_4
    return-object v0

    .line 116
    :cond_6
    return-object p0
.end method
