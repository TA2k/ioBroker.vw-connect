.class public final Ls40/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:I

.field public final synthetic e:Ls40/d;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Ljava/time/OffsetDateTime;

.field public final synthetic i:Z

.field public final synthetic j:Ljava/lang/Float;

.field public final synthetic k:Ljava/lang/Float;

.field public final synthetic l:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ls40/d;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;ZLjava/lang/Float;Ljava/lang/Float;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ls40/b;->e:Ls40/d;

    .line 2
    .line 3
    iput-object p2, p0, Ls40/b;->f:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p3, p0, Ls40/b;->g:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p4, p0, Ls40/b;->h:Ljava/time/OffsetDateTime;

    .line 8
    .line 9
    iput-boolean p5, p0, Ls40/b;->i:Z

    .line 10
    .line 11
    iput-object p6, p0, Ls40/b;->j:Ljava/lang/Float;

    .line 12
    .line 13
    iput-object p7, p0, Ls40/b;->k:Ljava/lang/Float;

    .line 14
    .line 15
    iput-object p8, p0, Ls40/b;->l:Ljava/lang/String;

    .line 16
    .line 17
    const/4 p1, 0x1

    .line 18
    invoke-direct {p0, p1, p9}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 10

    .line 1
    new-instance v0, Ls40/b;

    .line 2
    .line 3
    iget-object v7, p0, Ls40/b;->k:Ljava/lang/Float;

    .line 4
    .line 5
    iget-object v8, p0, Ls40/b;->l:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v1, p0, Ls40/b;->e:Ls40/d;

    .line 8
    .line 9
    iget-object v2, p0, Ls40/b;->f:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v3, p0, Ls40/b;->g:Ljava/lang/String;

    .line 12
    .line 13
    iget-object v4, p0, Ls40/b;->h:Ljava/time/OffsetDateTime;

    .line 14
    .line 15
    iget-boolean v5, p0, Ls40/b;->i:Z

    .line 16
    .line 17
    iget-object v6, p0, Ls40/b;->j:Ljava/lang/Float;

    .line 18
    .line 19
    move-object v9, p1

    .line 20
    invoke-direct/range {v0 .. v9}, Ls40/b;-><init>(Ls40/d;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;ZLjava/lang/Float;Ljava/lang/Float;Ljava/lang/String;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ls40/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ls40/b;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Ls40/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Ls40/b;->d:I

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
    iget-object p1, p0, Ls40/b;->e:Ls40/d;

    .line 33
    .line 34
    iget-object p1, p1, Ls40/d;->b:Lti0/a;

    .line 35
    .line 36
    iput v3, p0, Ls40/b;->d:I

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
    move-object v3, p1

    .line 46
    check-cast v3, Lcz/myskoda/api/bff/v1/ParkingApi;

    .line 47
    .line 48
    iget-boolean p1, p0, Ls40/b;->i:Z

    .line 49
    .line 50
    if-eqz p1, :cond_4

    .line 51
    .line 52
    const-string p1, "PAY_PARKING_ZONE"

    .line 53
    .line 54
    :goto_1
    move-object v7, p1

    .line 55
    goto :goto_2

    .line 56
    :cond_4
    const-string p1, "PAY_PARKING"

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :goto_2
    iput v2, p0, Ls40/b;->d:I

    .line 60
    .line 61
    iget-object v4, p0, Ls40/b;->f:Ljava/lang/String;

    .line 62
    .line 63
    iget-object v5, p0, Ls40/b;->g:Ljava/lang/String;

    .line 64
    .line 65
    iget-object v6, p0, Ls40/b;->h:Ljava/time/OffsetDateTime;

    .line 66
    .line 67
    iget-object v8, p0, Ls40/b;->j:Ljava/lang/Float;

    .line 68
    .line 69
    iget-object v9, p0, Ls40/b;->k:Ljava/lang/Float;

    .line 70
    .line 71
    iget-object v10, p0, Ls40/b;->l:Ljava/lang/String;

    .line 72
    .line 73
    move-object v11, p0

    .line 74
    invoke-interface/range {v3 .. v11}, Lcz/myskoda/api/bff/v1/ParkingApi;->getParkingPrice(Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;Ljava/lang/Float;Ljava/lang/Float;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    if-ne p0, v0, :cond_5

    .line 79
    .line 80
    :goto_3
    return-object v0

    .line 81
    :cond_5
    return-object p0
.end method
