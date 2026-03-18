.class public final Lod0/a0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:I

.field public final synthetic e:Lod0/b0;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:I


# direct methods
.method public constructor <init>(ILjava/lang/String;Lkotlin/coroutines/Continuation;Lod0/b0;)V
    .locals 0

    .line 1
    iput-object p4, p0, Lod0/a0;->e:Lod0/b0;

    .line 2
    .line 3
    iput-object p2, p0, Lod0/a0;->f:Ljava/lang/String;

    .line 4
    .line 5
    iput p1, p0, Lod0/a0;->g:I

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    new-instance v0, Lod0/a0;

    .line 2
    .line 3
    iget-object v1, p0, Lod0/a0;->f:Ljava/lang/String;

    .line 4
    .line 5
    iget v2, p0, Lod0/a0;->g:I

    .line 6
    .line 7
    iget-object p0, p0, Lod0/a0;->e:Lod0/b0;

    .line 8
    .line 9
    invoke-direct {v0, v2, v1, p1, p0}, Lod0/a0;-><init>(ILjava/lang/String;Lkotlin/coroutines/Continuation;Lod0/b0;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lod0/a0;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lod0/a0;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lod0/a0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Lod0/a0;->d:I

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
    iget-object p1, p0, Lod0/a0;->e:Lod0/b0;

    .line 33
    .line 34
    iget-object p1, p1, Lod0/b0;->b:Lti0/a;

    .line 35
    .line 36
    iput v3, p0, Lod0/a0;->d:I

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
    goto :goto_1

    .line 45
    :cond_3
    :goto_0
    check-cast p1, Lcz/myskoda/api/bff/v1/ChargingApi;

    .line 46
    .line 47
    new-instance v1, Lcz/myskoda/api/bff/v1/ChargingCurrentDto;

    .line 48
    .line 49
    const/4 v4, 0x0

    .line 50
    iget v5, p0, Lod0/a0;->g:I

    .line 51
    .line 52
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 53
    .line 54
    .line 55
    move-result-object v5

    .line 56
    invoke-direct {v1, v4, v5, v3, v4}, Lcz/myskoda/api/bff/v1/ChargingCurrentDto;-><init>(Ljava/lang/String;Ljava/lang/Integer;ILkotlin/jvm/internal/g;)V

    .line 57
    .line 58
    .line 59
    iput v2, p0, Lod0/a0;->d:I

    .line 60
    .line 61
    iget-object v2, p0, Lod0/a0;->f:Ljava/lang/String;

    .line 62
    .line 63
    invoke-interface {p1, v2, v1, p0}, Lcz/myskoda/api/bff/v1/ChargingApi;->updateChargingCurrent(Ljava/lang/String;Lcz/myskoda/api/bff/v1/ChargingCurrentDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    if-ne p0, v0, :cond_4

    .line 68
    .line 69
    :goto_1
    return-object v0

    .line 70
    :cond_4
    return-object p0
.end method
