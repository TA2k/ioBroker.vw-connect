.class public final Ld40/l;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:I

.field public final synthetic e:Ld40/n;

.field public final synthetic f:Ljava/lang/String;

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Lg40/n;


# direct methods
.method public constructor <init>(Ld40/n;Ljava/lang/String;Ljava/lang/String;Lg40/n;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ld40/l;->e:Ld40/n;

    .line 2
    .line 3
    iput-object p2, p0, Ld40/l;->f:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p3, p0, Ld40/l;->g:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p4, p0, Ld40/l;->h:Lg40/n;

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
    new-instance v0, Ld40/l;

    .line 2
    .line 3
    iget-object v3, p0, Ld40/l;->g:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v4, p0, Ld40/l;->h:Lg40/n;

    .line 6
    .line 7
    iget-object v1, p0, Ld40/l;->e:Ld40/n;

    .line 8
    .line 9
    iget-object v2, p0, Ld40/l;->f:Ljava/lang/String;

    .line 10
    .line 11
    move-object v5, p1

    .line 12
    invoke-direct/range {v0 .. v5}, Ld40/l;-><init>(Ld40/n;Ljava/lang/String;Ljava/lang/String;Lg40/n;Lkotlin/coroutines/Continuation;)V

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
    invoke-virtual {p0, p1}, Ld40/l;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ld40/l;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Ld40/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Ld40/l;->d:I

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
    iget-object p1, p0, Ld40/l;->e:Ld40/n;

    .line 33
    .line 34
    iget-object p1, p1, Ld40/n;->b:Lti0/a;

    .line 35
    .line 36
    iput v3, p0, Ld40/l;->d:I

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
    goto :goto_2

    .line 45
    :cond_3
    :goto_0
    check-cast p1, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;

    .line 46
    .line 47
    const-string v1, "<this>"

    .line 48
    .line 49
    iget-object v4, p0, Ld40/l;->h:Lg40/n;

    .line 50
    .line 51
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-eqz v1, :cond_5

    .line 59
    .line 60
    if-ne v1, v3, :cond_4

    .line 61
    .line 62
    sget-object v1, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;->PROMO:Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_4
    new-instance p0, La8/r0;

    .line 66
    .line 67
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 68
    .line 69
    .line 70
    throw p0

    .line 71
    :cond_5
    sget-object v1, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;->ACHIEVEMENT:Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;

    .line 72
    .line 73
    :goto_1
    iput v2, p0, Ld40/l;->d:I

    .line 74
    .line 75
    iget-object v2, p0, Ld40/l;->f:Ljava/lang/String;

    .line 76
    .line 77
    iget-object v3, p0, Ld40/l;->g:Ljava/lang/String;

    .line 78
    .line 79
    invoke-interface {p1, v2, v3, v1, p0}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->getBadgeDetail(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi$TypeGetBadgeDetail;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    if-ne p0, v0, :cond_6

    .line 84
    .line 85
    :goto_2
    return-object v0

    .line 86
    :cond_6
    return-object p0
.end method
