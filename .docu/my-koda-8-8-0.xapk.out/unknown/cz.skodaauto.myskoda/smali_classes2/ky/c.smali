.class public final Lky/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lf40/w0;

.field public final b:Lf40/u0;


# direct methods
.method public constructor <init>(Lf40/w0;Lf40/u0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lky/c;->a:Lf40/w0;

    .line 5
    .line 6
    iput-object p2, p0, Lky/c;->b:Lf40/u0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lly/b;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lky/c;->c(Lly/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Enum;
    .locals 5

    .line 1
    instance-of v0, p1, Lky/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lky/b;

    .line 7
    .line 8
    iget v1, v0, Lky/b;->f:I

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
    iput v1, v0, Lky/b;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lky/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lky/b;-><init>(Lky/c;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lky/b;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lky/b;->f:I

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
    iput v4, v0, Lky/b;->f:I

    .line 59
    .line 60
    iget-object p1, p0, Lky/c;->a:Lf40/w0;

    .line 61
    .line 62
    invoke-virtual {p1, v0}, Lf40/w0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    sget-object p0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->LoyaltyProgramIntro:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 78
    .line 79
    return-object p0

    .line 80
    :cond_5
    iput v3, v0, Lky/b;->f:I

    .line 81
    .line 82
    iget-object p0, p0, Lky/c;->b:Lf40/u0;

    .line 83
    .line 84
    invoke-virtual {p0, v0}, Lf40/u0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    if-ne p1, v1, :cond_6

    .line 89
    .line 90
    :goto_2
    return-object v1

    .line 91
    :cond_6
    :goto_3
    check-cast p1, Ljava/lang/Boolean;

    .line 92
    .line 93
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    if-eqz p0, :cond_7

    .line 98
    .line 99
    sget-object p0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->LoyaltyProgramBadgesIntro:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 100
    .line 101
    return-object p0

    .line 102
    :cond_7
    sget-object p0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->Application:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 103
    .line 104
    return-object p0
.end method

.method public final c(Lly/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p1, -0x1

    .line 4
    goto :goto_0

    .line 5
    :cond_0
    sget-object v0, Lky/a;->a:[I

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    aget p1, v0, p1

    .line 12
    .line 13
    :goto_0
    const/4 v0, 0x1

    .line 14
    if-eq p1, v0, :cond_2

    .line 15
    .line 16
    const/4 v0, 0x2

    .line 17
    if-eq p1, v0, :cond_2

    .line 18
    .line 19
    const/4 p0, 0x3

    .line 20
    if-eq p1, p0, :cond_1

    .line 21
    .line 22
    sget-object p0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->Application:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_1
    sget-object p0, Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;->LoyaltyProgramIntro:Lcz/skodaauto/myskoda/library/deeplink/model/DeepLink;

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_2
    invoke-virtual {p0, p2}, Lky/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
