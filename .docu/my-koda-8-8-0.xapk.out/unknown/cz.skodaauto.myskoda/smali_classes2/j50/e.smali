.class public final Lj50/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:Lbl0/p;

.field public e:I

.field public f:I

.field public final synthetic g:Lbl0/p;

.field public final synthetic h:Lj50/f;


# direct methods
.method public constructor <init>(Lbl0/p;Lj50/f;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lj50/e;->g:Lbl0/p;

    .line 2
    .line 3
    iput-object p2, p0, Lj50/e;->h:Lj50/f;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Lj50/e;

    .line 2
    .line 3
    iget-object v1, p0, Lj50/e;->g:Lbl0/p;

    .line 4
    .line 5
    iget-object p0, p0, Lj50/e;->h:Lj50/f;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p1}, Lj50/e;-><init>(Lbl0/p;Lj50/f;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lj50/e;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lj50/e;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lj50/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v1, p0, Lj50/e;->f:I

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
    goto :goto_2

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
    iget v1, p0, Lj50/e;->e:I

    .line 26
    .line 27
    iget-object v3, p0, Lj50/e;->d:Lbl0/p;

    .line 28
    .line 29
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, p0, Lj50/e;->h:Lj50/f;

    .line 37
    .line 38
    iget-object p1, p1, Lj50/f;->b:Lti0/a;

    .line 39
    .line 40
    iget-object v1, p0, Lj50/e;->g:Lbl0/p;

    .line 41
    .line 42
    iput-object v1, p0, Lj50/e;->d:Lbl0/p;

    .line 43
    .line 44
    const/4 v4, 0x0

    .line 45
    iput v4, p0, Lj50/e;->e:I

    .line 46
    .line 47
    iput v3, p0, Lj50/e;->f:I

    .line 48
    .line 49
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    if-ne p1, v0, :cond_3

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_3
    move-object v3, v1

    .line 57
    move v1, v4

    .line 58
    :goto_0
    move-object v4, p1

    .line 59
    check-cast v4, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 60
    .line 61
    iget-object v5, v3, Lbl0/p;->a:Ljava/lang/String;

    .line 62
    .line 63
    iget-wide v6, v3, Lbl0/p;->b:D

    .line 64
    .line 65
    iget-wide v8, v3, Lbl0/p;->c:D

    .line 66
    .line 67
    iget-object v10, v3, Lbl0/p;->d:Ljava/util/UUID;

    .line 68
    .line 69
    const/4 p1, 0x0

    .line 70
    iput-object p1, p0, Lj50/e;->d:Lbl0/p;

    .line 71
    .line 72
    iput v1, p0, Lj50/e;->e:I

    .line 73
    .line 74
    iput v2, p0, Lj50/e;->f:I

    .line 75
    .line 76
    move-object v11, p0

    .line 77
    invoke-interface/range {v4 .. v11}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->getPlacePredictions(Ljava/lang/String;DDLjava/util/UUID;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    if-ne p1, v0, :cond_4

    .line 82
    .line 83
    :goto_1
    return-object v0

    .line 84
    :cond_4
    :goto_2
    check-cast p1, Lretrofit2/Response;

    .line 85
    .line 86
    return-object p1
.end method
