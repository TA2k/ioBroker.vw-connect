.class public final Lc1/z0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lc1/c1;

.field public final synthetic h:Lc1/w1;

.field public final synthetic i:F


# direct methods
.method public constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Lc1/c1;Lc1/w1;FLkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lc1/z0;->e:Ljava/lang/Object;

    .line 2
    .line 3
    iput-object p2, p0, Lc1/z0;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lc1/z0;->g:Lc1/c1;

    .line 6
    .line 7
    iput-object p4, p0, Lc1/z0;->h:Lc1/w1;

    .line 8
    .line 9
    iput p5, p0, Lc1/z0;->i:F

    .line 10
    .line 11
    const/4 p1, 0x1

    .line 12
    invoke-direct {p0, p1, p6}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 7

    .line 1
    new-instance v0, Lc1/z0;

    .line 2
    .line 3
    iget-object v4, p0, Lc1/z0;->h:Lc1/w1;

    .line 4
    .line 5
    iget v5, p0, Lc1/z0;->i:F

    .line 6
    .line 7
    iget-object v1, p0, Lc1/z0;->e:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v2, p0, Lc1/z0;->f:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v3, p0, Lc1/z0;->g:Lc1/c1;

    .line 12
    .line 13
    move-object v6, p1

    .line 14
    invoke-direct/range {v0 .. v6}, Lc1/z0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Lc1/c1;Lc1/w1;FLkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lc1/z0;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lc1/z0;

    .line 8
    .line 9
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lc1/z0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v1, p0, Lc1/z0;->d:I

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-eqz v1, :cond_1

    .line 7
    .line 8
    if-ne v1, v2, :cond_0

    .line 9
    .line 10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 15
    .line 16
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 17
    .line 18
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    throw p0

    .line 22
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    new-instance v3, Lc1/y0;

    .line 26
    .line 27
    iget v8, p0, Lc1/z0;->i:F

    .line 28
    .line 29
    const/4 v9, 0x0

    .line 30
    iget-object v4, p0, Lc1/z0;->e:Ljava/lang/Object;

    .line 31
    .line 32
    iget-object v5, p0, Lc1/z0;->f:Ljava/lang/Object;

    .line 33
    .line 34
    iget-object v6, p0, Lc1/z0;->g:Lc1/c1;

    .line 35
    .line 36
    iget-object v7, p0, Lc1/z0;->h:Lc1/w1;

    .line 37
    .line 38
    invoke-direct/range {v3 .. v9}, Lc1/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Lc1/c1;Lc1/w1;FLkotlin/coroutines/Continuation;)V

    .line 39
    .line 40
    .line 41
    iput v2, p0, Lc1/z0;->d:I

    .line 42
    .line 43
    invoke-static {v3, p0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    if-ne p0, v0, :cond_2

    .line 48
    .line 49
    return-object v0

    .line 50
    :cond_2
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    return-object p0
.end method
