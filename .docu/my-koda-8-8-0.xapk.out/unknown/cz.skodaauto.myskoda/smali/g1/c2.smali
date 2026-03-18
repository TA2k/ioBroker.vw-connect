.class public final Lg1/c2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public synthetic d:Ljava/lang/Object;

.field public final synthetic e:Lkotlin/jvm/internal/c0;

.field public final synthetic f:F


# direct methods
.method public constructor <init>(Lkotlin/jvm/internal/c0;FLkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lg1/c2;->e:Lkotlin/jvm/internal/c0;

    .line 2
    .line 3
    iput p2, p0, Lg1/c2;->f:F

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Lg1/c2;

    .line 2
    .line 3
    iget-object v1, p0, Lg1/c2;->e:Lkotlin/jvm/internal/c0;

    .line 4
    .line 5
    iget p0, p0, Lg1/c2;->f:F

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Lg1/c2;-><init>(Lkotlin/jvm/internal/c0;FLkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Lg1/c2;->d:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lg1/e2;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lg1/c2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lg1/c2;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lg1/c2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lg1/c2;->d:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p1, Lg1/e2;

    .line 9
    .line 10
    iget v0, p0, Lg1/c2;->f:F

    .line 11
    .line 12
    invoke-interface {p1, v0}, Lg1/e2;->a(F)F

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    iget-object p0, p0, Lg1/c2;->e:Lkotlin/jvm/internal/c0;

    .line 17
    .line 18
    iput p1, p0, Lkotlin/jvm/internal/c0;->d:F

    .line 19
    .line 20
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 21
    .line 22
    return-object p0
.end method
