.class public final Lqx0/b;
.super Lrx0/g;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:I

.field public final synthetic e:Lio/ktor/utils/io/g0;


# direct methods
.method public constructor <init>(Lio/ktor/utils/io/g0;)V
    .locals 1

    .line 1
    sget-object v0, Lio/ktor/utils/io/h0;->a:Lio/ktor/utils/io/f0;

    .line 2
    .line 3
    iput-object p1, p0, Lqx0/b;->e:Lio/ktor/utils/io/g0;

    .line 4
    .line 5
    invoke-direct {p0, v0}, Lrx0/g;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lqx0/b;->d:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_1

    .line 5
    .line 6
    if-ne v0, v1, :cond_0

    .line 7
    .line 8
    const/4 v0, 0x2

    .line 9
    iput v0, p0, Lqx0/b;->d:I

    .line 10
    .line 11
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 16
    .line 17
    const-string p1, "This coroutine had already completed"

    .line 18
    .line 19
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :cond_1
    iput v1, p0, Lqx0/b;->d:I

    .line 24
    .line 25
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    iget-object p1, p0, Lqx0/b;->e:Lio/ktor/utils/io/g0;

    .line 29
    .line 30
    invoke-static {v1, p1}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method
