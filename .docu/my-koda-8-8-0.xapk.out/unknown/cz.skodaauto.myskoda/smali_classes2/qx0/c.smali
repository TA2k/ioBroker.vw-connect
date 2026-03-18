.class public final Lqx0/c;
.super Lrx0/g;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:I

.field public final synthetic e:Lay0/n;

.field public final synthetic f:Lkotlin/coroutines/Continuation;


# direct methods
.method public constructor <init>(Lay0/n;Lkotlin/coroutines/Continuation;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lqx0/c;->e:Lay0/n;

    .line 2
    .line 3
    iput-object p3, p0, Lqx0/c;->f:Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-direct {p0, p2}, Lrx0/g;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lqx0/c;->d:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x1

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    if-ne v0, v2, :cond_0

    .line 8
    .line 9
    iput v1, p0, Lqx0/c;->d:I

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
    iput v2, p0, Lqx0/c;->d:I

    .line 24
    .line 25
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    const-string p1, "null cannot be cast to non-null type kotlin.Function2<R of kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt.createCoroutineUnintercepted, kotlin.coroutines.Continuation<T of kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt.createCoroutineUnintercepted>, kotlin.Any?>"

    .line 29
    .line 30
    iget-object v0, p0, Lqx0/c;->e:Lay0/n;

    .line 31
    .line 32
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-static {v1, v0}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object p1, p0, Lqx0/c;->f:Lkotlin/coroutines/Continuation;

    .line 39
    .line 40
    invoke-interface {v0, p1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    return-object p0
.end method
