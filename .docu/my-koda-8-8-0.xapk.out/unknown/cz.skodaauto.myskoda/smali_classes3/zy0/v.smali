.class public final Lzy0/v;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/coroutines/Continuation;
.implements Lrx0/d;


# instance fields
.field public final d:Lkotlin/coroutines/Continuation;

.field public final e:Lpx0/g;


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;Lpx0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzy0/v;->d:Lkotlin/coroutines/Continuation;

    .line 5
    .line 6
    iput-object p2, p0, Lzy0/v;->e:Lpx0/g;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final getCallerFrame()Lrx0/d;
    .locals 1

    .line 1
    iget-object p0, p0, Lzy0/v;->d:Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    instance-of v0, p0, Lrx0/d;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p0, Lrx0/d;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return-object p0
.end method

.method public final getContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lzy0/v;->e:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lzy0/v;->d:Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
