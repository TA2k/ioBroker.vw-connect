.class public final Lpx0/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/coroutines/Continuation;
.implements Lrx0/d;


# static fields
.field public static final e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;


# instance fields
.field public final d:Lkotlin/coroutines/Continuation;

.field private volatile result:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-class v0, Ljava/lang/Object;

    .line 2
    .line 3
    const-string v1, "result"

    .line 4
    .line 5
    const-class v2, Lpx0/i;

    .line 6
    .line 7
    invoke-static {v2, v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lpx0/i;->e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lkotlin/coroutines/Continuation;)V
    .locals 1

    .line 4
    sget-object v0, Lqx0/a;->e:Lqx0/a;

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    iput-object p1, p0, Lpx0/i;->d:Lkotlin/coroutines/Continuation;

    .line 7
    iput-object v0, p0, Lpx0/i;->result:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lkotlin/coroutines/Continuation;Lqx0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lpx0/i;->d:Lkotlin/coroutines/Continuation;

    .line 3
    iput-object p2, p0, Lpx0/i;->result:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lpx0/i;->result:Ljava/lang/Object;

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->e:Lqx0/a;

    .line 4
    .line 5
    if-ne v0, v1, :cond_2

    .line 6
    .line 7
    sget-object v2, Lpx0/i;->e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 8
    .line 9
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 10
    .line 11
    :cond_0
    invoke-virtual {v2, p0, v1, v3}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_1

    .line 16
    .line 17
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_1
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    if-eq v0, v1, :cond_0

    .line 25
    .line 26
    iget-object v0, p0, Lpx0/i;->result:Ljava/lang/Object;

    .line 27
    .line 28
    :cond_2
    sget-object p0, Lqx0/a;->f:Lqx0/a;

    .line 29
    .line 30
    if-ne v0, p0, :cond_3

    .line 31
    .line 32
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_3
    instance-of p0, v0, Llx0/n;

    .line 36
    .line 37
    if-nez p0, :cond_4

    .line 38
    .line 39
    return-object v0

    .line 40
    :cond_4
    check-cast v0, Llx0/n;

    .line 41
    .line 42
    iget-object p0, v0, Llx0/n;->d:Ljava/lang/Throwable;

    .line 43
    .line 44
    throw p0
.end method

.method public final getCallerFrame()Lrx0/d;
    .locals 1

    .line 1
    iget-object p0, p0, Lpx0/i;->d:Lkotlin/coroutines/Continuation;

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
    iget-object p0, p0, Lpx0/i;->d:Lkotlin/coroutines/Continuation;

    .line 2
    .line 3
    invoke-interface {p0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 4

    .line 1
    :goto_0
    iget-object v0, p0, Lpx0/i;->result:Ljava/lang/Object;

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->e:Lqx0/a;

    .line 4
    .line 5
    if-ne v0, v1, :cond_2

    .line 6
    .line 7
    sget-object v2, Lpx0/i;->e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 8
    .line 9
    :cond_0
    invoke-virtual {v2, p0, v1, p1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    return-void

    .line 16
    :cond_1
    invoke-virtual {v2, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-eq v0, v1, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_2
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 24
    .line 25
    if-ne v0, v1, :cond_5

    .line 26
    .line 27
    sget-object v0, Lpx0/i;->e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->f:Lqx0/a;

    .line 30
    .line 31
    :cond_3
    invoke-virtual {v0, p0, v1, v2}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    if-eqz v3, :cond_4

    .line 36
    .line 37
    iget-object p0, p0, Lpx0/i;->d:Lkotlin/coroutines/Continuation;

    .line 38
    .line 39
    invoke-interface {p0, p1}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :cond_4
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    if-eq v3, v1, :cond_3

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "Already resumed"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SafeContinuation for "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lpx0/i;->d:Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
