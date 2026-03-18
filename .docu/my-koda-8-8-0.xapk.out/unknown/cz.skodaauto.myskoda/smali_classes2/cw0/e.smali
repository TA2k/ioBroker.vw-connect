.class public abstract Lcw0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcw0/c;


# static fields
.field public static final synthetic g:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;


# instance fields
.field private volatile synthetic closed:I

.field public final d:Ljava/lang/String;

.field public final e:Llx0/q;

.field public final f:Llx0/q;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Lcw0/e;

    .line 2
    .line 3
    const-string v1, "closed"

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lcw0/e;->g:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcw0/e;->d:Ljava/lang/String;

    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput p1, p0, Lcw0/e;->closed:I

    .line 8
    .line 9
    new-instance p1, Lcw0/d;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-direct {p1, p0, v0}, Lcw0/d;-><init>(Lcw0/e;I)V

    .line 13
    .line 14
    .line 15
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iput-object p1, p0, Lcw0/e;->e:Llx0/q;

    .line 20
    .line 21
    new-instance p1, Lcw0/d;

    .line 22
    .line 23
    const/4 v0, 0x1

    .line 24
    invoke-direct {p1, p0, v0}, Lcw0/d;-><init>(Lcw0/e;I)V

    .line 25
    .line 26
    .line 27
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    iput-object p1, p0, Lcw0/e;->f:Llx0/q;

    .line 32
    .line 33
    return-void
.end method


# virtual methods
.method public close()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    sget-object v2, Lcw0/e;->g:Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;

    .line 4
    .line 5
    invoke-virtual {v2, p0, v0, v1}, Ljava/util/concurrent/atomic/AtomicIntegerFieldUpdater;->compareAndSet(Ljava/lang/Object;II)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto :goto_1

    .line 12
    :cond_0
    invoke-virtual {p0}, Lcw0/e;->getCoroutineContext()Lpx0/g;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    sget-object v0, Lvy0/h1;->d:Lvy0/h1;

    .line 17
    .line 18
    invoke-interface {p0, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    instance-of v0, p0, Lvy0/s;

    .line 23
    .line 24
    if-eqz v0, :cond_1

    .line 25
    .line 26
    check-cast p0, Lvy0/s;

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    const/4 p0, 0x0

    .line 30
    :goto_0
    if-nez p0, :cond_2

    .line 31
    .line 32
    :goto_1
    return-void

    .line 33
    :cond_2
    check-cast p0, Lvy0/k1;

    .line 34
    .line 35
    invoke-virtual {p0}, Lvy0/k1;->l0()Z

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lcw0/e;->f:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lpx0/g;

    .line 8
    .line 9
    return-object p0
.end method
