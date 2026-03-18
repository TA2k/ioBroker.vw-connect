.class public abstract Lvp/b0;
.super Lvp/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public f:Z


# direct methods
.method public constructor <init>(Lvp/g1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lap0/o;-><init>(Lvp/g1;)V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast p0, Lvp/g1;

    .line 7
    .line 8
    iget p1, p0, Lvp/g1;->D:I

    .line 9
    .line 10
    add-int/lit8 p1, p1, 0x1

    .line 11
    .line 12
    iput p1, p0, Lvp/g1;->D:I

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final b0()V
    .locals 1

    .line 1
    iget-boolean p0, p0, Lvp/b0;->f:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 7
    .line 8
    const-string v0, "Not initialized"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public final c0()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lvp/b0;->f:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    invoke-virtual {p0}, Lvp/b0;->d0()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Lvp/g1;

    .line 14
    .line 15
    iget-object v0, v0, Lvp/g1;->F:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    iput-boolean v0, p0, Lvp/b0;->f:Z

    .line 22
    .line 23
    :cond_0
    return-void

    .line 24
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string v0, "Can\'t initialize twice"

    .line 27
    .line 28
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0
.end method

.method public abstract d0()Z
.end method
