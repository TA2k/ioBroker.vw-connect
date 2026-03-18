.class public final Lam/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lpx0/g;


# instance fields
.field public final d:Lpx0/g;


# direct methods
.method public constructor <init>(Lpx0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lam/e;->d:Lpx0/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lam/e;->d:Lpx0/g;

    .line 2
    .line 3
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final fold(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lam/e;->d:Lpx0/g;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lpx0/g;->fold(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final get(Lpx0/f;)Lpx0/e;
    .locals 0

    .line 1
    iget-object p0, p0, Lam/e;->d:Lpx0/g;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lam/e;->d:Lpx0/g;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final minusKey(Lpx0/f;)Lpx0/g;
    .locals 2

    .line 1
    iget-object v0, p0, Lam/e;->d:Lpx0/g;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lpx0/g;->minusKey(Lpx0/f;)Lpx0/g;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget v0, Lam/i;->b:I

    .line 8
    .line 9
    sget-object v0, Lvy0/x;->d:Lvy0/w;

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Lam/e;->get(Lpx0/f;)Lpx0/e;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lvy0/x;

    .line 16
    .line 17
    invoke-interface {p1, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lvy0/x;

    .line 22
    .line 23
    instance-of v1, p0, Lam/f;

    .line 24
    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-nez v0, :cond_0

    .line 32
    .line 33
    check-cast p0, Lam/f;

    .line 34
    .line 35
    const/4 v0, 0x0

    .line 36
    iput v0, p0, Lam/f;->f:I

    .line 37
    .line 38
    :cond_0
    new-instance p0, Lam/e;

    .line 39
    .line 40
    invoke-direct {p0, p1}, Lam/e;-><init>(Lpx0/g;)V

    .line 41
    .line 42
    .line 43
    return-object p0
.end method

.method public final plus(Lpx0/g;)Lpx0/g;
    .locals 2

    .line 1
    iget-object v0, p0, Lam/e;->d:Lpx0/g;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget v0, Lam/i;->b:I

    .line 8
    .line 9
    sget-object v0, Lvy0/x;->d:Lvy0/w;

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Lam/e;->get(Lpx0/f;)Lpx0/e;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Lvy0/x;

    .line 16
    .line 17
    invoke-interface {p1, v0}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lvy0/x;

    .line 22
    .line 23
    instance-of v1, p0, Lam/f;

    .line 24
    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-nez v0, :cond_0

    .line 32
    .line 33
    check-cast p0, Lam/f;

    .line 34
    .line 35
    const/4 v0, 0x0

    .line 36
    iput v0, p0, Lam/f;->f:I

    .line 37
    .line 38
    :cond_0
    new-instance p0, Lam/e;

    .line 39
    .line 40
    invoke-direct {p0, p1}, Lam/e;-><init>(Lpx0/g;)V

    .line 41
    .line 42
    .line 43
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ForwardingCoroutineContext(delegate="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lam/e;->d:Lpx0/g;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, ")"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
