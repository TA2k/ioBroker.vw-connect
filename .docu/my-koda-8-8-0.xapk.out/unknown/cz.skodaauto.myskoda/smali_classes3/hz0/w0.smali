.class public final Lhz0/w0;
.super Ljz0/v;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Lhz0/g1;


# direct methods
.method public constructor <init>(Lhz0/g1;)V
    .locals 4

    .line 1
    sget-object v0, Lhz0/c2;->b:Ljz0/u;

    .line 2
    .line 3
    sget-object v1, Lhz0/g1;->e:Lhz0/g1;

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    if-ne p1, v1, :cond_0

    .line 7
    .line 8
    move v1, v2

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v1, 0x1

    .line 11
    :goto_0
    sget-object v3, Lhz0/g1;->f:Lhz0/g1;

    .line 12
    .line 13
    if-ne p1, v3, :cond_1

    .line 14
    .line 15
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    goto :goto_1

    .line 20
    :cond_1
    const/4 v2, 0x0

    .line 21
    :goto_1
    invoke-direct {p0, v0, v1, v2}, Ljz0/v;-><init>(Ljz0/u;ILjava/lang/Integer;)V

    .line 22
    .line 23
    .line 24
    iput-object p1, p0, Lhz0/w0;->e:Lhz0/g1;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lhz0/w0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lhz0/w0;

    .line 6
    .line 7
    iget-object p1, p1, Lhz0/w0;->e:Lhz0/g1;

    .line 8
    .line 9
    iget-object p0, p0, Lhz0/w0;->e:Lhz0/g1;

    .line 10
    .line 11
    if-ne p0, p1, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/w0;->e:Lhz0/g1;

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
