.class public final Lz4/j;
.super Lw3/h0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/b1;


# instance fields
.field public final c:Lz4/f;

.field public final d:Lay0/k;


# direct methods
.method public constructor <init>(Lz4/f;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz4/j;->c:Lz4/f;

    .line 5
    .line 6
    iput-object p2, p0, Lz4/j;->d:Lay0/k;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Lz4/j;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    check-cast p1, Lz4/j;

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move-object p1, v1

    .line 10
    :goto_0
    if-eqz p1, :cond_1

    .line 11
    .line 12
    iget-object v1, p1, Lz4/j;->d:Lay0/k;

    .line 13
    .line 14
    :cond_1
    iget-object p0, p0, Lz4/j;->d:Lay0/k;

    .line 15
    .line 16
    if-ne p0, v1, :cond_2

    .line 17
    .line 18
    const/4 p0, 0x1

    .line 19
    return p0

    .line 20
    :cond_2
    const/4 p0, 0x0

    .line 21
    return p0
.end method

.method public final f()Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Lz4/i;

    .line 2
    .line 3
    iget-object v1, p0, Lz4/j;->c:Lz4/f;

    .line 4
    .line 5
    iget-object p0, p0, Lz4/j;->d:Lay0/k;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0}, Lz4/i;-><init>(Lz4/f;Lay0/k;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lz4/j;->d:Lay0/k;

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
