.class public final Lz4/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/a0;


# instance fields
.field public final d:Lz4/f;

.field public final e:Lay0/k;

.field public final f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lz4/f;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz4/i;->d:Lz4/f;

    .line 5
    .line 6
    iput-object p2, p0, Lz4/i;->e:Lay0/k;

    .line 7
    .line 8
    iget-object p1, p1, Lz4/f;->c:Ljava/lang/Object;

    .line 9
    .line 10
    iput-object p1, p0, Lz4/i;->f:Ljava/lang/Object;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final d0()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lz4/i;->f:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Lz4/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lz4/i;->d:Lz4/f;

    .line 6
    .line 7
    iget-object v0, v0, Lz4/f;->c:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p1, Lz4/i;

    .line 10
    .line 11
    iget-object v1, p1, Lz4/i;->d:Lz4/f;

    .line 12
    .line 13
    iget-object v1, v1, Lz4/f;->c:Ljava/lang/Object;

    .line 14
    .line 15
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    iget-object p0, p0, Lz4/i;->e:Lay0/k;

    .line 22
    .line 23
    iget-object p1, p1, Lz4/i;->e:Lay0/k;

    .line 24
    .line 25
    if-ne p0, p1, :cond_0

    .line 26
    .line 27
    const/4 p0, 0x1

    .line 28
    return p0

    .line 29
    :cond_0
    const/4 p0, 0x0

    .line 30
    return p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lz4/i;->d:Lz4/f;

    .line 2
    .line 3
    iget-object v0, v0, Lz4/f;->c:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    mul-int/lit8 v0, v0, 0x1f

    .line 10
    .line 11
    iget-object p0, p0, Lz4/i;->e:Lay0/k;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    add-int/2addr p0, v0

    .line 18
    return p0
.end method
