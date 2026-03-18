.class public final Lhz0/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhz0/z1;
.implements Llz0/c;


# instance fields
.field public a:Ljava/lang/Integer;

.field public b:Ljava/lang/Integer;


# direct methods
.method public constructor <init>(Ljava/lang/Integer;Ljava/lang/Integer;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 5
    .line 6
    iput-object p2, p0, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final A(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public final C()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy()Ljava/lang/Object;
    .locals 2

    .line 1
    new-instance v0, Lhz0/l0;

    .line 2
    .line 3
    iget-object v1, p0, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 4
    .line 5
    iget-object p0, p0, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0}, Lhz0/l0;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Lhz0/l0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 6
    .line 7
    check-cast p1, Lhz0/l0;

    .line 8
    .line 9
    iget-object v1, p1, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 10
    .line 11
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 18
    .line 19
    iget-object p1, p1, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_0

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
    .locals 2

    .line 1
    iget-object v0, p0, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v0, v1

    .line 12
    :goto_0
    mul-int/lit8 v0, v0, 0x1f

    .line 13
    .line 14
    iget-object p0, p0, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 15
    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    :cond_1
    add-int/2addr v0, v1

    .line 23
    return v0
.end method

.method public final s(Ljava/lang/Integer;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 2
    .line 3
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 7
    .line 8
    const-string v2, "??"

    .line 9
    .line 10
    if-nez v1, :cond_0

    .line 11
    .line 12
    move-object v1, v2

    .line 13
    :cond_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    const/16 v1, 0x2d

    .line 17
    .line 18
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lhz0/l0;->b:Ljava/lang/Integer;

    .line 22
    .line 23
    if-nez p0, :cond_1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    move-object v2, p0

    .line 27
    :goto_0
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public final v()Ljava/lang/Integer;
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/l0;->a:Ljava/lang/Integer;

    .line 2
    .line 3
    return-object p0
.end method
