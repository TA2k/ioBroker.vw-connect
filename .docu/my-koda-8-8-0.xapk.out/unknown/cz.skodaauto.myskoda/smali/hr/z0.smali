.class public final Lhr/z0;
.super Lhr/k0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final transient g:Lhr/c1;

.field public final transient h:[Ljava/lang/Object;

.field public final transient i:I


# direct methods
.method public constructor <init>(Lhr/c1;[Ljava/lang/Object;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/util/AbstractCollection;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhr/z0;->g:Lhr/c1;

    .line 5
    .line 6
    iput-object p2, p0, Lhr/z0;->h:[Ljava/lang/Object;

    .line 7
    .line 8
    iput p3, p0, Lhr/z0;->i:I

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final contains(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    instance-of v0, p1, Ljava/util/Map$Entry;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    check-cast p1, Ljava/util/Map$Entry;

    .line 7
    .line 8
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    iget-object p0, p0, Lhr/z0;->g:Lhr/c1;

    .line 19
    .line 20
    invoke-virtual {p0, v0}, Lhr/c1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    if-eqz p0, :cond_0

    .line 29
    .line 30
    const/4 p0, 0x1

    .line 31
    return p0

    .line 32
    :cond_0
    return v1
.end method

.method public final e(I[Ljava/lang/Object;)I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lhr/k0;->c()Lhr/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0, p1, p2}, Lhr/h0;->e(I[Ljava/lang/Object;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final m()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final r()Lhr/h0;
    .locals 1

    .line 1
    new-instance v0, Lhr/y0;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lhr/y0;-><init>(Lhr/z0;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public final s()Lhr/l1;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lhr/k0;->c()Lhr/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0, v0}, Lhr/h0;->s(I)Lhr/f0;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final size()I
    .locals 0

    .line 1
    iget p0, p0, Lhr/z0;->i:I

    .line 2
    .line 3
    return p0
.end method
