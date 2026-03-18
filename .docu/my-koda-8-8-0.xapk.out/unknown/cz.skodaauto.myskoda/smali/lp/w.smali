.class public final Llp/w;
.super Llp/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final transient f:Ljp/h0;

.field public final transient g:[Ljava/lang/Object;

.field public final transient h:I


# direct methods
.method public constructor <init>(Ljp/h0;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/util/AbstractCollection;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llp/w;->f:Ljp/h0;

    .line 5
    .line 6
    iput-object p2, p0, Llp/w;->g:[Ljava/lang/Object;

    .line 7
    .line 8
    const/4 p1, 0x1

    .line 9
    iput p1, p0, Llp/w;->h:I

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final c([Ljava/lang/Object;)I
    .locals 1

    .line 1
    iget-object v0, p0, Llp/p;->e:Llp/o;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Llp/v;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Llp/v;-><init>(Llp/w;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Llp/p;->e:Llp/o;

    .line 11
    .line 12
    :cond_0
    invoke-virtual {v0, p1}, Llp/o;->c([Ljava/lang/Object;)I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0
.end method

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
    iget-object p0, p0, Llp/w;->f:Ljp/h0;

    .line 19
    .line 20
    invoke-virtual {p0, v0}, Ljp/h0;->get(Ljava/lang/Object;)Ljava/lang/Object;

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

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    iget-object v0, p0, Llp/p;->e:Llp/o;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Llp/v;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Llp/v;-><init>(Llp/w;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Llp/p;->e:Llp/o;

    .line 11
    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    invoke-virtual {v0, p0}, Llp/o;->n(I)Llp/m;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final size()I
    .locals 0

    .line 1
    iget p0, p0, Llp/w;->h:I

    .line 2
    .line 3
    return p0
.end method
