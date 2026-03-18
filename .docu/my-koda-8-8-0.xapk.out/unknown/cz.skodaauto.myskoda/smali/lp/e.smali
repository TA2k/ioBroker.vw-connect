.class public abstract Llp/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public transient d:Llp/a;

.field public transient e:Lhr/d;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final a()Ljava/util/Map;
    .locals 4

    .line 1
    iget-object v0, p0, Llp/e;->e:Lhr/d;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    move-object v0, p0

    .line 6
    check-cast v0, Llp/f;

    .line 7
    .line 8
    new-instance v1, Lhr/d;

    .line 9
    .line 10
    iget-object v2, v0, Llp/f;->f:Llp/j;

    .line 11
    .line 12
    const/4 v3, 0x2

    .line 13
    invoke-direct {v1, v0, v2, v3}, Lhr/d;-><init>(Ljava/io/Serializable;Ljava/util/Map;I)V

    .line 14
    .line 15
    .line 16
    iput-object v1, p0, Llp/e;->e:Lhr/d;

    .line 17
    .line 18
    return-object v1

    .line 19
    :cond_0
    return-object v0
.end method

.method public final b()Ljava/util/Set;
    .locals 3

    .line 1
    iget-object v0, p0, Llp/e;->d:Llp/a;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    move-object v0, p0

    .line 6
    check-cast v0, Llp/f;

    .line 7
    .line 8
    new-instance v1, Llp/a;

    .line 9
    .line 10
    iget-object v2, v0, Llp/f;->f:Llp/j;

    .line 11
    .line 12
    invoke-direct {v1, v0, v2}, Llp/a;-><init>(Llp/f;Ljava/util/Map;)V

    .line 13
    .line 14
    .line 15
    iput-object v1, p0, Llp/e;->d:Llp/a;

    .line 16
    .line 17
    return-object v1

    .line 18
    :cond_0
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p1, p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Llp/e;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_1
    check-cast p1, Llp/e;

    .line 12
    .line 13
    invoke-virtual {p0}, Llp/e;->a()Ljava/util/Map;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p1}, Llp/e;->a()Ljava/util/Map;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Llp/e;->a()Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lhr/d;

    .line 6
    .line 7
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Llp/e;->a()Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lhr/d;

    .line 6
    .line 7
    iget-object p0, p0, Lhr/d;->e:Ljava/util/Map;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0
.end method
