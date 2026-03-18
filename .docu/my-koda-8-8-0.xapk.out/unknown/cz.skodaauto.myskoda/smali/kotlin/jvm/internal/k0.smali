.class public final Lkotlin/jvm/internal/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhy0/b0;


# instance fields
.field public final d:Ljava/lang/Object;

.field public volatile e:Ljava/util/List;


# direct methods
.method public constructor <init>(Ljava/lang/Object;)V
    .locals 1

    .line 1
    sget-object v0, Lhy0/e0;->d:Lhy0/e0;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lkotlin/jvm/internal/k0;->d:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lkotlin/jvm/internal/k0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lkotlin/jvm/internal/k0;

    .line 6
    .line 7
    iget-object p1, p1, Lkotlin/jvm/internal/k0;->d:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object p0, p0, Lkotlin/jvm/internal/k0;->d:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "PluginConfigT"

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUpperBounds()Ljava/util/List;
    .locals 4

    .line 1
    iget-object v0, p0, Lkotlin/jvm/internal/k0;->e:Ljava/util/List;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 6
    .line 7
    const-class v1, Ljava/lang/Object;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-virtual {v0, v1, v2, v3}, Lkotlin/jvm/internal/h0;->typeOf(Lhy0/e;Ljava/util/List;Z)Lhy0/a0;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {v0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iput-object v0, p0, Lkotlin/jvm/internal/k0;->e:Ljava/util/List;

    .line 25
    .line 26
    :cond_0
    return-object v0
.end method

.method public final getVariance()Lhy0/e0;
    .locals 0

    .line 1
    sget-object p0, Lhy0/e0;->d:Lhy0/e0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object p0, p0, Lkotlin/jvm/internal/k0;->d:Ljava/lang/Object;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    :goto_0
    mul-int/lit8 p0, p0, 0x1f

    .line 12
    .line 13
    const v0, 0x2cb24e7f

    .line 14
    .line 15
    .line 16
    add-int/2addr p0, v0

    .line 17
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    sget-object p0, Lhy0/e0;->d:Lhy0/e0;

    .line 2
    .line 3
    const-string p0, "PluginConfigT"

    .line 4
    .line 5
    return-object p0
.end method
