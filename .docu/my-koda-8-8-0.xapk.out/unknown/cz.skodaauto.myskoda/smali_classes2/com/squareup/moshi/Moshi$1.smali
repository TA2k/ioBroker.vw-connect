.class Lcom/squareup/moshi/Moshi$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/squareup/moshi/JsonAdapter$Factory;


# virtual methods
.method public final a(Ljava/lang/reflect/Type;Ljava/util/Set;Lcom/squareup/moshi/Moshi;)Lcom/squareup/moshi/JsonAdapter;
    .locals 0

    .line 1
    invoke-interface {p2}, Ljava/util/Set;->isEmpty()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    const/4 p2, 0x0

    .line 6
    if-eqz p0, :cond_0

    .line 7
    .line 8
    sget-object p0, Lax/b;->a:Ljava/util/Set;

    .line 9
    .line 10
    invoke-static {p2, p1}, Lcom/squareup/moshi/Types;->b(Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;)Z

    .line 11
    .line 12
    .line 13
    :cond_0
    return-object p2
.end method
