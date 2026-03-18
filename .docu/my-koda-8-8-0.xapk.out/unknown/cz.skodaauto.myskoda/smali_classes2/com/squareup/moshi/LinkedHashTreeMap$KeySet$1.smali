.class Lcom/squareup/moshi/LinkedHashTreeMap$KeySet$1;
.super Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lcom/squareup/moshi/LinkedHashTreeMap<",
        "Ljava/lang/Object;",
        "Ljava/lang/Object;",
        ">.",
        "LinkedTreeMapIterator<",
        "Ljava/lang/Object;",
        ">;"
    }
.end annotation


# virtual methods
.method public final next()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->a()Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$Node;->i:Ljava/lang/Object;

    .line 6
    .line 7
    return-object p0
.end method
