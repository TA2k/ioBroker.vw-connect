.class final Lcom/squareup/moshi/LinkedHashTreeMap$KeySet;
.super Ljava/util/AbstractSet;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/squareup/moshi/LinkedHashTreeMap;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "KeySet"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/util/AbstractSet<",
        "TK;>;"
    }
.end annotation


# instance fields
.field public final synthetic d:Lcom/squareup/moshi/LinkedHashTreeMap;


# direct methods
.method public constructor <init>(Lcom/squareup/moshi/LinkedHashTreeMap;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/squareup/moshi/LinkedHashTreeMap$KeySet;->d:Lcom/squareup/moshi/LinkedHashTreeMap;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/AbstractSet;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final clear()V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$KeySet;->d:Lcom/squareup/moshi/LinkedHashTreeMap;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/squareup/moshi/LinkedHashTreeMap;->clear()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$KeySet;->d:Lcom/squareup/moshi/LinkedHashTreeMap;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lcom/squareup/moshi/LinkedHashTreeMap;->containsKey(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    .line 1
    new-instance v0, Lcom/squareup/moshi/LinkedHashTreeMap$KeySet$1;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$KeySet;->d:Lcom/squareup/moshi/LinkedHashTreeMap;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;-><init>(Lcom/squareup/moshi/LinkedHashTreeMap;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object p0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$KeySet;->d:Lcom/squareup/moshi/LinkedHashTreeMap;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    :try_start_0
    invoke-virtual {p0, p1, v0}, Lcom/squareup/moshi/LinkedHashTreeMap;->a(Ljava/lang/Object;Z)Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 8
    .line 9
    .line 10
    move-result-object v1
    :try_end_0
    .catch Ljava/lang/ClassCastException; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    :catch_0
    :cond_0
    const/4 p1, 0x1

    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    invoke-virtual {p0, v1, p1}, Lcom/squareup/moshi/LinkedHashTreeMap;->c(Lcom/squareup/moshi/LinkedHashTreeMap$Node;Z)V

    .line 15
    .line 16
    .line 17
    :cond_1
    if-eqz v1, :cond_2

    .line 18
    .line 19
    return p1

    .line 20
    :cond_2
    return v0
.end method

.method public final size()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$KeySet;->d:Lcom/squareup/moshi/LinkedHashTreeMap;

    .line 2
    .line 3
    iget p0, p0, Lcom/squareup/moshi/LinkedHashTreeMap;->g:I

    .line 4
    .line 5
    return p0
.end method
