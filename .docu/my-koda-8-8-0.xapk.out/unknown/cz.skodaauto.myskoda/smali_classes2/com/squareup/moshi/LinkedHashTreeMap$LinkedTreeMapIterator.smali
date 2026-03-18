.class abstract Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/squareup/moshi/LinkedHashTreeMap;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x401
    name = "LinkedTreeMapIterator"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Ljava/util/Iterator<",
        "TT;>;"
    }
.end annotation


# instance fields
.field public d:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

.field public e:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

.field public f:I

.field public final synthetic g:Lcom/squareup/moshi/LinkedHashTreeMap;


# direct methods
.method public constructor <init>(Lcom/squareup/moshi/LinkedHashTreeMap;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->g:Lcom/squareup/moshi/LinkedHashTreeMap;

    .line 5
    .line 6
    iget-object v0, p1, Lcom/squareup/moshi/LinkedHashTreeMap;->f:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 7
    .line 8
    iget-object v0, v0, Lcom/squareup/moshi/LinkedHashTreeMap$Node;->g:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 9
    .line 10
    iput-object v0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->d:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    iput-object v0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->e:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 14
    .line 15
    iget p1, p1, Lcom/squareup/moshi/LinkedHashTreeMap;->h:I

    .line 16
    .line 17
    iput p1, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->f:I

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final a()Lcom/squareup/moshi/LinkedHashTreeMap$Node;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->d:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->g:Lcom/squareup/moshi/LinkedHashTreeMap;

    .line 4
    .line 5
    iget-object v2, v1, Lcom/squareup/moshi/LinkedHashTreeMap;->f:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 6
    .line 7
    if-eq v0, v2, :cond_1

    .line 8
    .line 9
    iget v1, v1, Lcom/squareup/moshi/LinkedHashTreeMap;->h:I

    .line 10
    .line 11
    iget v2, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->f:I

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    iget-object v1, v0, Lcom/squareup/moshi/LinkedHashTreeMap$Node;->g:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 16
    .line 17
    iput-object v1, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->d:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 18
    .line 19
    iput-object v0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->e:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 20
    .line 21
    return-object v0

    .line 22
    :cond_0
    new-instance p0, Ljava/util/ConcurrentModificationException;

    .line 23
    .line 24
    invoke-direct {p0}, Ljava/util/ConcurrentModificationException;-><init>()V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 29
    .line 30
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 31
    .line 32
    .line 33
    throw p0
.end method

.method public final hasNext()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->d:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->g:Lcom/squareup/moshi/LinkedHashTreeMap;

    .line 4
    .line 5
    iget-object p0, p0, Lcom/squareup/moshi/LinkedHashTreeMap;->f:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 6
    .line 7
    if-eq v0, p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x1

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public next()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->a()Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final remove()V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->e:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    iget-object v2, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->g:Lcom/squareup/moshi/LinkedHashTreeMap;

    .line 7
    .line 8
    invoke-virtual {v2, v0, v1}, Lcom/squareup/moshi/LinkedHashTreeMap;->c(Lcom/squareup/moshi/LinkedHashTreeMap$Node;Z)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    iput-object v0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->e:Lcom/squareup/moshi/LinkedHashTreeMap$Node;

    .line 13
    .line 14
    iget v0, v2, Lcom/squareup/moshi/LinkedHashTreeMap;->h:I

    .line 15
    .line 16
    iput v0, p0, Lcom/squareup/moshi/LinkedHashTreeMap$LinkedTreeMapIterator;->f:I

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 22
    .line 23
    .line 24
    throw p0
.end method
