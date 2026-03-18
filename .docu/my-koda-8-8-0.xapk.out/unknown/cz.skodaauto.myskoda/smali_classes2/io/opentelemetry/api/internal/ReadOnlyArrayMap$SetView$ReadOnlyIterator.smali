.class final Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView$ReadOnlyIterator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x11
    name = "ReadOnlyIterator"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Ljava/util/Iterator<",
        "TE;>;"
    }
.end annotation


# instance fields
.field current:I

.field final synthetic this$1:Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView;


# direct methods
.method public constructor <init>(Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView$ReadOnlyIterator;->this$1:Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 p1, 0x0

    .line 7
    iput p1, p0, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView$ReadOnlyIterator;->current:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView$ReadOnlyIterator;->current:I

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView$ReadOnlyIterator;->this$1:Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView;->this$0:Lio/opentelemetry/api/internal/ReadOnlyArrayMap;

    .line 6
    .line 7
    invoke-static {p0}, Lio/opentelemetry/api/internal/ReadOnlyArrayMap;->access$100(Lio/opentelemetry/api/internal/ReadOnlyArrayMap;)Ljava/util/List;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-ge v0, p0, :cond_0

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

.method public next()Ljava/lang/Object;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()TE;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView$ReadOnlyIterator;->hasNext()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView$ReadOnlyIterator;->this$1:Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView;

    .line 8
    .line 9
    iget v1, p0, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView$ReadOnlyIterator;->current:I

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView;->elementAtArrayIndex(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget v1, p0, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView$ReadOnlyIterator;->current:I

    .line 16
    .line 17
    add-int/lit8 v1, v1, 0x2

    .line 18
    .line 19
    iput v1, p0, Lio/opentelemetry/api/internal/ReadOnlyArrayMap$SetView$ReadOnlyIterator;->current:I

    .line 20
    .line 21
    return-object v0

    .line 22
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 23
    .line 24
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 25
    .line 26
    .line 27
    throw p0
.end method

.method public remove()V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method
