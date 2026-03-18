.class public Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$WithInlinedExpunction;
.super Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "WithInlinedExpunction"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<K:",
        "Ljava/lang/Object;",
        "V:",
        "Ljava/lang/Object;",
        ">",
        "Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap<",
        "TK;TV;>;"
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;-><init>(Z)V

    .line 3
    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public approximateSize()I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$WithInlinedExpunction;->expungeStaleEntries()V

    .line 2
    .line 3
    .line 4
    invoke-super {p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->approximateSize()I

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    return p0
.end method

.method public bridge synthetic clear()V
    .locals 0

    .line 1
    invoke-super {p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->clear()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public containsKey(Ljava/lang/Object;)Z
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TK;)Z"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$WithInlinedExpunction;->expungeStaleEntries()V

    .line 2
    .line 3
    .line 4
    invoke-super {p0, p1}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->containsKey(Ljava/lang/Object;)Z

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    return p0
.end method

.method public bridge synthetic expungeStaleEntries()V
    .locals 0

    .line 1
    invoke-super {p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->expungeStaleEntries()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TK;)TV;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$WithInlinedExpunction;->expungeStaleEntries()V

    .line 2
    .line 3
    .line 4
    invoke-super {p0, p1}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method

.method public bridge synthetic getIfPresent(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->getIfPresent(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public bridge synthetic getLookupKey(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->getLookupKey(Ljava/lang/Object;)Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public iterator()Ljava/util/Iterator;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Iterator<",
            "Ljava/util/Map$Entry<",
            "TK;TV;>;>;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$WithInlinedExpunction;->expungeStaleEntries()V

    .line 2
    .line 3
    .line 4
    invoke-super {p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->iterator()Ljava/util/Iterator;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method

.method public put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TK;TV;)TV;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$WithInlinedExpunction;->expungeStaleEntries()V

    .line 2
    .line 3
    .line 4
    invoke-super {p0, p1, p2}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method

.method public bridge synthetic putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public bridge synthetic putIfProbablyAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->putIfProbablyAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public remove(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TK;)TV;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$WithInlinedExpunction;->expungeStaleEntries()V

    .line 2
    .line 3
    .line 4
    invoke-super {p0, p1}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method

.method public bridge synthetic resetLookupKey(Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;

    .line 2
    .line 3
    invoke-super {p0, p1}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->resetLookupKey(Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public bridge synthetic run()V
    .locals 0

    .line 1
    invoke-super {p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->run()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public bridge synthetic toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-super {p0}, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;->toString()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
