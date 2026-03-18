.class final Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "LookupKey"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<K:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field private hashCode:I

.field private key:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "TK;"
        }
    .end annotation
.end field


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
.method public equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    instance-of v0, p1, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    check-cast p1, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;

    .line 8
    .line 9
    iget-object p1, p1, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;->key:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object p0, p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;->key:Ljava/lang/Object;

    .line 12
    .line 13
    if-ne p1, p0, :cond_0

    .line 14
    .line 15
    return v2

    .line 16
    :cond_0
    return v1

    .line 17
    :cond_1
    check-cast p1, Lio/opentelemetry/context/internal/shaded/AbstractWeakConcurrentMap$WeakKey;

    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iget-object p0, p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;->key:Ljava/lang/Object;

    .line 24
    .line 25
    if-ne p1, p0, :cond_2

    .line 26
    .line 27
    return v2

    .line 28
    :cond_2
    return v1
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;->hashCode:I

    .line 2
    .line 3
    return p0
.end method

.method public reset()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;->key:Ljava/lang/Object;

    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;->hashCode:I

    .line 6
    .line 7
    return-void
.end method

.method public withValue(Ljava/lang/Object;)Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TK;)",
            "Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey<",
            "TK;>;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;->key:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-static {p1}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    iput p1, p0, Lio/opentelemetry/context/internal/shaded/WeakConcurrentMap$LookupKey;->hashCode:I

    .line 8
    .line 9
    return-object p0
.end method
