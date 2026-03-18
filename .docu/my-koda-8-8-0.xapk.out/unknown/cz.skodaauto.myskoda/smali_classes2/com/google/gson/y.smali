.class public abstract Lcom/google/gson/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final a()Lcom/google/gson/y;
    .locals 1

    .line 1
    instance-of v0, p0, Lcom/google/gson/TypeAdapter$NullSafeTypeAdapter;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/gson/TypeAdapter$NullSafeTypeAdapter;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Lcom/google/gson/TypeAdapter$NullSafeTypeAdapter;-><init>(Lcom/google/gson/y;)V

    .line 8
    .line 9
    .line 10
    return-object v0

    .line 11
    :cond_0
    return-object p0
.end method

.method public abstract b(Lpu/a;)Ljava/lang/Object;
.end method

.method public abstract c(Lpu/b;Ljava/lang/Object;)V
.end method
