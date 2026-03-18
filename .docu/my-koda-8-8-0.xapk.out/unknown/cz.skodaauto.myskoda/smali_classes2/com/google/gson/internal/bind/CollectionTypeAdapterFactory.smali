.class public final Lcom/google/gson/internal/bind/CollectionTypeAdapterFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/gson/z;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/gson/internal/bind/CollectionTypeAdapterFactory$Adapter;
    }
.end annotation


# instance fields
.field public final d:Lcom/google/android/gms/internal/measurement/i4;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/internal/measurement/i4;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/gson/internal/bind/CollectionTypeAdapterFactory;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;
    .locals 5

    .line 1
    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const-class v2, Ljava/util/Collection;

    .line 10
    .line 11
    invoke-virtual {v2, v1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    if-nez v3, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x0

    .line 18
    return-object p0

    .line 19
    :cond_0
    instance-of v3, v0, Ljava/lang/reflect/WildcardType;

    .line 20
    .line 21
    const/4 v4, 0x0

    .line 22
    if-eqz v3, :cond_1

    .line 23
    .line 24
    check-cast v0, Ljava/lang/reflect/WildcardType;

    .line 25
    .line 26
    invoke-interface {v0}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    aget-object v0, v0, v4

    .line 31
    .line 32
    :cond_1
    invoke-virtual {v2, v1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    invoke-static {v3}, Lcom/google/gson/internal/f;->b(Z)V

    .line 37
    .line 38
    .line 39
    invoke-static {v0, v1, v2}, Lcom/google/gson/internal/f;->g(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/reflect/Type;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    new-instance v3, Ljava/util/HashMap;

    .line 44
    .line 45
    invoke-direct {v3}, Ljava/util/HashMap;-><init>()V

    .line 46
    .line 47
    .line 48
    invoke-static {v0, v1, v2, v3}, Lcom/google/gson/internal/f;->j(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/HashMap;)Ljava/lang/reflect/Type;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    instance-of v1, v0, Ljava/lang/reflect/ParameterizedType;

    .line 53
    .line 54
    if-eqz v1, :cond_2

    .line 55
    .line 56
    check-cast v0, Ljava/lang/reflect/ParameterizedType;

    .line 57
    .line 58
    invoke-interface {v0}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    aget-object v0, v0, v4

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_2
    const-class v0, Ljava/lang/Object;

    .line 66
    .line 67
    :goto_0
    invoke-static {v0}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    invoke-virtual {p1, v1}, Lcom/google/gson/j;->c(Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    new-instance v2, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;

    .line 76
    .line 77
    invoke-direct {v2, p1, v1, v0}, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;-><init>(Lcom/google/gson/j;Lcom/google/gson/y;Ljava/lang/reflect/Type;)V

    .line 78
    .line 79
    .line 80
    iget-object p0, p0, Lcom/google/gson/internal/bind/CollectionTypeAdapterFactory;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 81
    .line 82
    invoke-virtual {p0, p2, v4}, Lcom/google/android/gms/internal/measurement/i4;->r(Lcom/google/gson/reflect/TypeToken;Z)Lcom/google/gson/internal/m;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    new-instance p1, Lcom/google/gson/internal/bind/CollectionTypeAdapterFactory$Adapter;

    .line 87
    .line 88
    invoke-direct {p1, v2, p0}, Lcom/google/gson/internal/bind/CollectionTypeAdapterFactory$Adapter;-><init>(Lcom/google/gson/y;Lcom/google/gson/internal/m;)V

    .line 89
    .line 90
    .line 91
    return-object p1
.end method
