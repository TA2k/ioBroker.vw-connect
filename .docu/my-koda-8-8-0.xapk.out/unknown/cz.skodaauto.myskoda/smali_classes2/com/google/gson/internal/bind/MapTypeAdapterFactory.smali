.class public final Lcom/google/gson/internal/bind/MapTypeAdapterFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/gson/z;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/gson/internal/bind/MapTypeAdapterFactory$Adapter;
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
    iput-object p1, p0, Lcom/google/gson/internal/bind/MapTypeAdapterFactory;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;
    .locals 7

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
    const-class v2, Ljava/util/Map;

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
    const-class v3, Ljava/util/Properties;

    .line 20
    .line 21
    invoke-virtual {v3, v1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    const/4 v4, 0x2

    .line 26
    const/4 v5, 0x1

    .line 27
    const/4 v6, 0x0

    .line 28
    if-eqz v3, :cond_1

    .line 29
    .line 30
    new-array v0, v4, [Ljava/lang/reflect/Type;

    .line 31
    .line 32
    const-class v1, Ljava/lang/String;

    .line 33
    .line 34
    aput-object v1, v0, v6

    .line 35
    .line 36
    aput-object v1, v0, v5

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    instance-of v3, v0, Ljava/lang/reflect/WildcardType;

    .line 40
    .line 41
    if-eqz v3, :cond_2

    .line 42
    .line 43
    check-cast v0, Ljava/lang/reflect/WildcardType;

    .line 44
    .line 45
    invoke-interface {v0}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    aget-object v0, v0, v6

    .line 50
    .line 51
    :cond_2
    invoke-virtual {v2, v1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    invoke-static {v3}, Lcom/google/gson/internal/f;->b(Z)V

    .line 56
    .line 57
    .line 58
    invoke-static {v0, v1, v2}, Lcom/google/gson/internal/f;->g(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/Class;)Ljava/lang/reflect/Type;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    new-instance v3, Ljava/util/HashMap;

    .line 63
    .line 64
    invoke-direct {v3}, Ljava/util/HashMap;-><init>()V

    .line 65
    .line 66
    .line 67
    invoke-static {v0, v1, v2, v3}, Lcom/google/gson/internal/f;->j(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/HashMap;)Ljava/lang/reflect/Type;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    instance-of v1, v0, Ljava/lang/reflect/ParameterizedType;

    .line 72
    .line 73
    if-eqz v1, :cond_3

    .line 74
    .line 75
    check-cast v0, Ljava/lang/reflect/ParameterizedType;

    .line 76
    .line 77
    invoke-interface {v0}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    goto :goto_0

    .line 82
    :cond_3
    new-array v0, v4, [Ljava/lang/reflect/Type;

    .line 83
    .line 84
    const-class v1, Ljava/lang/Object;

    .line 85
    .line 86
    aput-object v1, v0, v6

    .line 87
    .line 88
    aput-object v1, v0, v5

    .line 89
    .line 90
    :goto_0
    aget-object v1, v0, v6

    .line 91
    .line 92
    aget-object v0, v0, v5

    .line 93
    .line 94
    sget-object v2, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 95
    .line 96
    if-eq v1, v2, :cond_5

    .line 97
    .line 98
    const-class v2, Ljava/lang/Boolean;

    .line 99
    .line 100
    if-ne v1, v2, :cond_4

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_4
    invoke-static {v1}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    invoke-virtual {p1, v2}, Lcom/google/gson/j;->c(Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;

    .line 108
    .line 109
    .line 110
    move-result-object v2

    .line 111
    goto :goto_2

    .line 112
    :cond_5
    :goto_1
    sget-object v2, Lcom/google/gson/internal/bind/e;->c:Lcom/google/gson/y;

    .line 113
    .line 114
    :goto_2
    new-instance v3, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;

    .line 115
    .line 116
    invoke-direct {v3, p1, v2, v1}, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;-><init>(Lcom/google/gson/j;Lcom/google/gson/y;Ljava/lang/reflect/Type;)V

    .line 117
    .line 118
    .line 119
    invoke-static {v0}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    .line 120
    .line 121
    .line 122
    move-result-object v1

    .line 123
    invoke-virtual {p1, v1}, Lcom/google/gson/j;->c(Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    new-instance v2, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;

    .line 128
    .line 129
    invoke-direct {v2, p1, v1, v0}, Lcom/google/gson/internal/bind/TypeAdapterRuntimeTypeWrapper;-><init>(Lcom/google/gson/j;Lcom/google/gson/y;Ljava/lang/reflect/Type;)V

    .line 130
    .line 131
    .line 132
    iget-object p1, p0, Lcom/google/gson/internal/bind/MapTypeAdapterFactory;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 133
    .line 134
    invoke-virtual {p1, p2, v6}, Lcom/google/android/gms/internal/measurement/i4;->r(Lcom/google/gson/reflect/TypeToken;Z)Lcom/google/gson/internal/m;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    new-instance p2, Lcom/google/gson/internal/bind/MapTypeAdapterFactory$Adapter;

    .line 139
    .line 140
    invoke-direct {p2, p0, v3, v2, p1}, Lcom/google/gson/internal/bind/MapTypeAdapterFactory$Adapter;-><init>(Lcom/google/gson/internal/bind/MapTypeAdapterFactory;Lcom/google/gson/y;Lcom/google/gson/y;Lcom/google/gson/internal/m;)V

    .line 141
    .line 142
    .line 143
    return-object p2
.end method
