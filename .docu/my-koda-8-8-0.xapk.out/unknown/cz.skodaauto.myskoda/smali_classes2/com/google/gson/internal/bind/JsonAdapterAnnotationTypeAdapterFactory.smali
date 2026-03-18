.class public final Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/gson/z;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory$DummyTypeAdapterFactory;
    }
.end annotation


# static fields
.field public static final f:Lcom/google/gson/z;

.field public static final g:Lcom/google/gson/z;


# instance fields
.field public final d:Lcom/google/android/gms/internal/measurement/i4;

.field public final e:Ljava/util/concurrent/ConcurrentHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory$DummyTypeAdapterFactory;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory$DummyTypeAdapterFactory;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;->f:Lcom/google/gson/z;

    .line 8
    .line 9
    new-instance v0, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory$DummyTypeAdapterFactory;

    .line 10
    .line 11
    invoke-direct {v0, v1}, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory$DummyTypeAdapterFactory;-><init>(I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;->g:Lcom/google/gson/z;

    .line 15
    .line 16
    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/measurement/i4;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 5
    .line 6
    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    .line 7
    .line 8
    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;->e:Ljava/util/concurrent/ConcurrentHashMap;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final a(Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;
    .locals 7

    .line 1
    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-class v1, Lmu/a;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Ljava/lang/Class;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    move-object v5, v0

    .line 12
    check-cast v5, Lmu/a;

    .line 13
    .line 14
    if-nez v5, :cond_0

    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    return-object p0

    .line 18
    :cond_0
    iget-object v2, p0, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 19
    .line 20
    const/4 v6, 0x1

    .line 21
    move-object v1, p0

    .line 22
    move-object v3, p1

    .line 23
    move-object v4, p2

    .line 24
    invoke-virtual/range {v1 .. v6}, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;->b(Lcom/google/android/gms/internal/measurement/i4;Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;Lmu/a;Z)Lcom/google/gson/y;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0
.end method

.method public final b(Lcom/google/android/gms/internal/measurement/i4;Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;Lmu/a;Z)Lcom/google/gson/y;
    .locals 7

    .line 1
    invoke-interface {p4}, Lmu/a;->value()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-static {v0}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/Class;)Lcom/google/gson/reflect/TypeToken;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {p1, v0, v1}, Lcom/google/android/gms/internal/measurement/i4;->r(Lcom/google/gson/reflect/TypeToken;Z)Lcom/google/gson/internal/m;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-interface {p1}, Lcom/google/gson/internal/m;->a()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-interface {p4}, Lmu/a;->nullSafe()Z

    .line 19
    .line 20
    .line 21
    move-result v6

    .line 22
    instance-of p4, p1, Lcom/google/gson/y;

    .line 23
    .line 24
    if-eqz p4, :cond_0

    .line 25
    .line 26
    check-cast p1, Lcom/google/gson/y;

    .line 27
    .line 28
    goto/16 :goto_4

    .line 29
    .line 30
    :cond_0
    instance-of p4, p1, Lcom/google/gson/z;

    .line 31
    .line 32
    if-eqz p4, :cond_2

    .line 33
    .line 34
    check-cast p1, Lcom/google/gson/z;

    .line 35
    .line 36
    if-eqz p5, :cond_1

    .line 37
    .line 38
    invoke-virtual {p3}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    move-result-object p4

    .line 42
    iget-object p0, p0, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;->e:Ljava/util/concurrent/ConcurrentHashMap;

    .line 43
    .line 44
    invoke-virtual {p0, p4, p1}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lcom/google/gson/z;

    .line 49
    .line 50
    if-eqz p0, :cond_1

    .line 51
    .line 52
    move-object p1, p0

    .line 53
    :cond_1
    invoke-interface {p1, p2, p3}, Lcom/google/gson/z;->a(Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    goto :goto_4

    .line 58
    :cond_2
    instance-of p0, p1, Lcom/google/gson/s;

    .line 59
    .line 60
    if-nez p0, :cond_4

    .line 61
    .line 62
    instance-of p4, p1, Lcom/google/gson/m;

    .line 63
    .line 64
    if-eqz p4, :cond_3

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 68
    .line 69
    new-instance p2, Ljava/lang/StringBuilder;

    .line 70
    .line 71
    const-string p4, "Invalid attempt to bind an instance of "

    .line 72
    .line 73
    invoke-direct {p2, p4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    const-string p1, " as a @JsonAdapter for "

    .line 88
    .line 89
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {p3}, Lcom/google/gson/reflect/TypeToken;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    const-string p1, ". @JsonAdapter value must be a TypeAdapter, TypeAdapterFactory, JsonSerializer or JsonDeserializer."

    .line 100
    .line 101
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    throw p0

    .line 112
    :cond_4
    :goto_0
    const/4 p4, 0x0

    .line 113
    if-eqz p0, :cond_5

    .line 114
    .line 115
    move-object p0, p1

    .line 116
    check-cast p0, Lcom/google/gson/s;

    .line 117
    .line 118
    move-object v1, p0

    .line 119
    goto :goto_1

    .line 120
    :cond_5
    move-object v1, p4

    .line 121
    :goto_1
    instance-of p0, p1, Lcom/google/gson/m;

    .line 122
    .line 123
    if-eqz p0, :cond_6

    .line 124
    .line 125
    move-object p4, p1

    .line 126
    check-cast p4, Lcom/google/gson/m;

    .line 127
    .line 128
    :cond_6
    move-object v2, p4

    .line 129
    if-eqz p5, :cond_7

    .line 130
    .line 131
    sget-object p0, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;->f:Lcom/google/gson/z;

    .line 132
    .line 133
    :goto_2
    move-object v5, p0

    .line 134
    goto :goto_3

    .line 135
    :cond_7
    sget-object p0, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;->g:Lcom/google/gson/z;

    .line 136
    .line 137
    goto :goto_2

    .line 138
    :goto_3
    new-instance v0, Lcom/google/gson/internal/bind/TreeTypeAdapter;

    .line 139
    .line 140
    move-object v3, p2

    .line 141
    move-object v4, p3

    .line 142
    invoke-direct/range {v0 .. v6}, Lcom/google/gson/internal/bind/TreeTypeAdapter;-><init>(Lcom/google/gson/s;Lcom/google/gson/m;Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;Lcom/google/gson/z;Z)V

    .line 143
    .line 144
    .line 145
    const/4 v6, 0x0

    .line 146
    move-object p1, v0

    .line 147
    :goto_4
    if-eqz p1, :cond_8

    .line 148
    .line 149
    if-eqz v6, :cond_8

    .line 150
    .line 151
    invoke-virtual {p1}, Lcom/google/gson/y;->a()Lcom/google/gson/y;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    return-object p0

    .line 156
    :cond_8
    return-object p1
.end method
