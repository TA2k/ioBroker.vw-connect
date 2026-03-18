.class public final Lkotlin/reflect/jvm/internal/KTypeSubstitutor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/KTypeSubstitutor$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010$\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u000c\u0018\u0000 \u00132\u00020\u0001:\u0001\u0013B\u001b\u0012\u0012\u0010\u0005\u001a\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00040\u0002\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\u001b\u0010\n\u001a\u00020\u0008*\u00020\u00082\u0006\u0010\t\u001a\u00020\u0008H\u0002\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u0013\u0010\u000c\u001a\u00020\u0004*\u00020\u0004H\u0002\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0013\u0010\u000e\u001a\u00020\u0004*\u00020\u0004H\u0002\u00a2\u0006\u0004\u0008\u000e\u0010\rJ\u0015\u0010\u0010\u001a\u00020\u00042\u0006\u0010\u000f\u001a\u00020\u0008\u00a2\u0006\u0004\u0008\u0010\u0010\u0011R \u0010\u0005\u001a\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00040\u00028\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u0010\u0012\u00a8\u0006\u0014"
    }
    d2 = {
        "Lkotlin/reflect/jvm/internal/KTypeSubstitutor;",
        "",
        "",
        "Lhy0/b0;",
        "Lhy0/d0;",
        "substitution",
        "<init>",
        "(Ljava/util/Map;)V",
        "Lhy0/a0;",
        "other",
        "withNullabilityOf",
        "(Lhy0/a0;Lhy0/a0;)Lhy0/a0;",
        "lowerBoundIfFlexible",
        "(Lhy0/d0;)Lhy0/d0;",
        "upperBoundIfFlexible",
        "type",
        "substitute",
        "(Lhy0/a0;)Lhy0/d0;",
        "Ljava/util/Map;",
        "Companion",
        "kotlin-reflection"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final Companion:Lkotlin/reflect/jvm/internal/KTypeSubstitutor$Companion;


# instance fields
.field private final substitution:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lhy0/b0;",
            "Lhy0/d0;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/KTypeSubstitutor$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lkotlin/reflect/jvm/internal/KTypeSubstitutor$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lkotlin/reflect/jvm/internal/KTypeSubstitutor;->Companion:Lkotlin/reflect/jvm/internal/KTypeSubstitutor$Companion;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Ljava/util/Map;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Lhy0/b0;",
            "Lhy0/d0;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "substitution"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/KTypeSubstitutor;->substitution:Ljava/util/Map;

    .line 10
    .line 11
    return-void
.end method

.method private final lowerBoundIfFlexible(Lhy0/d0;)Lhy0/d0;
    .locals 1

    .line 1
    iget-object p0, p1, Lhy0/d0;->b:Lhy0/a0;

    .line 2
    .line 3
    instance-of v0, p0, Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p0, Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    :goto_0
    if-eqz p0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/AbstractKType;->lowerBoundIfFlexible()Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    if-eqz p0, :cond_1

    .line 18
    .line 19
    new-instance v0, Lhy0/d0;

    .line 20
    .line 21
    iget-object p1, p1, Lhy0/d0;->a:Lhy0/e0;

    .line 22
    .line 23
    invoke-direct {v0, p1, p0}, Lhy0/d0;-><init>(Lhy0/e0;Lhy0/a0;)V

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :cond_1
    return-object p1
.end method

.method private final upperBoundIfFlexible(Lhy0/d0;)Lhy0/d0;
    .locals 1

    .line 1
    iget-object p0, p1, Lhy0/d0;->b:Lhy0/a0;

    .line 2
    .line 3
    instance-of v0, p0, Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p0, Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    :goto_0
    if-eqz p0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/AbstractKType;->upperBoundIfFlexible()Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    if-eqz p0, :cond_1

    .line 18
    .line 19
    new-instance v0, Lhy0/d0;

    .line 20
    .line 21
    iget-object p1, p1, Lhy0/d0;->a:Lhy0/e0;

    .line 22
    .line 23
    invoke-direct {v0, p1, p0}, Lhy0/d0;-><init>(Lhy0/e0;Lhy0/a0;)V

    .line 24
    .line 25
    .line 26
    return-object v0

    .line 27
    :cond_1
    return-object p1
.end method

.method private final withNullabilityOf(Lhy0/a0;Lhy0/a0;)Lhy0/a0;
    .locals 3

    .line 1
    const-string p0, "null cannot be cast to non-null type kotlin.reflect.jvm.internal.AbstractKType"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object p0, p1

    .line 7
    check-cast p0, Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 8
    .line 9
    invoke-interface {p2}, Lhy0/a0;->isMarkedNullable()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/4 v1, 0x1

    .line 14
    const/4 v2, 0x0

    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    invoke-interface {p1}, Lhy0/a0;->isMarkedNullable()Z

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    if-eqz p1, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move p1, v2

    .line 25
    goto :goto_1

    .line 26
    :cond_1
    :goto_0
    move p1, v1

    .line 27
    :goto_1
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/AbstractKType;->makeNullableAsSpecified(Z)Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    move-object v0, p2

    .line 32
    check-cast v0, Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 33
    .line 34
    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/AbstractKType;->isDefinitelyNotNullType()Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-nez v0, :cond_3

    .line 39
    .line 40
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/AbstractKType;->isDefinitelyNotNullType()Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-eqz p0, :cond_2

    .line 45
    .line 46
    invoke-interface {p2}, Lhy0/a0;->isMarkedNullable()Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-nez p0, :cond_2

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_2
    move v1, v2

    .line 54
    :cond_3
    :goto_2
    invoke-virtual {p1, v1}, Lkotlin/reflect/jvm/internal/AbstractKType;->makeDefinitelyNotNullAsSpecified(Z)Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0
.end method


# virtual methods
.method public final substitute(Lhy0/a0;)Lhy0/d0;
    .locals 4

    .line 1
    const-string v0, "type"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    move-object v2, p1

    .line 12
    check-cast v2, Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move-object v2, v1

    .line 16
    :goto_0
    if-eqz v2, :cond_1

    .line 17
    .line 18
    invoke-virtual {v2}, Lkotlin/reflect/jvm/internal/AbstractKType;->lowerBoundIfFlexible()Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move-object v2, v1

    .line 24
    :goto_1
    if-eqz v0, :cond_2

    .line 25
    .line 26
    move-object v0, p1

    .line 27
    check-cast v0, Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 28
    .line 29
    goto :goto_2

    .line 30
    :cond_2
    move-object v0, v1

    .line 31
    :goto_2
    if-eqz v0, :cond_3

    .line 32
    .line 33
    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/AbstractKType;->upperBoundIfFlexible()Lkotlin/reflect/jvm/internal/AbstractKType;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    :cond_3
    if-eqz v2, :cond_4

    .line 38
    .line 39
    if-eqz v1, :cond_4

    .line 40
    .line 41
    invoke-virtual {p0, v2}, Lkotlin/reflect/jvm/internal/KTypeSubstitutor;->substitute(Lhy0/a0;)Lhy0/d0;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/KTypeSubstitutor;->lowerBoundIfFlexible(Lhy0/d0;)Lhy0/d0;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-virtual {p0, v1}, Lkotlin/reflect/jvm/internal/KTypeSubstitutor;->substitute(Lhy0/a0;)Lhy0/d0;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    invoke-direct {p0, v0}, Lkotlin/reflect/jvm/internal/KTypeSubstitutor;->upperBoundIfFlexible(Lhy0/d0;)Lhy0/d0;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    new-instance v0, Lhy0/d0;

    .line 58
    .line 59
    iget-object v1, p1, Lhy0/d0;->a:Lhy0/e0;

    .line 60
    .line 61
    iget-object p1, p1, Lhy0/d0;->b:Lhy0/a0;

    .line 62
    .line 63
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object p0, p0, Lhy0/d0;->b:Lhy0/a0;

    .line 67
    .line 68
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    invoke-static {p1, p0}, Lkotlin/reflect/jvm/internal/TypeOfImplKt;->createPlatformKType(Lhy0/a0;Lhy0/a0;)Lhy0/a0;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-direct {v0, v1, p0}, Lhy0/d0;-><init>(Lhy0/e0;Lhy0/a0;)V

    .line 76
    .line 77
    .line 78
    return-object v0

    .line 79
    :cond_4
    invoke-interface {p1}, Lhy0/a0;->getClassifier()Lhy0/e;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    if-nez v0, :cond_5

    .line 84
    .line 85
    sget-object p0, Lhy0/d0;->c:Lhy0/d0;

    .line 86
    .line 87
    invoke-static {p1}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    return-object p0

    .line 92
    :cond_5
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/KTypeSubstitutor;->substitution:Ljava/util/Map;

    .line 93
    .line 94
    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    check-cast v1, Lhy0/d0;

    .line 99
    .line 100
    if-eqz v1, :cond_7

    .line 101
    .line 102
    iget-object v0, v1, Lhy0/d0;->a:Lhy0/e0;

    .line 103
    .line 104
    iget-object v2, v1, Lhy0/d0;->b:Lhy0/a0;

    .line 105
    .line 106
    if-nez v2, :cond_6

    .line 107
    .line 108
    return-object v1

    .line 109
    :cond_6
    new-instance v1, Lhy0/d0;

    .line 110
    .line 111
    invoke-direct {p0, v2, p1}, Lkotlin/reflect/jvm/internal/KTypeSubstitutor;->withNullabilityOf(Lhy0/a0;Lhy0/a0;)Lhy0/a0;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    invoke-direct {v1, v0, p0}, Lhy0/d0;-><init>(Lhy0/e0;Lhy0/a0;)V

    .line 116
    .line 117
    .line 118
    return-object v1

    .line 119
    :cond_7
    sget-object v1, Lhy0/d0;->c:Lhy0/d0;

    .line 120
    .line 121
    invoke-interface {p1}, Lhy0/a0;->getArguments()Ljava/util/List;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    check-cast v1, Ljava/lang/Iterable;

    .line 126
    .line 127
    new-instance v2, Ljava/util/ArrayList;

    .line 128
    .line 129
    const/16 v3, 0xa

    .line 130
    .line 131
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 132
    .line 133
    .line 134
    move-result v3

    .line 135
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 136
    .line 137
    .line 138
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 143
    .line 144
    .line 145
    move-result v3

    .line 146
    if-eqz v3, :cond_a

    .line 147
    .line 148
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v3

    .line 152
    check-cast v3, Lhy0/d0;

    .line 153
    .line 154
    iget-object v3, v3, Lhy0/d0;->b:Lhy0/a0;

    .line 155
    .line 156
    if-eqz v3, :cond_8

    .line 157
    .line 158
    invoke-virtual {p0, v3}, Lkotlin/reflect/jvm/internal/KTypeSubstitutor;->substitute(Lhy0/a0;)Lhy0/d0;

    .line 159
    .line 160
    .line 161
    move-result-object v3

    .line 162
    if-nez v3, :cond_9

    .line 163
    .line 164
    :cond_8
    sget-object v3, Lhy0/d0;->c:Lhy0/d0;

    .line 165
    .line 166
    :cond_9
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    goto :goto_3

    .line 170
    :cond_a
    invoke-interface {p1}, Lhy0/a0;->isMarkedNullable()Z

    .line 171
    .line 172
    .line 173
    move-result p0

    .line 174
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 175
    .line 176
    invoke-static {v0, v2, p0, p1}, Liy0/b;->a(Lhy0/e;Ljava/util/List;ZLjava/util/List;)Lkotlin/reflect/jvm/internal/KTypeImpl;

    .line 177
    .line 178
    .line 179
    move-result-object p0

    .line 180
    invoke-static {p0}, Llp/e1;->c(Lhy0/a0;)Lhy0/d0;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    return-object p0
.end method
