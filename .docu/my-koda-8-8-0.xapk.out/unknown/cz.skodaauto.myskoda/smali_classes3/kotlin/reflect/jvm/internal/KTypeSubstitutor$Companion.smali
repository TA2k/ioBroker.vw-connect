.class public final Lkotlin/reflect/jvm/internal/KTypeSubstitutor$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/KTypeSubstitutor;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\'\u0010\n\u001a\u00020\t2\n\u0010\u0005\u001a\u0006\u0012\u0002\u0008\u00030\u00042\u000c\u0010\u0008\u001a\u0008\u0012\u0004\u0012\u00020\u00070\u0006\u00a2\u0006\u0004\u0008\n\u0010\u000b\u00a8\u0006\u000c"
    }
    d2 = {
        "Lkotlin/reflect/jvm/internal/KTypeSubstitutor$Companion;",
        "",
        "<init>",
        "()V",
        "Lhy0/d;",
        "klass",
        "",
        "Lhy0/d0;",
        "arguments",
        "Lkotlin/reflect/jvm/internal/KTypeSubstitutor;",
        "create",
        "(Lhy0/d;Ljava/util/List;)Lkotlin/reflect/jvm/internal/KTypeSubstitutor;",
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


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/KTypeSubstitutor$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final create(Lhy0/d;Ljava/util/List;)Lkotlin/reflect/jvm/internal/KTypeSubstitutor;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lhy0/d;",
            "Ljava/util/List<",
            "Lhy0/d0;",
            ">;)",
            "Lkotlin/reflect/jvm/internal/KTypeSubstitutor;"
        }
    .end annotation

    .line 1
    const-string p0, "klass"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "arguments"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Lkotlin/reflect/jvm/internal/KTypeSubstitutor;

    .line 12
    .line 13
    invoke-interface {p1}, Lhy0/d;->getTypeParameters()Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    check-cast p1, Ljava/lang/Iterable;

    .line 18
    .line 19
    check-cast p2, Ljava/lang/Iterable;

    .line 20
    .line 21
    invoke-static {p1, p2}, Lmx0/q;->E0(Ljava/lang/Iterable;Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-static {p1}, Lmx0/x;->t(Ljava/lang/Iterable;)Ljava/util/Map;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-direct {p0, p1}, Lkotlin/reflect/jvm/internal/KTypeSubstitutor;-><init>(Ljava/util/Map;)V

    .line 30
    .line 31
    .line 32
    return-object p0
.end method
