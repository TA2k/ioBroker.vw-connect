.class public abstract Lkotlin/reflect/jvm/internal/AbstractKType;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhy0/a0;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0002\u0008\n\n\u0002\u0018\u0002\n\u0002\u0008\u0008\u0008 \u0018\u0000B\u0007\u00a2\u0006\u0004\u0008\u0001\u0010\u0002J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0000H&\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\u0008\u001a\u00020\u00002\u0006\u0010\u0007\u001a\u00020\u0004H&\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u0017\u0010\u000b\u001a\u00020\u00002\u0006\u0010\n\u001a\u00020\u0004H&\u00a2\u0006\u0004\u0008\u000b\u0010\tJ\u0011\u0010\u000c\u001a\u0004\u0018\u00010\u0000H&\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0011\u0010\u000e\u001a\u0004\u0018\u00010\u0000H&\u00a2\u0006\u0004\u0008\u000e\u0010\rR\u0016\u0010\u0012\u001a\u0004\u0018\u00010\u000f8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0010\u0010\u0011R\u0014\u0010\u0013\u001a\u00020\u00048&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0013\u0010\u0014R\u0014\u0010\u0015\u001a\u00020\u00048&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0015\u0010\u0014R\u0014\u0010\u0016\u001a\u00020\u00048&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0016\u0010\u0014\u00a8\u0006\u0017"
    }
    d2 = {
        "Lkotlin/reflect/jvm/internal/AbstractKType;",
        "<init>",
        "()V",
        "other",
        "",
        "isSubtypeOf",
        "(Lkotlin/reflect/jvm/internal/AbstractKType;)Z",
        "nullable",
        "makeNullableAsSpecified",
        "(Z)Lkotlin/reflect/jvm/internal/AbstractKType;",
        "isDefinitelyNotNull",
        "makeDefinitelyNotNullAsSpecified",
        "lowerBoundIfFlexible",
        "()Lkotlin/reflect/jvm/internal/AbstractKType;",
        "upperBoundIfFlexible",
        "Lhy0/a0;",
        "getAbbreviation",
        "()Lhy0/a0;",
        "abbreviation",
        "isDefinitelyNotNullType",
        "()Z",
        "isNothingType",
        "isMutableCollectionType",
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
.method public abstract getAbbreviation()Lhy0/a0;
.end method

.method public abstract synthetic getAnnotations()Ljava/util/List;
.end method

.method public abstract synthetic getArguments()Ljava/util/List;
.end method

.method public abstract synthetic getClassifier()Lhy0/e;
.end method

.method public abstract getJavaType()Ljava/lang/reflect/Type;
.end method

.method public abstract isDefinitelyNotNullType()Z
.end method

.method public abstract synthetic isMarkedNullable()Z
.end method

.method public abstract isMutableCollectionType()Z
.end method

.method public abstract isNothingType()Z
.end method

.method public abstract isSubtypeOf(Lkotlin/reflect/jvm/internal/AbstractKType;)Z
.end method

.method public abstract lowerBoundIfFlexible()Lkotlin/reflect/jvm/internal/AbstractKType;
.end method

.method public abstract makeDefinitelyNotNullAsSpecified(Z)Lkotlin/reflect/jvm/internal/AbstractKType;
.end method

.method public abstract makeNullableAsSpecified(Z)Lkotlin/reflect/jvm/internal/AbstractKType;
.end method

.method public abstract upperBoundIfFlexible()Lkotlin/reflect/jvm/internal/AbstractKType;
.end method
