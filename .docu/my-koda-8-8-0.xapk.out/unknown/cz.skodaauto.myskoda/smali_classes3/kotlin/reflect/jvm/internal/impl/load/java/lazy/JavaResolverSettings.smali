.class public interface abstract Lkotlin/reflect/jvm/internal/impl/load/java/lazy/JavaResolverSettings;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/impl/load/java/lazy/JavaResolverSettings$Companion;,
        Lkotlin/reflect/jvm/internal/impl/load/java/lazy/JavaResolverSettings$Default;
    }
.end annotation


# static fields
.field public static final Companion:Lkotlin/reflect/jvm/internal/impl/load/java/lazy/JavaResolverSettings$Companion;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/lazy/JavaResolverSettings$Companion;->$$INSTANCE:Lkotlin/reflect/jvm/internal/impl/load/java/lazy/JavaResolverSettings$Companion;

    .line 2
    .line 3
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/load/java/lazy/JavaResolverSettings;->Companion:Lkotlin/reflect/jvm/internal/impl/load/java/lazy/JavaResolverSettings$Companion;

    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public abstract getCorrectNullabilityForNotNullTypeParameter()Z
.end method

.method public abstract getEnhancePrimitiveArrays()Z
.end method

.method public abstract getIgnoreNullabilityForErasedValueParameters()Z
.end method

.method public abstract getTypeEnhancementImprovementsInStrictMode()Z
.end method
