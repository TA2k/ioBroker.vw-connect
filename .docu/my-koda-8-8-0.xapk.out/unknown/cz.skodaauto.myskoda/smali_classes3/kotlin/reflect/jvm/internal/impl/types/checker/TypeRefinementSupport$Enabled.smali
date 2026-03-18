.class public final Lkotlin/reflect/jvm/internal/impl/types/checker/TypeRefinementSupport$Enabled;
.super Lkotlin/reflect/jvm/internal/impl/types/checker/TypeRefinementSupport;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/impl/types/checker/TypeRefinementSupport;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Enabled"
.end annotation


# instance fields
.field private final typeRefiner:Lkotlin/reflect/jvm/internal/impl/types/checker/KotlinTypeRefiner;


# virtual methods
.method public final getTypeRefiner()Lkotlin/reflect/jvm/internal/impl/types/checker/KotlinTypeRefiner;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/types/checker/TypeRefinementSupport$Enabled;->typeRefiner:Lkotlin/reflect/jvm/internal/impl/types/checker/KotlinTypeRefiner;

    .line 2
    .line 3
    return-object p0
.end method
