.class final Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Effect$EffectConditionKind$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/protobuf/Internal$EnumLiteMap;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Effect$EffectConditionKind;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Lkotlin/reflect/jvm/internal/impl/protobuf/Internal$EnumLiteMap<",
        "Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Effect$EffectConditionKind;",
        ">;"
    }
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
.method public findValueByNumber(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Effect$EffectConditionKind;
    .locals 0

    .line 2
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Effect$EffectConditionKind;->valueOf(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Effect$EffectConditionKind;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic findValueByNumber(I)Lkotlin/reflect/jvm/internal/impl/protobuf/Internal$EnumLite;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Effect$EffectConditionKind$1;->findValueByNumber(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Effect$EffectConditionKind;

    move-result-object p0

    return-object p0
.end method
