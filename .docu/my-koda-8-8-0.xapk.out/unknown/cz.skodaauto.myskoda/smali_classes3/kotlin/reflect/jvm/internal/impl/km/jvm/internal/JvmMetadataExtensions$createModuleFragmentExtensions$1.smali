.class public final Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmMetadataExtensions$createModuleFragmentExtensions$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmModuleFragmentExtension;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmMetadataExtensions;->createModuleFragmentExtensions()Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmModuleFragmentExtension;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation


# instance fields
.field private final type:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;

    .line 5
    .line 6
    const-class v1, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmModuleFragmentExtension;

    .line 7
    .line 8
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 9
    .line 10
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-direct {v0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;-><init>(Lhy0/d;)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmMetadataExtensions$createModuleFragmentExtensions$1;->type:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public getType()Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmMetadataExtensions$createModuleFragmentExtensions$1;->type:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;

    .line 2
    .line 3
    return-object p0
.end method
