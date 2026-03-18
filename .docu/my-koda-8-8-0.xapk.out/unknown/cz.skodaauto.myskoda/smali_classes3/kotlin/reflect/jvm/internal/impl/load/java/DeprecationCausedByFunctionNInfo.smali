.class public final Lkotlin/reflect/jvm/internal/impl/load/java/DeprecationCausedByFunctionNInfo;
.super Lkotlin/reflect/jvm/internal/impl/resolve/deprecation/DescriptorBasedDeprecationInfo;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final target:Lkotlin/reflect/jvm/internal/impl/descriptors/DeclarationDescriptor;


# direct methods
.method public constructor <init>(Lkotlin/reflect/jvm/internal/impl/descriptors/DeclarationDescriptor;)V
    .locals 1

    .line 1
    const-string v0, "target"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/impl/resolve/deprecation/DescriptorBasedDeprecationInfo;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/load/java/DeprecationCausedByFunctionNInfo;->target:Lkotlin/reflect/jvm/internal/impl/descriptors/DeclarationDescriptor;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public getDeprecationLevel()Lkotlin/reflect/jvm/internal/impl/resolve/deprecation/DeprecationLevelValue;
    .locals 0

    .line 1
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/resolve/deprecation/DeprecationLevelValue;->ERROR:Lkotlin/reflect/jvm/internal/impl/resolve/deprecation/DeprecationLevelValue;

    .line 2
    .line 3
    return-object p0
.end method
