.class public final Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmConstructorExtension;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension$Companion;
    }
.end annotation


# static fields
.field public static final Companion:Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension$Companion;

.field public static final TYPE:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;


# instance fields
.field private signature:Lkotlin/reflect/jvm/internal/impl/km/jvm/JvmMethodSignature;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension;->Companion:Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension$Companion;

    .line 8
    .line 9
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;

    .line 10
    .line 11
    const-class v1, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension;

    .line 12
    .line 13
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 14
    .line 15
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-direct {v0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;-><init>(Lhy0/d;)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension;->TYPE:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;

    .line 23
    .line 24
    return-void
.end method

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
.method public final getSignature()Lkotlin/reflect/jvm/internal/impl/km/jvm/JvmMethodSignature;
    .locals 0

    .line 1
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension;->signature:Lkotlin/reflect/jvm/internal/impl/km/jvm/JvmMethodSignature;

    .line 2
    .line 3
    return-object p0
.end method

.method public getType()Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;
    .locals 0

    .line 1
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension;->TYPE:Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/KmExtensionType;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setSignature(Lkotlin/reflect/jvm/internal/impl/km/jvm/JvmMethodSignature;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/km/jvm/internal/JvmConstructorExtension;->signature:Lkotlin/reflect/jvm/internal/impl/km/jvm/JvmMethodSignature;

    .line 2
    .line 3
    return-void
.end method
