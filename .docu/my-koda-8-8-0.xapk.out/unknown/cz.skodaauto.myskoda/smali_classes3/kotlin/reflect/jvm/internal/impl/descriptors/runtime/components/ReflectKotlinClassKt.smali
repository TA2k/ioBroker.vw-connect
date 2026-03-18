.class public final Lkotlin/reflect/jvm/internal/impl/descriptors/runtime/components/ReflectKotlinClassKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final TYPES_ELIGIBLE_FOR_SIMPLE_VISIT:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/Class<",
            "*>;>;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 19

    .line 1
    const-class v17, Ljava/lang/Class;

    .line 2
    .line 3
    const-class v18, Ljava/lang/String;

    .line 4
    .line 5
    const-class v1, Ljava/lang/Integer;

    .line 6
    .line 7
    const-class v2, Ljava/lang/Character;

    .line 8
    .line 9
    const-class v3, Ljava/lang/Byte;

    .line 10
    .line 11
    const-class v4, Ljava/lang/Long;

    .line 12
    .line 13
    const-class v5, Ljava/lang/Short;

    .line 14
    .line 15
    const-class v6, Ljava/lang/Boolean;

    .line 16
    .line 17
    const-class v7, Ljava/lang/Double;

    .line 18
    .line 19
    const-class v8, Ljava/lang/Float;

    .line 20
    .line 21
    const-class v9, [I

    .line 22
    .line 23
    const-class v10, [C

    .line 24
    .line 25
    const-class v11, [B

    .line 26
    .line 27
    const-class v12, [J

    .line 28
    .line 29
    const-class v13, [S

    .line 30
    .line 31
    const-class v14, [Z

    .line 32
    .line 33
    const-class v15, [D

    .line 34
    .line 35
    const-class v16, [F

    .line 36
    .line 37
    filled-new-array/range {v1 .. v18}, [Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lkotlin/reflect/jvm/internal/impl/descriptors/runtime/components/ReflectKotlinClassKt;->TYPES_ELIGIBLE_FOR_SIMPLE_VISIT:Ljava/util/Set;

    .line 46
    .line 47
    return-void
.end method

.method public static final synthetic access$getTYPES_ELIGIBLE_FOR_SIMPLE_VISIT$p()Ljava/util/Set;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/descriptors/runtime/components/ReflectKotlinClassKt;->TYPES_ELIGIBLE_FOR_SIMPLE_VISIT:Ljava/util/Set;

    .line 2
    .line 3
    return-object v0
.end method
