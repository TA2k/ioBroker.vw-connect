.class public final Lkotlin/reflect/jvm/internal/impl/types/TypeParameterErasureOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final intersectUpperBounds:Z

.field private final leaveNonTypeParameterTypes:Z


# direct methods
.method public constructor <init>(ZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lkotlin/reflect/jvm/internal/impl/types/TypeParameterErasureOptions;->leaveNonTypeParameterTypes:Z

    .line 5
    .line 6
    iput-boolean p2, p0, Lkotlin/reflect/jvm/internal/impl/types/TypeParameterErasureOptions;->intersectUpperBounds:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final getIntersectUpperBounds()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lkotlin/reflect/jvm/internal/impl/types/TypeParameterErasureOptions;->intersectUpperBounds:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getLeaveNonTypeParameterTypes()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lkotlin/reflect/jvm/internal/impl/types/TypeParameterErasureOptions;->leaveNonTypeParameterTypes:Z

    .line 2
    .line 3
    return p0
.end method
