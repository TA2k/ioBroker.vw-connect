.class public final Lcom/google/android/filament/MathUtils;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nPackTangentFrame(FFFFFFFFF[FI)V
.end method

.method public static packTangentFrame(FFFFFFFFF[F)V
    .locals 11

    const/4 v10, 0x0

    move v0, p0

    move v1, p1

    move v2, p2

    move v3, p3

    move v4, p4

    move/from16 v5, p5

    move/from16 v6, p6

    move/from16 v7, p7

    move/from16 v8, p8

    move-object/from16 v9, p9

    .line 1
    invoke-static/range {v0 .. v10}, Lcom/google/android/filament/MathUtils;->nPackTangentFrame(FFFFFFFFF[FI)V

    return-void
.end method

.method public static packTangentFrame(FFFFFFFFF[FI)V
    .locals 0

    .line 2
    invoke-static/range {p0 .. p10}, Lcom/google/android/filament/MathUtils;->nPackTangentFrame(FFFFFFFFF[FI)V

    return-void
.end method
