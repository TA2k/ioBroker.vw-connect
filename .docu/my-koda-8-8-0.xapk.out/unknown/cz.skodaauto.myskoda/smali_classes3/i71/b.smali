.class public abstract Li71/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh71/n;


# direct methods
.method static constructor <clinit>()V
    .locals 22

    .line 1
    const/16 v0, 0x30

    .line 2
    .line 3
    int-to-float v2, v0

    .line 4
    new-instance v1, Lh71/n;

    .line 5
    .line 6
    const/16 v0, 0x40

    .line 7
    .line 8
    int-to-float v3, v0

    .line 9
    const/4 v0, 0x4

    .line 10
    int-to-float v4, v0

    .line 11
    const/16 v0, 0x18

    .line 12
    .line 13
    int-to-float v5, v0

    .line 14
    const/4 v0, 0x2

    .line 15
    int-to-float v6, v0

    .line 16
    const/16 v0, 0x10

    .line 17
    .line 18
    int-to-float v7, v0

    .line 19
    const/16 v0, 0x58

    .line 20
    .line 21
    int-to-float v9, v0

    .line 22
    const v0, 0x3f11eb85    # 0.57f

    .line 23
    .line 24
    .line 25
    div-float v10, v2, v0

    .line 26
    .line 27
    const-wide/high16 v11, 0x3ff8000000000000L    # 1.5

    .line 28
    .line 29
    double-to-float v12, v11

    .line 30
    const/16 v0, 0xe

    .line 31
    .line 32
    int-to-float v13, v0

    .line 33
    const/16 v0, 0xd7

    .line 34
    .line 35
    int-to-float v15, v0

    .line 36
    const/16 v0, 0x14

    .line 37
    .line 38
    int-to-float v0, v0

    .line 39
    const/16 v8, 0x22

    .line 40
    .line 41
    int-to-float v8, v8

    .line 42
    const/16 v11, 0x8

    .line 43
    .line 44
    int-to-float v11, v11

    .line 45
    move/from16 v18, v8

    .line 46
    .line 47
    move v8, v2

    .line 48
    move/from16 v19, v11

    .line 49
    .line 50
    move v11, v2

    .line 51
    move v14, v3

    .line 52
    move/from16 v17, v13

    .line 53
    .line 54
    move/from16 v20, v2

    .line 55
    .line 56
    move/from16 v21, v12

    .line 57
    .line 58
    move/from16 v16, v0

    .line 59
    .line 60
    invoke-direct/range {v1 .. v21}, Lh71/n;-><init>(FFFFFFFFFFFFFFFFFFFF)V

    .line 61
    .line 62
    .line 63
    sput-object v1, Li71/b;->a:Lh71/n;

    .line 64
    .line 65
    return-void
.end method
