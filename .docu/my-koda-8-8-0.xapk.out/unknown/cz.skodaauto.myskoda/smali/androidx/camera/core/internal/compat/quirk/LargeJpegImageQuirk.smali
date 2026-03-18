.class public final Landroidx/camera/core/internal/compat/quirk/LargeJpegImageQuirk;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/p1;


# static fields
.field public static final a:Ljava/util/HashSet;


# direct methods
.method static constructor <clinit>()V
    .locals 32

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    const-string v30, "SM-S901B/DS"

    .line 4
    .line 5
    const-string v31, "SM-S906B"

    .line 6
    .line 7
    const-string v1, "SM-A520F"

    .line 8
    .line 9
    const-string v2, "SM-A520L"

    .line 10
    .line 11
    const-string v3, "SM-A520K"

    .line 12
    .line 13
    const-string v4, "SM-A520S"

    .line 14
    .line 15
    const-string v5, "SM-A520X"

    .line 16
    .line 17
    const-string v6, "SM-A520W"

    .line 18
    .line 19
    const-string v7, "SM-A525F"

    .line 20
    .line 21
    const-string v8, "SM-A525M"

    .line 22
    .line 23
    const-string v9, "SM-A705F"

    .line 24
    .line 25
    const-string v10, "SM-A705FN"

    .line 26
    .line 27
    const-string v11, "SM-A705GM"

    .line 28
    .line 29
    const-string v12, "SM-A705MN"

    .line 30
    .line 31
    const-string v13, "SM-A7050"

    .line 32
    .line 33
    const-string v14, "SM-A705W"

    .line 34
    .line 35
    const-string v15, "SM-A705YN"

    .line 36
    .line 37
    const-string v16, "SM-A705U"

    .line 38
    .line 39
    const-string v17, "SM-A715F"

    .line 40
    .line 41
    const-string v18, "SM-A715F/DS"

    .line 42
    .line 43
    const-string v19, "SM-A715F/DSM"

    .line 44
    .line 45
    const-string v20, "SM-A715F/DSN"

    .line 46
    .line 47
    const-string v21, "SM-A715W"

    .line 48
    .line 49
    const-string v22, "SM-A715X"

    .line 50
    .line 51
    const-string v23, "SM-A725F"

    .line 52
    .line 53
    const-string v24, "SM-A725M"

    .line 54
    .line 55
    const-string v25, "SM-M515F"

    .line 56
    .line 57
    const-string v26, "SM-M515F/DSN"

    .line 58
    .line 59
    const-string v27, "SM-G930T"

    .line 60
    .line 61
    const-string v28, "SM-G930V"

    .line 62
    .line 63
    const-string v29, "SM-S901B"

    .line 64
    .line 65
    filled-new-array/range {v1 .. v31}, [Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 74
    .line 75
    .line 76
    new-instance v0, Ljava/util/HashSet;

    .line 77
    .line 78
    const-string v1, "V2045"

    .line 79
    .line 80
    const-string v2, "V2046"

    .line 81
    .line 82
    const-string v3, "V2244A"

    .line 83
    .line 84
    filled-new-array {v3, v1, v2}, [Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 93
    .line 94
    .line 95
    sput-object v0, Landroidx/camera/core/internal/compat/quirk/LargeJpegImageQuirk;->a:Ljava/util/HashSet;

    .line 96
    .line 97
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
