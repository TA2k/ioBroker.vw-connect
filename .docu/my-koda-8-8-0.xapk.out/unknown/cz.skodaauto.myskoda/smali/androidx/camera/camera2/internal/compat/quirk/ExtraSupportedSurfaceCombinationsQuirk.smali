.class public Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/p1;


# static fields
.field public static final a:Lh0/d2;

.field public static final b:Lh0/d2;

.field public static final c:Ljava/util/HashSet;

.field public static final d:Ljava/util/HashSet;


# direct methods
.method static constructor <clinit>()V
    .locals 16

    .line 1
    new-instance v0, Lh0/d2;

    .line 2
    .line 3
    invoke-direct {v0}, Lh0/d2;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object v1, Lh0/g2;->e:Lh0/g2;

    .line 7
    .line 8
    sget-object v2, Lh0/e2;->f:Lh0/e2;

    .line 9
    .line 10
    invoke-static {v1, v2}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    invoke-virtual {v0, v3}, Lh0/d2;->a(Lh0/h2;)V

    .line 15
    .line 16
    .line 17
    sget-object v3, Lh0/g2;->d:Lh0/g2;

    .line 18
    .line 19
    sget-object v4, Lh0/e2;->i:Lh0/e2;

    .line 20
    .line 21
    invoke-static {v3, v4}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 22
    .line 23
    .line 24
    move-result-object v5

    .line 25
    invoke-virtual {v0, v5}, Lh0/d2;->a(Lh0/h2;)V

    .line 26
    .line 27
    .line 28
    sget-object v5, Lh0/e2;->p:Lh0/e2;

    .line 29
    .line 30
    invoke-static {v1, v5}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 31
    .line 32
    .line 33
    move-result-object v6

    .line 34
    invoke-virtual {v0, v6}, Lh0/d2;->a(Lh0/h2;)V

    .line 35
    .line 36
    .line 37
    sput-object v0, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;->a:Lh0/d2;

    .line 38
    .line 39
    new-instance v0, Lh0/d2;

    .line 40
    .line 41
    invoke-direct {v0}, Lh0/d2;-><init>()V

    .line 42
    .line 43
    .line 44
    invoke-static {v3, v4, v0, v3, v2}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 45
    .line 46
    .line 47
    invoke-static {v1, v5}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {v0, v1}, Lh0/d2;->a(Lh0/h2;)V

    .line 52
    .line 53
    .line 54
    sput-object v0, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;->b:Lh0/d2;

    .line 55
    .line 56
    new-instance v0, Ljava/util/HashSet;

    .line 57
    .line 58
    const-string v9, "PIXEL 9 PRO XL"

    .line 59
    .line 60
    const-string v10, "PIXEL 9 PRO FOLD"

    .line 61
    .line 62
    const-string v1, "PIXEL 6"

    .line 63
    .line 64
    const-string v2, "PIXEL 6 PRO"

    .line 65
    .line 66
    const-string v3, "PIXEL 7"

    .line 67
    .line 68
    const-string v4, "PIXEL 7 PRO"

    .line 69
    .line 70
    const-string v5, "PIXEL 8"

    .line 71
    .line 72
    const-string v6, "PIXEL 8 PRO"

    .line 73
    .line 74
    const-string v7, "PIXEL 9"

    .line 75
    .line 76
    const-string v8, "PIXEL 9 PRO"

    .line 77
    .line 78
    filled-new-array/range {v1 .. v10}, [Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v1

    .line 82
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 87
    .line 88
    .line 89
    sput-object v0, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;->c:Ljava/util/HashSet;

    .line 90
    .line 91
    new-instance v0, Ljava/util/HashSet;

    .line 92
    .line 93
    const-string v14, "SC-51F"

    .line 94
    .line 95
    const-string v15, "SC-52F"

    .line 96
    .line 97
    const-string v1, "SM-S921"

    .line 98
    .line 99
    const-string v2, "SC-51E"

    .line 100
    .line 101
    const-string v3, "SCG25"

    .line 102
    .line 103
    const-string v4, "SM-S926"

    .line 104
    .line 105
    const-string v5, "SM-S928"

    .line 106
    .line 107
    const-string v6, "SC-52E"

    .line 108
    .line 109
    const-string v7, "SCG26"

    .line 110
    .line 111
    const-string v8, "SM-S931"

    .line 112
    .line 113
    const-string v9, "SM-S936"

    .line 114
    .line 115
    const-string v10, "SM-S937"

    .line 116
    .line 117
    const-string v11, "SM-S938"

    .line 118
    .line 119
    const-string v12, "SCG31"

    .line 120
    .line 121
    const-string v13, "SCG32"

    .line 122
    .line 123
    filled-new-array/range {v1 .. v15}, [Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 128
    .line 129
    .line 130
    move-result-object v1

    .line 131
    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 132
    .line 133
    .line 134
    sput-object v0, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;->d:Ljava/util/HashSet;

    .line 135
    .line 136
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

.method public static b()Z
    .locals 3

    .line 1
    const-string v0, "samsung"

    .line 2
    .line 3
    sget-object v1, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 13
    .line 14
    sget-object v1, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sget-object v1, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;->d:Ljava/util/HashSet;

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    :cond_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-eqz v2, :cond_2

    .line 31
    .line 32
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    check-cast v2, Ljava/lang/String;

    .line 37
    .line 38
    invoke-virtual {v0, v2}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    if-eqz v2, :cond_1

    .line 43
    .line 44
    const/4 v0, 0x1

    .line 45
    return v0

    .line 46
    :cond_2
    :goto_0
    const/4 v0, 0x0

    .line 47
    return v0
.end method
