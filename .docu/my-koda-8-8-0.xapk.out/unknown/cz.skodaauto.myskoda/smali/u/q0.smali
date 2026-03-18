.class public final Lu/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Landroid/util/Size;

.field public static final f:Landroid/util/Size;

.field public static final g:Landroid/util/Size;

.field public static final h:Ljava/lang/Object;

.field public static volatile i:Lu/q0;


# instance fields
.field public final a:Landroid/hardware/display/DisplayManager;

.field public volatile b:Landroid/util/Size;

.field public final c:Lt1/j0;

.field public final d:Lpv/g;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Landroid/util/Size;

    .line 2
    .line 3
    const/16 v1, 0x780

    .line 4
    .line 5
    const/16 v2, 0x438

    .line 6
    .line 7
    invoke-direct {v0, v1, v2}, Landroid/util/Size;-><init>(II)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lu/q0;->e:Landroid/util/Size;

    .line 11
    .line 12
    new-instance v0, Landroid/util/Size;

    .line 13
    .line 14
    const/16 v1, 0x140

    .line 15
    .line 16
    const/16 v2, 0xf0

    .line 17
    .line 18
    invoke-direct {v0, v1, v2}, Landroid/util/Size;-><init>(II)V

    .line 19
    .line 20
    .line 21
    sput-object v0, Lu/q0;->f:Landroid/util/Size;

    .line 22
    .line 23
    new-instance v0, Landroid/util/Size;

    .line 24
    .line 25
    const/16 v1, 0x280

    .line 26
    .line 27
    const/16 v2, 0x1e0

    .line 28
    .line 29
    invoke-direct {v0, v1, v2}, Landroid/util/Size;-><init>(II)V

    .line 30
    .line 31
    .line 32
    sput-object v0, Lu/q0;->g:Landroid/util/Size;

    .line 33
    .line 34
    new-instance v0, Ljava/lang/Object;

    .line 35
    .line 36
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 37
    .line 38
    .line 39
    sput-object v0, Lu/q0;->h:Ljava/lang/Object;

    .line 40
    .line 41
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lu/q0;->b:Landroid/util/Size;

    .line 6
    .line 7
    new-instance v0, Lt1/j0;

    .line 8
    .line 9
    const/16 v1, 0x15

    .line 10
    .line 11
    invoke-direct {v0, v1}, Lt1/j0;-><init>(I)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lu/q0;->c:Lt1/j0;

    .line 15
    .line 16
    new-instance v0, Lpv/g;

    .line 17
    .line 18
    const/16 v1, 0x1a

    .line 19
    .line 20
    invoke-direct {v0, v1}, Lpv/g;-><init>(I)V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lu/q0;->d:Lpv/g;

    .line 24
    .line 25
    const-string v0, "display"

    .line 26
    .line 27
    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    check-cast p1, Landroid/hardware/display/DisplayManager;

    .line 32
    .line 33
    iput-object p1, p0, Lu/q0;->a:Landroid/hardware/display/DisplayManager;

    .line 34
    .line 35
    return-void
.end method

.method public static b(Landroid/content/Context;)Lu/q0;
    .locals 2

    .line 1
    sget-object v0, Lu/q0;->i:Lu/q0;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    sget-object v0, Lu/q0;->h:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v0

    .line 8
    :try_start_0
    sget-object v1, Lu/q0;->i:Lu/q0;

    .line 9
    .line 10
    if-nez v1, :cond_0

    .line 11
    .line 12
    new-instance v1, Lu/q0;

    .line 13
    .line 14
    invoke-direct {v1, p0}, Lu/q0;-><init>(Landroid/content/Context;)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lu/q0;->i:Lu/q0;

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :catchall_0
    move-exception p0

    .line 21
    goto :goto_1

    .line 22
    :cond_0
    :goto_0
    monitor-exit v0

    .line 23
    goto :goto_2

    .line 24
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    throw p0

    .line 26
    :cond_1
    :goto_2
    sget-object p0, Lu/q0;->i:Lu/q0;

    .line 27
    .line 28
    return-object p0
.end method

.method public static d([Landroid/view/Display;Z)Landroid/view/Display;
    .locals 7

    .line 1
    array-length v0, p0

    .line 2
    const/4 v1, 0x0

    .line 3
    const/4 v2, -0x1

    .line 4
    const/4 v3, 0x0

    .line 5
    :goto_0
    if-ge v3, v0, :cond_2

    .line 6
    .line 7
    aget-object v4, p0, v3

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    invoke-virtual {v4}, Landroid/view/Display;->getState()I

    .line 12
    .line 13
    .line 14
    move-result v5

    .line 15
    const/4 v6, 0x1

    .line 16
    if-ne v5, v6, :cond_0

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_0
    new-instance v5, Landroid/graphics/Point;

    .line 20
    .line 21
    invoke-direct {v5}, Landroid/graphics/Point;-><init>()V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v4, v5}, Landroid/view/Display;->getRealSize(Landroid/graphics/Point;)V

    .line 25
    .line 26
    .line 27
    iget v6, v5, Landroid/graphics/Point;->x:I

    .line 28
    .line 29
    iget v5, v5, Landroid/graphics/Point;->y:I

    .line 30
    .line 31
    mul-int/2addr v6, v5

    .line 32
    if-le v6, v2, :cond_1

    .line 33
    .line 34
    move-object v1, v4

    .line 35
    move v2, v6

    .line 36
    :cond_1
    :goto_1
    add-int/lit8 v3, v3, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_2
    return-object v1
.end method


# virtual methods
.method public final a()Landroid/util/Size;
    .locals 5

    .line 1
    new-instance v0, Landroid/graphics/Point;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/graphics/Point;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-virtual {p0, v1}, Lu/q0;->c(Z)Landroid/view/Display;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {v1, v0}, Landroid/view/Display;->getRealSize(Landroid/graphics/Point;)V

    .line 12
    .line 13
    .line 14
    new-instance v1, Landroid/util/Size;

    .line 15
    .line 16
    iget v2, v0, Landroid/graphics/Point;->x:I

    .line 17
    .line 18
    iget v0, v0, Landroid/graphics/Point;->y:I

    .line 19
    .line 20
    invoke-direct {v1, v2, v0}, Landroid/util/Size;-><init>(II)V

    .line 21
    .line 22
    .line 23
    sget-object v0, Lo0/a;->a:Landroid/util/Size;

    .line 24
    .line 25
    invoke-virtual {v1}, Landroid/util/Size;->getWidth()I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    invoke-virtual {v1}, Landroid/util/Size;->getHeight()I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    mul-int/2addr v2, v0

    .line 34
    sget-object v0, Lu/q0;->f:Landroid/util/Size;

    .line 35
    .line 36
    invoke-static {v0}, Lo0/a;->a(Landroid/util/Size;)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-ge v2, v0, :cond_1

    .line 41
    .line 42
    iget-object v0, p0, Lu/q0;->d:Lpv/g;

    .line 43
    .line 44
    iget-object v0, v0, Lpv/g;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v0, Landroidx/camera/camera2/internal/compat/quirk/SmallDisplaySizeQuirk;

    .line 47
    .line 48
    if-eqz v0, :cond_0

    .line 49
    .line 50
    sget-object v0, Landroidx/camera/camera2/internal/compat/quirk/SmallDisplaySizeQuirk;->a:Ljava/util/HashMap;

    .line 51
    .line 52
    sget-object v1, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 53
    .line 54
    sget-object v2, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 55
    .line 56
    invoke-virtual {v1, v2}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-virtual {v0, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    check-cast v0, Landroid/util/Size;

    .line 65
    .line 66
    :goto_0
    move-object v1, v0

    .line 67
    goto :goto_1

    .line 68
    :cond_0
    const/4 v0, 0x0

    .line 69
    goto :goto_0

    .line 70
    :goto_1
    if-nez v1, :cond_1

    .line 71
    .line 72
    sget-object v1, Lu/q0;->g:Landroid/util/Size;

    .line 73
    .line 74
    :cond_1
    invoke-virtual {v1}, Landroid/util/Size;->getHeight()I

    .line 75
    .line 76
    .line 77
    move-result v0

    .line 78
    invoke-virtual {v1}, Landroid/util/Size;->getWidth()I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    if-le v0, v2, :cond_2

    .line 83
    .line 84
    new-instance v0, Landroid/util/Size;

    .line 85
    .line 86
    invoke-virtual {v1}, Landroid/util/Size;->getHeight()I

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    invoke-virtual {v1}, Landroid/util/Size;->getWidth()I

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    invoke-direct {v0, v2, v1}, Landroid/util/Size;-><init>(II)V

    .line 95
    .line 96
    .line 97
    move-object v1, v0

    .line 98
    :cond_2
    invoke-virtual {v1}, Landroid/util/Size;->getWidth()I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    invoke-virtual {v1}, Landroid/util/Size;->getHeight()I

    .line 103
    .line 104
    .line 105
    move-result v2

    .line 106
    mul-int/2addr v2, v0

    .line 107
    sget-object v0, Lu/q0;->e:Landroid/util/Size;

    .line 108
    .line 109
    invoke-virtual {v0}, Landroid/util/Size;->getWidth()I

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    invoke-virtual {v0}, Landroid/util/Size;->getHeight()I

    .line 114
    .line 115
    .line 116
    move-result v4

    .line 117
    mul-int/2addr v4, v3

    .line 118
    if-le v2, v4, :cond_3

    .line 119
    .line 120
    move-object v1, v0

    .line 121
    :cond_3
    iget-object p0, p0, Lu/q0;->c:Lt1/j0;

    .line 122
    .line 123
    iget-object p0, p0, Lt1/j0;->e:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast p0, Landroidx/camera/camera2/internal/compat/quirk/ExtraCroppingQuirk;

    .line 126
    .line 127
    if-nez p0, :cond_4

    .line 128
    .line 129
    goto :goto_2

    .line 130
    :cond_4
    sget-object p0, Lh0/g2;->d:Lh0/g2;

    .line 131
    .line 132
    invoke-static {p0}, Landroidx/camera/camera2/internal/compat/quirk/ExtraCroppingQuirk;->b(Lh0/g2;)Landroid/util/Size;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    if-nez p0, :cond_5

    .line 137
    .line 138
    goto :goto_2

    .line 139
    :cond_5
    invoke-virtual {p0}, Landroid/util/Size;->getWidth()I

    .line 140
    .line 141
    .line 142
    move-result v0

    .line 143
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 144
    .line 145
    .line 146
    move-result v2

    .line 147
    mul-int/2addr v2, v0

    .line 148
    invoke-virtual {v1}, Landroid/util/Size;->getWidth()I

    .line 149
    .line 150
    .line 151
    move-result v0

    .line 152
    invoke-virtual {v1}, Landroid/util/Size;->getHeight()I

    .line 153
    .line 154
    .line 155
    move-result v3

    .line 156
    mul-int/2addr v3, v0

    .line 157
    if-le v2, v3, :cond_6

    .line 158
    .line 159
    return-object p0

    .line 160
    :cond_6
    :goto_2
    return-object v1
.end method

.method public final c(Z)Landroid/view/Display;
    .locals 3

    .line 1
    iget-object p0, p0, Lu/q0;->a:Landroid/hardware/display/DisplayManager;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/hardware/display/DisplayManager;->getDisplays()[Landroid/view/Display;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    array-length v0, p0

    .line 8
    const/4 v1, 0x1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-ne v0, v1, :cond_0

    .line 11
    .line 12
    aget-object p0, p0, v2

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_0
    invoke-static {p0, p1}, Lu/q0;->d([Landroid/view/Display;Z)Landroid/view/Display;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    if-eqz p1, :cond_1

    .line 22
    .line 23
    invoke-static {p0, v2}, Lu/q0;->d([Landroid/view/Display;Z)Landroid/view/Display;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    :cond_1
    if-eqz v0, :cond_2

    .line 28
    .line 29
    return-object v0

    .line 30
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 31
    .line 32
    const-string p1, "No display can be found from the input display manager!"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0
.end method

.method public final e()Landroid/util/Size;
    .locals 1

    .line 1
    iget-object v0, p0, Lu/q0;->b:Landroid/util/Size;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lu/q0;->b:Landroid/util/Size;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    invoke-virtual {p0}, Lu/q0;->a()Landroid/util/Size;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lu/q0;->b:Landroid/util/Size;

    .line 13
    .line 14
    iget-object p0, p0, Lu/q0;->b:Landroid/util/Size;

    .line 15
    .line 16
    return-object p0
.end method
