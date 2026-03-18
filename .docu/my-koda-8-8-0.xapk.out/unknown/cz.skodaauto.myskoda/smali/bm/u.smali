.class public final Lbm/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lbm/j;


# instance fields
.field public final a:Lez0/i;


# direct methods
.method public constructor <init>(Lez0/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbm/u;->a:Lez0/i;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ldm/i;Lmm/n;)Lbm/k;
    .locals 6

    .line 1
    invoke-static {p2}, Lmm/i;->a(Lmm/n;)Landroid/graphics/Bitmap$Config;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p2, Lmm/n;->a:Landroid/content/Context;

    .line 6
    .line 7
    sget-object v2, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    if-eq v0, v2, :cond_0

    .line 11
    .line 12
    sget-object v2, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 13
    .line 14
    if-ne v0, v2, :cond_6

    .line 15
    .line 16
    :cond_0
    iget-object v0, p1, Ldm/i;->a:Lbm/q;

    .line 17
    .line 18
    invoke-interface {v0}, Lbm/q;->getFileSystem()Lu01/k;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    sget-object v4, Lu01/k;->d:Lu01/u;

    .line 23
    .line 24
    if-ne v2, v4, :cond_1

    .line 25
    .line 26
    invoke-interface {v0}, Lbm/q;->m0()Lu01/y;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    invoke-virtual {v2}, Lu01/y;->toFile()Ljava/io/File;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-static {v0}, Landroid/graphics/ImageDecoder;->createSource(Ljava/io/File;)Landroid/graphics/ImageDecoder$Source;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    goto :goto_0

    .line 41
    :cond_1
    invoke-interface {v0}, Lbm/q;->getMetadata()Ljp/ua;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    instance-of v2, v0, Lbm/a;

    .line 46
    .line 47
    if-eqz v2, :cond_2

    .line 48
    .line 49
    invoke-virtual {v1}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    check-cast v0, Lbm/a;

    .line 54
    .line 55
    iget-object v0, v0, Lbm/a;->a:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {v1, v0}, Landroid/graphics/ImageDecoder;->createSource(Landroid/content/res/AssetManager;Ljava/lang/String;)Landroid/graphics/ImageDecoder$Source;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    goto :goto_0

    .line 62
    :cond_2
    instance-of v2, v0, Lbm/g;

    .line 63
    .line 64
    if-eqz v2, :cond_3

    .line 65
    .line 66
    :try_start_0
    check-cast v0, Lbm/g;

    .line 67
    .line 68
    iget-object v0, v0, Lbm/g;->a:Landroid/content/res/AssetFileDescriptor;

    .line 69
    .line 70
    invoke-virtual {v0}, Landroid/content/res/AssetFileDescriptor;->getFileDescriptor()Ljava/io/FileDescriptor;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    invoke-virtual {v0}, Landroid/content/res/AssetFileDescriptor;->getStartOffset()J

    .line 75
    .line 76
    .line 77
    move-result-wide v4

    .line 78
    sget v2, Landroid/system/OsConstants;->SEEK_SET:I

    .line 79
    .line 80
    invoke-static {v1, v4, v5, v2}, Landroid/system/Os;->lseek(Ljava/io/FileDescriptor;JI)J

    .line 81
    .line 82
    .line 83
    new-instance v1, Lbm/x;

    .line 84
    .line 85
    const/4 v2, 0x0

    .line 86
    invoke-direct {v1, v0, v2}, Lbm/x;-><init>(Ljava/lang/Object;I)V

    .line 87
    .line 88
    .line 89
    invoke-static {v1}, Landroid/graphics/ImageDecoder;->createSource(Ljava/util/concurrent/Callable;)Landroid/graphics/ImageDecoder$Source;

    .line 90
    .line 91
    .line 92
    move-result-object v0
    :try_end_0
    .catch Landroid/system/ErrnoException; {:try_start_0 .. :try_end_0} :catch_0

    .line 93
    goto :goto_0

    .line 94
    :cond_3
    instance-of v2, v0, Lbm/r;

    .line 95
    .line 96
    if-eqz v2, :cond_4

    .line 97
    .line 98
    move-object v2, v0

    .line 99
    check-cast v2, Lbm/r;

    .line 100
    .line 101
    iget-object v4, v2, Lbm/r;->a:Ljava/lang/String;

    .line 102
    .line 103
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v5

    .line 107
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v4

    .line 111
    if-eqz v4, :cond_4

    .line 112
    .line 113
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    iget v1, v2, Lbm/r;->b:I

    .line 118
    .line 119
    invoke-static {v0, v1}, Landroid/graphics/ImageDecoder;->createSource(Landroid/content/res/Resources;I)Landroid/graphics/ImageDecoder$Source;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    goto :goto_0

    .line 124
    :cond_4
    instance-of v1, v0, Lbm/f;

    .line 125
    .line 126
    if-eqz v1, :cond_5

    .line 127
    .line 128
    check-cast v0, Lbm/f;

    .line 129
    .line 130
    iget-object v0, v0, Lbm/f;->a:Ljava/nio/ByteBuffer;

    .line 131
    .line 132
    invoke-static {v0}, Landroid/graphics/ImageDecoder;->createSource(Ljava/nio/ByteBuffer;)Landroid/graphics/ImageDecoder$Source;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    goto :goto_0

    .line 137
    :catch_0
    :cond_5
    move-object v0, v3

    .line 138
    :goto_0
    if-nez v0, :cond_7

    .line 139
    .line 140
    :cond_6
    return-object v3

    .line 141
    :cond_7
    new-instance v1, Lbm/e;

    .line 142
    .line 143
    iget-object p1, p1, Ldm/i;->a:Lbm/q;

    .line 144
    .line 145
    iget-object p0, p0, Lbm/u;->a:Lez0/i;

    .line 146
    .line 147
    invoke-direct {v1, v0, p1, p2, p0}, Lbm/e;-><init>(Landroid/graphics/ImageDecoder$Source;Ljava/lang/AutoCloseable;Lmm/n;Lez0/i;)V

    .line 148
    .line 149
    .line 150
    return-object v1
.end method
