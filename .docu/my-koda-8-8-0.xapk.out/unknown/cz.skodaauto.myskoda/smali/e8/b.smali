.class public final Le8/b;
.super Lz7/g;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final n:Landroid/content/Context;

.field public final o:I


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    new-array v1, v0, [Lz7/e;

    .line 3
    .line 4
    new-array v0, v0, [Le8/a;

    .line 5
    .line 6
    invoke-direct {p0, v1, v0}, Lz7/g;-><init>([Lz7/e;[Lz7/f;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Le8/b;->n:Landroid/content/Context;

    .line 10
    .line 11
    const/4 p1, -0x1

    .line 12
    iput p1, p0, Le8/b;->o:I

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final g()Lz7/e;
    .locals 1

    .line 1
    new-instance p0, Lz7/e;

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    invoke-direct {p0, v0}, Lz7/e;-><init>(I)V

    .line 5
    .line 6
    .line 7
    return-object p0
.end method

.method public final h()Lz7/f;
    .locals 1

    .line 1
    new-instance v0, Le8/a;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Le8/a;-><init>(Le8/b;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public final i(Ljava/lang/Throwable;)Lyq0/l;
    .locals 1

    .line 1
    new-instance p0, Le8/c;

    .line 2
    .line 3
    const-string v0, "Unexpected decode error"

    .line 4
    .line 5
    invoke-direct {p0, v0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 6
    .line 7
    .line 8
    return-object p0
.end method

.method public final j(Lz7/e;Lz7/f;Z)Lyq0/l;
    .locals 5

    .line 1
    check-cast p2, Le8/a;

    .line 2
    .line 3
    iget-object p3, p1, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 4
    .line 5
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    invoke-virtual {p3}, Ljava/nio/ByteBuffer;->hasArray()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {p3}, Ljava/nio/ByteBuffer;->arrayOffset()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const/4 v1, 0x1

    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    move v0, v1

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 v0, 0x0

    .line 25
    :goto_0
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 26
    .line 27
    .line 28
    :try_start_0
    iget v0, p0, Le8/b;->o:I

    .line 29
    .line 30
    const/4 v2, -0x1

    .line 31
    if-eq v0, v2, :cond_1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    iget-object p0, p0, Le8/b;->n:Landroid/content/Context;

    .line 35
    .line 36
    if-eqz p0, :cond_4

    .line 37
    .line 38
    invoke-static {p0}, Lw7/w;->o(Landroid/content/Context;)Landroid/graphics/Point;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    iget v0, p0, Landroid/graphics/Point;->x:I

    .line 43
    .line 44
    iget p0, p0, Landroid/graphics/Point;->y:I

    .line 45
    .line 46
    iget-object v3, p1, Lz7/e;->f:Lt7/o;

    .line 47
    .line 48
    if-eqz v3, :cond_3

    .line 49
    .line 50
    iget v4, v3, Lt7/o;->M:I

    .line 51
    .line 52
    if-eq v4, v2, :cond_2

    .line 53
    .line 54
    mul-int/2addr v0, v4

    .line 55
    :cond_2
    iget v3, v3, Lt7/o;->N:I

    .line 56
    .line 57
    if-eq v3, v2, :cond_3

    .line 58
    .line 59
    mul-int/2addr p0, v3

    .line 60
    :cond_3
    invoke-static {v0, p0}, Ljava/lang/Math;->max(II)I

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    mul-int/lit8 p0, p0, 0x2

    .line 65
    .line 66
    add-int/lit8 v0, p0, -0x1

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_4
    const/16 v0, 0x1000

    .line 70
    .line 71
    :goto_1
    invoke-virtual {p3}, Ljava/nio/ByteBuffer;->array()[B

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    invoke-virtual {p3}, Ljava/nio/Buffer;->remaining()I

    .line 76
    .line 77
    .line 78
    move-result p3

    .line 79
    invoke-static {p0, p3, v0}, Llp/ng;->a([BII)Landroid/graphics/Bitmap;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    iput-object p0, p2, Le8/a;->h:Landroid/graphics/Bitmap;
    :try_end_0
    .catch Lt7/e0; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 84
    .line 85
    iget-wide p0, p1, Lz7/e;->j:J

    .line 86
    .line 87
    iput-wide p0, p2, Lz7/f;->f:J

    .line 88
    .line 89
    const/4 p0, 0x0

    .line 90
    return-object p0

    .line 91
    :catch_0
    move-exception p0

    .line 92
    new-instance p1, Le8/c;

    .line 93
    .line 94
    invoke-direct {p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 95
    .line 96
    .line 97
    goto :goto_2

    .line 98
    :catch_1
    move-exception p0

    .line 99
    new-instance p1, Le8/c;

    .line 100
    .line 101
    const-string p2, "Could not decode image data with BitmapFactory."

    .line 102
    .line 103
    invoke-direct {p1, p2, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 104
    .line 105
    .line 106
    :goto_2
    return-object p1
.end method
