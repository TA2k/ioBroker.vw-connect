.class public final La8/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/q;
.implements Lpv/c;


# instance fields
.field public final synthetic d:I

.field public e:Z

.field public final f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, La8/b;->d:I

    sparse-switch p1, :sswitch_data_0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/b;->f:Ljava/lang/Object;

    new-instance p1, Ljava/util/ArrayDeque;

    invoke-direct {p1}, Ljava/util/ArrayDeque;-><init>()V

    iput-object p1, p0, La8/b;->g:Ljava/lang/Object;

    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    invoke-direct {p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    iput-object p1, p0, La8/b;->h:Ljava/lang/Object;

    return-void

    .line 3
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/16 p1, 0x10

    .line 4
    new-array v0, p1, [F

    iput-object v0, p0, La8/b;->f:Ljava/lang/Object;

    .line 5
    new-array p1, p1, [F

    iput-object p1, p0, La8/b;->g:Ljava/lang/Object;

    .line 6
    new-instance p1, Li4/c;

    invoke-direct {p1}, Li4/c;-><init>()V

    iput-object p1, p0, La8/b;->h:Ljava/lang/Object;

    return-void

    .line 7
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 9
    iput-object p1, p0, La8/b;->f:Ljava/lang/Object;

    .line 10
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, La8/b;->g:Ljava/lang/Object;

    .line 11
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, La8/b;->h:Ljava/lang/Object;

    const/4 p1, 0x1

    .line 12
    iput-boolean p1, p0, La8/b;->e:Z

    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0x6 -> :sswitch_1
        0x9 -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    const/16 v0, 0xc

    iput v0, p0, La8/b;->d:I

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llp/xb;

    const/4 v1, 0x0

    .line 14
    invoke-direct {v0, v1}, Llp/xb;-><init>(Ljava/lang/String;)V

    iput-object v0, p0, La8/b;->g:Ljava/lang/Object;

    iput-object p1, p0, La8/b;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/os/Looper;Landroid/os/Looper;La8/f0;Lw7/r;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, La8/b;->d:I

    .line 21
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 22
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    iput-object p1, p0, La8/b;->f:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 23
    invoke-virtual {p5, p2, p1}, Lw7/r;->a(Landroid/os/Looper;Landroid/os/Handler$Callback;)Lw7/t;

    move-result-object p2

    iput-object p2, p0, La8/b;->h:Ljava/lang/Object;

    .line 24
    new-instance p2, La8/a;

    .line 25
    invoke-virtual {p5, p3, p1}, Lw7/r;->a(Landroid/os/Looper;Landroid/os/Handler$Callback;)Lw7/t;

    move-result-object p1

    invoke-direct {p2, p0, p1, p4}, La8/a;-><init>(La8/b;Lw7/t;La8/f0;)V

    iput-object p2, p0, La8/b;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lj8/o;Ljava/lang/Boolean;)V
    .locals 2

    const/4 v0, 0x5

    iput v0, p0, La8/b;->d:I

    .line 48
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    if-nez p1, :cond_0

    move-object p1, v0

    goto :goto_0

    .line 49
    :cond_0
    invoke-static {p1}, Lu7/b;->a(Landroid/content/Context;)Landroid/media/AudioManager;

    move-result-object p1

    :goto_0
    const/4 v1, 0x0

    if-eqz p1, :cond_3

    if-eqz p3, :cond_1

    .line 50
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p3

    if-eqz p3, :cond_1

    goto :goto_1

    .line 51
    :cond_1
    invoke-static {p1}, Le6/b;->b(Landroid/media/AudioManager;)Landroid/media/Spatializer;

    move-result-object p1

    iput-object p1, p0, La8/b;->f:Ljava/lang/Object;

    .line 52
    invoke-static {p1}, Le6/b;->a(Landroid/media/Spatializer;)I

    move-result p3

    if-eqz p3, :cond_2

    const/4 v1, 0x1

    :cond_2
    iput-boolean v1, p0, La8/b;->e:Z

    .line 53
    new-instance p3, Lj8/j;

    invoke-direct {p3, p2}, Lj8/j;-><init>(Lj8/o;)V

    iput-object p3, p0, La8/b;->h:Ljava/lang/Object;

    .line 54
    new-instance p2, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object v0

    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    invoke-direct {p2, v0}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    iput-object p2, p0, La8/b;->g:Ljava/lang/Object;

    .line 55
    new-instance p0, Lc8/w;

    const/4 v0, 0x0

    invoke-direct {p0, p2, v0}, Lc8/w;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1, p0, p3}, Le6/b;->f(Landroid/media/Spatializer;Lc8/w;Lj8/j;)V

    goto :goto_2

    .line 56
    :cond_3
    :goto_1
    iput-object v0, p0, La8/b;->f:Ljava/lang/Object;

    .line 57
    iput-boolean v1, p0, La8/b;->e:Z

    .line 58
    iput-object v0, p0, La8/b;->g:Ljava/lang/Object;

    .line 59
    iput-object v0, p0, La8/b;->h:Ljava/lang/Object;

    :goto_2
    return-void
.end method

.method public constructor <init>(Lcm/d;Lcm/a;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, La8/b;->d:I

    .line 37
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/b;->h:Ljava/lang/Object;

    iput-object p2, p0, La8/b;->f:Ljava/lang/Object;

    const/4 p1, 0x2

    .line 38
    new-array p1, p1, [Z

    iput-object p1, p0, La8/b;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lcom/google/firebase/messaging/FirebaseMessaging;Ldt/c;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, La8/b;->d:I

    .line 41
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/b;->h:Ljava/lang/Object;

    .line 42
    iput-object p2, p0, La8/b;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lf01/g;Lf01/c;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, La8/b;->d:I

    .line 43
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/b;->h:Ljava/lang/Object;

    .line 44
    iput-object p2, p0, La8/b;->f:Ljava/lang/Object;

    .line 45
    iget-boolean p2, p2, Lf01/c;->e:Z

    if-eqz p2, :cond_0

    const/4 p1, 0x0

    goto :goto_0

    .line 46
    :cond_0
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x2

    .line 47
    new-array p1, p1, [Z

    :goto_0
    iput-object p1, p0, La8/b;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lll/d;Lll/a;)V
    .locals 1

    const/16 v0, 0x8

    iput v0, p0, La8/b;->d:I

    .line 39
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/b;->h:Ljava/lang/Object;

    iput-object p2, p0, La8/b;->f:Ljava/lang/Object;

    const/4 p1, 0x2

    .line 40
    new-array p1, p1, [Z

    iput-object p1, p0, La8/b;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lo1/a0;Lt3/o1;Lo1/z0;)V
    .locals 1

    const/16 v0, 0xa

    iput v0, p0, La8/b;->d:I

    .line 32
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 33
    iput-object p1, p0, La8/b;->f:Ljava/lang/Object;

    .line 34
    iput-object p2, p0, La8/b;->g:Ljava/lang/Object;

    .line 35
    iput-object p3, p0, La8/b;->h:Ljava/lang/Object;

    const/4 p1, 0x1

    .line 36
    iput-boolean p1, p0, La8/b;->e:Z

    return-void
.end method

.method public constructor <init>(Lo8/q;Ll9/h;)V
    .locals 1

    const/4 v0, 0x7

    iput v0, p0, La8/b;->d:I

    .line 17
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 18
    iput-object p1, p0, La8/b;->f:Ljava/lang/Object;

    .line 19
    iput-object p2, p0, La8/b;->g:Ljava/lang/Object;

    .line 20
    new-instance p1, Landroid/util/SparseArray;

    invoke-direct {p1}, Landroid/util/SparseArray;-><init>()V

    iput-object p1, p0, La8/b;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lss/b;Z)V
    .locals 1

    const/16 v0, 0xb

    iput v0, p0, La8/b;->d:I

    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/b;->h:Ljava/lang/Object;

    .line 27
    new-instance p1, Ljava/util/concurrent/atomic/AtomicReference;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, La8/b;->g:Ljava/lang/Object;

    .line 28
    iput-boolean p2, p0, La8/b;->e:Z

    .line 29
    new-instance p1, Los/e;

    if-eqz p2, :cond_0

    const/16 p2, 0x2000

    goto :goto_0

    :cond_0
    const/16 p2, 0x400

    .line 30
    :goto_0
    invoke-direct {p1, p2}, Los/e;-><init>(I)V

    .line 31
    new-instance p2, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    const/4 v0, 0x0

    invoke-direct {p2, p1, v0}, Ljava/util/concurrent/atomic/AtomicMarkableReference;-><init>(Ljava/lang/Object;Z)V

    iput-object p2, p0, La8/b;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lvp/w0;Ljava/lang/String;)V
    .locals 1

    const/16 v0, 0xd

    iput v0, p0, La8/b;->d:I

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, La8/b;->h:Ljava/lang/Object;

    .line 16
    invoke-static {p2}, Lno/c0;->e(Ljava/lang/String;)V

    iput-object p2, p0, La8/b;->f:Ljava/lang/Object;

    return-void
.end method

.method public static f([F[F)V
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {p0, v0}, Landroid/opengl/Matrix;->setIdentityM([FI)V

    .line 3
    .line 4
    .line 5
    const/16 v1, 0xa

    .line 6
    .line 7
    aget v2, p1, v1

    .line 8
    .line 9
    mul-float/2addr v2, v2

    .line 10
    const/16 v3, 0x8

    .line 11
    .line 12
    aget v4, p1, v3

    .line 13
    .line 14
    mul-float/2addr v4, v4

    .line 15
    add-float/2addr v4, v2

    .line 16
    float-to-double v4, v4

    .line 17
    invoke-static {v4, v5}, Ljava/lang/Math;->sqrt(D)D

    .line 18
    .line 19
    .line 20
    move-result-wide v4

    .line 21
    double-to-float v2, v4

    .line 22
    aget v4, p1, v1

    .line 23
    .line 24
    div-float/2addr v4, v2

    .line 25
    aput v4, p0, v0

    .line 26
    .line 27
    aget p1, p1, v3

    .line 28
    .line 29
    div-float v0, p1, v2

    .line 30
    .line 31
    const/4 v5, 0x2

    .line 32
    aput v0, p0, v5

    .line 33
    .line 34
    neg-float p1, p1

    .line 35
    div-float/2addr p1, v2

    .line 36
    aput p1, p0, v3

    .line 37
    .line 38
    aput v4, p0, v1

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public a(Lmv/a;)Lov/d;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, La8/b;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Llp/a4;

    .line 8
    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0}, La8/b;->l()V

    .line 12
    .line 13
    .line 14
    :cond_0
    iget-object v2, v0, La8/b;->h:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Llp/a4;

    .line 17
    .line 18
    if-eqz v2, :cond_18

    .line 19
    .line 20
    iget v2, v1, Lmv/a;->f:I

    .line 21
    .line 22
    const/4 v3, -0x1

    .line 23
    const/4 v4, 0x0

    .line 24
    if-ne v2, v3, :cond_1

    .line 25
    .line 26
    iget-object v2, v1, Lmv/a;->a:Landroid/graphics/Bitmap;

    .line 27
    .line 28
    iget v3, v1, Lmv/a;->e:I

    .line 29
    .line 30
    invoke-static {v3}, Ljp/xa;->a(I)I

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    goto/16 :goto_3

    .line 35
    .line 36
    :cond_1
    if-eq v2, v3, :cond_6

    .line 37
    .line 38
    const/16 v3, 0x11

    .line 39
    .line 40
    const/4 v5, 0x0

    .line 41
    if-eq v2, v3, :cond_5

    .line 42
    .line 43
    const/16 v3, 0x23

    .line 44
    .line 45
    if-eq v2, v3, :cond_3

    .line 46
    .line 47
    const v0, 0x32315659

    .line 48
    .line 49
    .line 50
    if-eq v2, v0, :cond_2

    .line 51
    .line 52
    new-instance v0, Lbv/a;

    .line 53
    .line 54
    const-string v1, "Unsupported image format"

    .line 55
    .line 56
    const/16 v2, 0xd

    .line 57
    .line 58
    invoke-direct {v0, v1, v2}, Lbv/a;-><init>(Ljava/lang/String;I)V

    .line 59
    .line 60
    .line 61
    throw v0

    .line 62
    :cond_2
    invoke-static {v5}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    throw v5

    .line 66
    :cond_3
    invoke-virtual {v1}, Lmv/a;->b()[Landroid/media/Image$Plane;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    iget v3, v1, Lmv/a;->c:I

    .line 74
    .line 75
    iget v5, v1, Lmv/a;->d:I

    .line 76
    .line 77
    invoke-static {v2, v3, v5}, Ljp/ya;->c([Landroid/media/Image$Plane;II)Ljava/nio/ByteBuffer;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    iget v8, v1, Lmv/a;->c:I

    .line 82
    .line 83
    iget v9, v1, Lmv/a;->d:I

    .line 84
    .line 85
    iget v3, v1, Lmv/a;->e:I

    .line 86
    .line 87
    invoke-virtual {v2}, Ljava/nio/ByteBuffer;->hasArray()Z

    .line 88
    .line 89
    .line 90
    move-result v5

    .line 91
    if-eqz v5, :cond_4

    .line 92
    .line 93
    invoke-virtual {v2}, Ljava/nio/ByteBuffer;->arrayOffset()I

    .line 94
    .line 95
    .line 96
    move-result v5

    .line 97
    if-nez v5, :cond_4

    .line 98
    .line 99
    invoke-virtual {v2}, Ljava/nio/ByteBuffer;->array()[B

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    move-object v6, v2

    .line 104
    goto :goto_0

    .line 105
    :cond_4
    invoke-virtual {v2}, Ljava/nio/ByteBuffer;->rewind()Ljava/nio/Buffer;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v2}, Ljava/nio/Buffer;->limit()I

    .line 109
    .line 110
    .line 111
    move-result v5

    .line 112
    new-array v6, v5, [B

    .line 113
    .line 114
    invoke-virtual {v2, v6, v4, v5}, Ljava/nio/ByteBuffer;->get([BII)Ljava/nio/ByteBuffer;

    .line 115
    .line 116
    .line 117
    :goto_0
    const-class v2, Ljava/lang/Throwable;

    .line 118
    .line 119
    new-instance v5, Landroid/graphics/YuvImage;

    .line 120
    .line 121
    const/16 v7, 0x11

    .line 122
    .line 123
    const/4 v10, 0x0

    .line 124
    invoke-direct/range {v5 .. v10}, Landroid/graphics/YuvImage;-><init>([BIII[I)V

    .line 125
    .line 126
    .line 127
    :try_start_0
    new-instance v6, Ljava/io/ByteArrayOutputStream;

    .line 128
    .line 129
    invoke-direct {v6}, Ljava/io/ByteArrayOutputStream;-><init>()V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1

    .line 130
    .line 131
    .line 132
    :try_start_1
    new-instance v7, Landroid/graphics/Rect;

    .line 133
    .line 134
    invoke-direct {v7, v4, v4, v8, v9}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 135
    .line 136
    .line 137
    const/16 v8, 0x64

    .line 138
    .line 139
    invoke-virtual {v5, v7, v8, v6}, Landroid/graphics/YuvImage;->compressToJpeg(Landroid/graphics/Rect;ILjava/io/OutputStream;)Z

    .line 140
    .line 141
    .line 142
    invoke-virtual {v6}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 143
    .line 144
    .line 145
    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 146
    :try_start_2
    invoke-virtual {v6}, Ljava/io/ByteArrayOutputStream;->close()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_1

    .line 147
    .line 148
    .line 149
    array-length v5, v2

    .line 150
    invoke-static {v2, v4, v5}, Landroid/graphics/BitmapFactory;->decodeByteArray([BII)Landroid/graphics/Bitmap;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    invoke-virtual {v2}, Landroid/graphics/Bitmap;->getWidth()I

    .line 155
    .line 156
    .line 157
    move-result v5

    .line 158
    invoke-virtual {v2}, Landroid/graphics/Bitmap;->getHeight()I

    .line 159
    .line 160
    .line 161
    move-result v6

    .line 162
    invoke-static {v2, v3, v5, v6}, Ljp/ya;->d(Landroid/graphics/Bitmap;III)Landroid/graphics/Bitmap;

    .line 163
    .line 164
    .line 165
    move-result-object v2

    .line 166
    goto :goto_2

    .line 167
    :catchall_0
    move-exception v0

    .line 168
    move-object v1, v0

    .line 169
    :try_start_3
    invoke-virtual {v6}, Ljava/io/ByteArrayOutputStream;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 170
    .line 171
    .line 172
    goto :goto_1

    .line 173
    :catchall_1
    move-exception v0

    .line 174
    :try_start_4
    const-string v3, "addSuppressed"

    .line 175
    .line 176
    filled-new-array {v2}, [Ljava/lang/Class;

    .line 177
    .line 178
    .line 179
    move-result-object v4

    .line 180
    invoke-virtual {v2, v3, v4}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    invoke-virtual {v2, v1, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_0

    .line 189
    .line 190
    .line 191
    :catch_0
    :goto_1
    :try_start_5
    throw v1
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_1

    .line 192
    :catch_1
    move-exception v0

    .line 193
    const-string v1, "ImageConvertUtils"

    .line 194
    .line 195
    const-string v2, "Error closing ByteArrayOutputStream"

    .line 196
    .line 197
    invoke-static {v1, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 198
    .line 199
    .line 200
    new-instance v1, Lbv/a;

    .line 201
    .line 202
    const-string v2, "Image conversion error from NV21 format"

    .line 203
    .line 204
    invoke-direct {v1, v2, v0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 205
    .line 206
    .line 207
    throw v1

    .line 208
    :cond_5
    invoke-static {v5}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    throw v5

    .line 212
    :cond_6
    iget-object v2, v1, Lmv/a;->a:Landroid/graphics/Bitmap;

    .line 213
    .line 214
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    iget v3, v1, Lmv/a;->e:I

    .line 218
    .line 219
    iget v5, v1, Lmv/a;->c:I

    .line 220
    .line 221
    iget v6, v1, Lmv/a;->d:I

    .line 222
    .line 223
    invoke-static {v2, v3, v5, v6}, Ljp/ya;->d(Landroid/graphics/Bitmap;III)Landroid/graphics/Bitmap;

    .line 224
    .line 225
    .line 226
    move-result-object v2

    .line 227
    :goto_2
    move v3, v4

    .line 228
    :goto_3
    new-instance v5, Lyo/b;

    .line 229
    .line 230
    invoke-direct {v5, v2}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    iget v2, v1, Lmv/a;->c:I

    .line 234
    .line 235
    iget v1, v1, Lmv/a;->d:I

    .line 236
    .line 237
    :try_start_6
    iget-object v0, v0, La8/b;->h:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v0, Llp/a4;

    .line 240
    .line 241
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 245
    .line 246
    .line 247
    move-result-object v6

    .line 248
    sget v7, Llp/s;->a:I

    .line 249
    .line 250
    invoke-virtual {v6, v5}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 251
    .line 252
    .line 253
    const/4 v5, 0x1

    .line 254
    invoke-virtual {v6, v5}, Landroid/os/Parcel;->writeInt(I)V

    .line 255
    .line 256
    .line 257
    const/16 v7, 0x4f45

    .line 258
    .line 259
    invoke-static {v6, v7}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 260
    .line 261
    .line 262
    move-result v7

    .line 263
    const/4 v8, 0x4

    .line 264
    const/4 v9, 0x2

    .line 265
    invoke-static {v6, v9, v8}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 266
    .line 267
    .line 268
    invoke-virtual {v6, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 269
    .line 270
    .line 271
    const/4 v2, 0x3

    .line 272
    invoke-static {v6, v2, v8}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 273
    .line 274
    .line 275
    invoke-virtual {v6, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 276
    .line 277
    .line 278
    invoke-static {v6, v8, v8}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {v6, v4}, Landroid/os/Parcel;->writeInt(I)V

    .line 282
    .line 283
    .line 284
    const/4 v1, 0x5

    .line 285
    const/16 v10, 0x8

    .line 286
    .line 287
    invoke-static {v6, v1, v10}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 288
    .line 289
    .line 290
    const-wide/16 v10, 0x0

    .line 291
    .line 292
    invoke-virtual {v6, v10, v11}, Landroid/os/Parcel;->writeLong(J)V

    .line 293
    .line 294
    .line 295
    const/4 v1, 0x6

    .line 296
    invoke-static {v6, v1, v8}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 297
    .line 298
    .line 299
    invoke-virtual {v6, v3}, Landroid/os/Parcel;->writeInt(I)V

    .line 300
    .line 301
    .line 302
    invoke-static {v6, v7}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 303
    .line 304
    .line 305
    invoke-virtual {v0, v6, v5}, Lbp/a;->T(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 306
    .line 307
    .line 308
    move-result-object v0

    .line 309
    sget-object v1, Llp/e8;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 310
    .line 311
    invoke-virtual {v0, v1}, Landroid/os/Parcel;->createTypedArray(Landroid/os/Parcelable$Creator;)[Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object v1

    .line 315
    check-cast v1, [Llp/e8;

    .line 316
    .line 317
    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V
    :try_end_6
    .catch Landroid/os/RemoteException; {:try_start_6 .. :try_end_6} :catch_2

    .line 318
    .line 319
    .line 320
    new-instance v0, Landroid/util/SparseArray;

    .line 321
    .line 322
    invoke-direct {v0}, Landroid/util/SparseArray;-><init>()V

    .line 323
    .line 324
    .line 325
    array-length v3, v1

    .line 326
    move v6, v4

    .line 327
    :goto_4
    if-ge v6, v3, :cond_8

    .line 328
    .line 329
    aget-object v7, v1, v6

    .line 330
    .line 331
    iget v10, v7, Llp/e8;->m:I

    .line 332
    .line 333
    invoke-virtual {v0, v10}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object v10

    .line 337
    check-cast v10, Landroid/util/SparseArray;

    .line 338
    .line 339
    if-nez v10, :cond_7

    .line 340
    .line 341
    new-instance v10, Landroid/util/SparseArray;

    .line 342
    .line 343
    invoke-direct {v10}, Landroid/util/SparseArray;-><init>()V

    .line 344
    .line 345
    .line 346
    iget v11, v7, Llp/e8;->m:I

    .line 347
    .line 348
    invoke-virtual {v0, v11, v10}, Landroid/util/SparseArray;->append(ILjava/lang/Object;)V

    .line 349
    .line 350
    .line 351
    :cond_7
    iget v11, v7, Llp/e8;->n:I

    .line 352
    .line 353
    invoke-virtual {v10, v11, v7}, Landroid/util/SparseArray;->append(ILjava/lang/Object;)V

    .line 354
    .line 355
    .line 356
    add-int/lit8 v6, v6, 0x1

    .line 357
    .line 358
    goto :goto_4

    .line 359
    :cond_8
    new-array v1, v8, [Ljava/lang/Object;

    .line 360
    .line 361
    move v3, v4

    .line 362
    move v6, v3

    .line 363
    :goto_5
    invoke-virtual {v0}, Landroid/util/SparseArray;->size()I

    .line 364
    .line 365
    .line 366
    move-result v7

    .line 367
    const/16 v10, 0xb

    .line 368
    .line 369
    if-ge v3, v7, :cond_17

    .line 370
    .line 371
    invoke-virtual {v0, v3}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 372
    .line 373
    .line 374
    move-result-object v7

    .line 375
    check-cast v7, Landroid/util/SparseArray;

    .line 376
    .line 377
    new-array v11, v8, [Ljava/lang/Object;

    .line 378
    .line 379
    move v12, v4

    .line 380
    move v13, v12

    .line 381
    :goto_6
    invoke-virtual {v7}, Landroid/util/SparseArray;->size()I

    .line 382
    .line 383
    .line 384
    move-result v14

    .line 385
    if-ge v12, v14, :cond_c

    .line 386
    .line 387
    invoke-virtual {v7, v12}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    move-result-object v14

    .line 391
    check-cast v14, Llp/e8;

    .line 392
    .line 393
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 394
    .line 395
    .line 396
    move/from16 p0, v2

    .line 397
    .line 398
    add-int/lit8 v2, v13, 0x1

    .line 399
    .line 400
    move/from16 p1, v5

    .line 401
    .line 402
    array-length v5, v11

    .line 403
    if-ge v5, v2, :cond_b

    .line 404
    .line 405
    shr-int/lit8 v16, v5, 0x1

    .line 406
    .line 407
    add-int v5, v5, v16

    .line 408
    .line 409
    add-int/lit8 v5, v5, 0x1

    .line 410
    .line 411
    if-ge v5, v2, :cond_9

    .line 412
    .line 413
    invoke-static {v13}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 414
    .line 415
    .line 416
    move-result v5

    .line 417
    add-int/2addr v5, v5

    .line 418
    :cond_9
    if-gez v5, :cond_a

    .line 419
    .line 420
    const v15, 0x7fffffff

    .line 421
    .line 422
    .line 423
    goto :goto_7

    .line 424
    :cond_a
    move v15, v5

    .line 425
    :goto_7
    invoke-static {v11, v15}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 426
    .line 427
    .line 428
    move-result-object v5

    .line 429
    move-object v11, v5

    .line 430
    :cond_b
    aput-object v14, v11, v13

    .line 431
    .line 432
    add-int/lit8 v12, v12, 0x1

    .line 433
    .line 434
    move/from16 v5, p1

    .line 435
    .line 436
    move v13, v2

    .line 437
    move/from16 v2, p0

    .line 438
    .line 439
    goto :goto_6

    .line 440
    :cond_c
    move/from16 p0, v2

    .line 441
    .line 442
    move/from16 p1, v5

    .line 443
    .line 444
    invoke-static {v13, v11}, Llp/o;->m(I[Ljava/lang/Object;)Llp/u;

    .line 445
    .line 446
    .line 447
    move-result-object v2

    .line 448
    new-instance v5, Lwq/f;

    .line 449
    .line 450
    invoke-direct {v5, v10}, Lwq/f;-><init>(I)V

    .line 451
    .line 452
    .line 453
    invoke-static {v2, v5}, Llp/cg;->d(Ljava/util/List;Llp/jg;)Ljava/util/AbstractList;

    .line 454
    .line 455
    .line 456
    move-result-object v5

    .line 457
    invoke-virtual {v2, v4}, Llp/u;->get(I)Ljava/lang/Object;

    .line 458
    .line 459
    .line 460
    move-result-object v7

    .line 461
    check-cast v7, Llp/e8;

    .line 462
    .line 463
    iget-object v7, v7, Llp/e8;->e:Llp/y1;

    .line 464
    .line 465
    invoke-virtual {v2, v4}, Llp/o;->n(I)Llp/m;

    .line 466
    .line 467
    .line 468
    move-result-object v2

    .line 469
    const/high16 v10, -0x80000000

    .line 470
    .line 471
    move v11, v10

    .line 472
    const v12, 0x7fffffff

    .line 473
    .line 474
    .line 475
    const v13, 0x7fffffff

    .line 476
    .line 477
    .line 478
    :goto_8
    invoke-virtual {v2}, Llp/m;->hasNext()Z

    .line 479
    .line 480
    .line 481
    move-result v14

    .line 482
    if-eqz v14, :cond_e

    .line 483
    .line 484
    invoke-virtual {v2}, Llp/m;->next()Ljava/lang/Object;

    .line 485
    .line 486
    .line 487
    move-result-object v14

    .line 488
    check-cast v14, Llp/e8;

    .line 489
    .line 490
    iget-object v14, v14, Llp/e8;->e:Llp/y1;

    .line 491
    .line 492
    move/from16 v16, v4

    .line 493
    .line 494
    iget v4, v7, Llp/y1;->d:I

    .line 495
    .line 496
    move/from16 v17, v9

    .line 497
    .line 498
    iget v9, v7, Llp/y1;->h:F

    .line 499
    .line 500
    neg-int v4, v4

    .line 501
    iget v15, v7, Llp/y1;->e:I

    .line 502
    .line 503
    neg-int v15, v15

    .line 504
    float-to-double v8, v9

    .line 505
    invoke-static {v8, v9}, Ljava/lang/Math;->toRadians(D)D

    .line 506
    .line 507
    .line 508
    move-result-wide v19

    .line 509
    invoke-static/range {v19 .. v20}, Ljava/lang/Math;->sin(D)D

    .line 510
    .line 511
    .line 512
    move-result-wide v19

    .line 513
    invoke-static {v8, v9}, Ljava/lang/Math;->toRadians(D)D

    .line 514
    .line 515
    .line 516
    move-result-wide v8

    .line 517
    invoke-static {v8, v9}, Ljava/lang/Math;->cos(D)D

    .line 518
    .line 519
    .line 520
    move-result-wide v8

    .line 521
    move-object/from16 v21, v0

    .line 522
    .line 523
    move-object/from16 v22, v2

    .line 524
    .line 525
    const/4 v0, 0x4

    .line 526
    new-array v2, v0, [Landroid/graphics/Point;

    .line 527
    .line 528
    new-instance v0, Landroid/graphics/Point;

    .line 529
    .line 530
    move-object/from16 v23, v2

    .line 531
    .line 532
    iget v2, v14, Llp/y1;->d:I

    .line 533
    .line 534
    move/from16 v24, v3

    .line 535
    .line 536
    iget v3, v14, Llp/y1;->g:I

    .line 537
    .line 538
    move/from16 v25, v3

    .line 539
    .line 540
    iget v3, v14, Llp/y1;->f:I

    .line 541
    .line 542
    iget v14, v14, Llp/y1;->e:I

    .line 543
    .line 544
    invoke-direct {v0, v2, v14}, Landroid/graphics/Point;-><init>(II)V

    .line 545
    .line 546
    .line 547
    aput-object v0, v23, v16

    .line 548
    .line 549
    invoke-virtual {v0, v4, v15}, Landroid/graphics/Point;->offset(II)V

    .line 550
    .line 551
    .line 552
    aget-object v0, v23, v16

    .line 553
    .line 554
    iget v2, v0, Landroid/graphics/Point;->x:I

    .line 555
    .line 556
    int-to-double v14, v2

    .line 557
    mul-double/2addr v14, v8

    .line 558
    iget v4, v0, Landroid/graphics/Point;->y:I

    .line 559
    .line 560
    move/from16 v26, v3

    .line 561
    .line 562
    int-to-double v3, v4

    .line 563
    mul-double v27, v3, v19

    .line 564
    .line 565
    neg-int v2, v2

    .line 566
    move-wide/from16 v29, v3

    .line 567
    .line 568
    int-to-double v2, v2

    .line 569
    mul-double v2, v2, v19

    .line 570
    .line 571
    mul-double v8, v8, v29

    .line 572
    .line 573
    add-double v14, v14, v27

    .line 574
    .line 575
    double-to-int v4, v14

    .line 576
    iput v4, v0, Landroid/graphics/Point;->x:I

    .line 577
    .line 578
    add-double/2addr v2, v8

    .line 579
    double-to-int v2, v2

    .line 580
    iput v2, v0, Landroid/graphics/Point;->y:I

    .line 581
    .line 582
    new-instance v0, Landroid/graphics/Point;

    .line 583
    .line 584
    add-int v3, v4, v26

    .line 585
    .line 586
    invoke-direct {v0, v3, v2}, Landroid/graphics/Point;-><init>(II)V

    .line 587
    .line 588
    .line 589
    aput-object v0, v23, p1

    .line 590
    .line 591
    new-instance v0, Landroid/graphics/Point;

    .line 592
    .line 593
    add-int v2, v2, v25

    .line 594
    .line 595
    invoke-direct {v0, v3, v2}, Landroid/graphics/Point;-><init>(II)V

    .line 596
    .line 597
    .line 598
    aput-object v0, v23, v17

    .line 599
    .line 600
    new-instance v0, Landroid/graphics/Point;

    .line 601
    .line 602
    invoke-direct {v0, v4, v2}, Landroid/graphics/Point;-><init>(II)V

    .line 603
    .line 604
    .line 605
    aput-object v0, v23, p0

    .line 606
    .line 607
    move/from16 v0, v16

    .line 608
    .line 609
    :goto_9
    const/4 v2, 0x4

    .line 610
    if-ge v0, v2, :cond_d

    .line 611
    .line 612
    aget-object v2, v23, v0

    .line 613
    .line 614
    iget v3, v2, Landroid/graphics/Point;->x:I

    .line 615
    .line 616
    invoke-static {v12, v3}, Ljava/lang/Math;->min(II)I

    .line 617
    .line 618
    .line 619
    move-result v12

    .line 620
    iget v3, v2, Landroid/graphics/Point;->x:I

    .line 621
    .line 622
    invoke-static {v10, v3}, Ljava/lang/Math;->max(II)I

    .line 623
    .line 624
    .line 625
    move-result v10

    .line 626
    iget v3, v2, Landroid/graphics/Point;->y:I

    .line 627
    .line 628
    invoke-static {v13, v3}, Ljava/lang/Math;->min(II)I

    .line 629
    .line 630
    .line 631
    move-result v13

    .line 632
    iget v2, v2, Landroid/graphics/Point;->y:I

    .line 633
    .line 634
    invoke-static {v11, v2}, Ljava/lang/Math;->max(II)I

    .line 635
    .line 636
    .line 637
    move-result v11

    .line 638
    add-int/lit8 v0, v0, 0x1

    .line 639
    .line 640
    goto :goto_9

    .line 641
    :cond_d
    move v8, v2

    .line 642
    move/from16 v4, v16

    .line 643
    .line 644
    move/from16 v9, v17

    .line 645
    .line 646
    move-object/from16 v0, v21

    .line 647
    .line 648
    move-object/from16 v2, v22

    .line 649
    .line 650
    move/from16 v3, v24

    .line 651
    .line 652
    goto/16 :goto_8

    .line 653
    .line 654
    :cond_e
    move-object/from16 v21, v0

    .line 655
    .line 656
    move/from16 v24, v3

    .line 657
    .line 658
    move/from16 v16, v4

    .line 659
    .line 660
    move/from16 v17, v9

    .line 661
    .line 662
    iget v0, v7, Llp/y1;->d:I

    .line 663
    .line 664
    iget v2, v7, Llp/y1;->h:F

    .line 665
    .line 666
    iget v3, v7, Llp/y1;->e:I

    .line 667
    .line 668
    float-to-double v7, v2

    .line 669
    invoke-static {v7, v8}, Ljava/lang/Math;->toRadians(D)D

    .line 670
    .line 671
    .line 672
    move-result-wide v14

    .line 673
    invoke-static {v14, v15}, Ljava/lang/Math;->sin(D)D

    .line 674
    .line 675
    .line 676
    move-result-wide v14

    .line 677
    invoke-static {v7, v8}, Ljava/lang/Math;->toRadians(D)D

    .line 678
    .line 679
    .line 680
    move-result-wide v7

    .line 681
    invoke-static {v7, v8}, Ljava/lang/Math;->cos(D)D

    .line 682
    .line 683
    .line 684
    move-result-wide v7

    .line 685
    new-instance v2, Landroid/graphics/Point;

    .line 686
    .line 687
    invoke-direct {v2, v12, v13}, Landroid/graphics/Point;-><init>(II)V

    .line 688
    .line 689
    .line 690
    new-instance v4, Landroid/graphics/Point;

    .line 691
    .line 692
    invoke-direct {v4, v10, v13}, Landroid/graphics/Point;-><init>(II)V

    .line 693
    .line 694
    .line 695
    new-instance v9, Landroid/graphics/Point;

    .line 696
    .line 697
    invoke-direct {v9, v10, v11}, Landroid/graphics/Point;-><init>(II)V

    .line 698
    .line 699
    .line 700
    new-instance v10, Landroid/graphics/Point;

    .line 701
    .line 702
    invoke-direct {v10, v12, v11}, Landroid/graphics/Point;-><init>(II)V

    .line 703
    .line 704
    .line 705
    filled-new-array {v2, v4, v9, v10}, [Landroid/graphics/Point;

    .line 706
    .line 707
    .line 708
    move-result-object v2

    .line 709
    move/from16 v4, v16

    .line 710
    .line 711
    :goto_a
    const/4 v9, 0x4

    .line 712
    if-ge v4, v9, :cond_f

    .line 713
    .line 714
    aget-object v10, v2, v4

    .line 715
    .line 716
    iget v11, v10, Landroid/graphics/Point;->x:I

    .line 717
    .line 718
    int-to-double v11, v11

    .line 719
    mul-double v18, v11, v7

    .line 720
    .line 721
    iget v13, v10, Landroid/graphics/Point;->y:I

    .line 722
    .line 723
    move-object/from16 v22, v10

    .line 724
    .line 725
    int-to-double v9, v13

    .line 726
    mul-double v25, v9, v14

    .line 727
    .line 728
    mul-double/2addr v11, v14

    .line 729
    mul-double/2addr v9, v7

    .line 730
    move-wide/from16 v27, v7

    .line 731
    .line 732
    sub-double v7, v18, v25

    .line 733
    .line 734
    double-to-int v7, v7

    .line 735
    move-object/from16 v8, v22

    .line 736
    .line 737
    iput v7, v8, Landroid/graphics/Point;->x:I

    .line 738
    .line 739
    add-double/2addr v11, v9

    .line 740
    double-to-int v7, v11

    .line 741
    iput v7, v8, Landroid/graphics/Point;->y:I

    .line 742
    .line 743
    invoke-virtual {v8, v0, v3}, Landroid/graphics/Point;->offset(II)V

    .line 744
    .line 745
    .line 746
    add-int/lit8 v4, v4, 0x1

    .line 747
    .line 748
    move-wide/from16 v7, v27

    .line 749
    .line 750
    goto :goto_a

    .line 751
    :cond_f
    invoke-static {v2}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 752
    .line 753
    .line 754
    move-result-object v0

    .line 755
    new-instance v2, Lov/c;

    .line 756
    .line 757
    new-instance v3, La61/a;

    .line 758
    .line 759
    const/16 v4, 0xc

    .line 760
    .line 761
    invoke-direct {v3, v4}, La61/a;-><init>(I)V

    .line 762
    .line 763
    .line 764
    invoke-static {v5, v3}, Llp/cg;->d(Ljava/util/List;Llp/jg;)Ljava/util/AbstractList;

    .line 765
    .line 766
    .line 767
    move-result-object v3

    .line 768
    invoke-static {v3}, Llp/eg;->g(Ljava/util/AbstractList;)Ljava/lang/String;

    .line 769
    .line 770
    .line 771
    move-result-object v3

    .line 772
    invoke-static {v0}, Lpv/b;->a(Ljava/util/List;)Landroid/graphics/Rect;

    .line 773
    .line 774
    .line 775
    move-result-object v4

    .line 776
    new-instance v7, Ljava/util/HashMap;

    .line 777
    .line 778
    invoke-direct {v7}, Ljava/util/HashMap;-><init>()V

    .line 779
    .line 780
    .line 781
    invoke-interface {v5}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 782
    .line 783
    .line 784
    move-result-object v5

    .line 785
    :goto_b
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 786
    .line 787
    .line 788
    move-result v8

    .line 789
    if-eqz v8, :cond_11

    .line 790
    .line 791
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 792
    .line 793
    .line 794
    move-result-object v8

    .line 795
    check-cast v8, Lov/b;

    .line 796
    .line 797
    iget-object v8, v8, Lh/w;->c:Ljava/lang/Object;

    .line 798
    .line 799
    check-cast v8, Ljava/lang/String;

    .line 800
    .line 801
    invoke-virtual {v7, v8}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 802
    .line 803
    .line 804
    move-result v9

    .line 805
    if-eqz v9, :cond_10

    .line 806
    .line 807
    invoke-virtual {v7, v8}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 808
    .line 809
    .line 810
    move-result-object v9

    .line 811
    check-cast v9, Ljava/lang/Integer;

    .line 812
    .line 813
    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    .line 814
    .line 815
    .line 816
    move-result v9

    .line 817
    goto :goto_c

    .line 818
    :cond_10
    move/from16 v9, v16

    .line 819
    .line 820
    :goto_c
    add-int/lit8 v9, v9, 0x1

    .line 821
    .line 822
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 823
    .line 824
    .line 825
    move-result-object v9

    .line 826
    invoke-virtual {v7, v8, v9}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 827
    .line 828
    .line 829
    goto :goto_b

    .line 830
    :cond_11
    invoke-virtual {v7}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 831
    .line 832
    .line 833
    move-result-object v5

    .line 834
    invoke-interface {v5}, Ljava/util/Set;->isEmpty()Z

    .line 835
    .line 836
    .line 837
    move-result v7

    .line 838
    if-eqz v7, :cond_12

    .line 839
    .line 840
    goto :goto_d

    .line 841
    :cond_12
    sget-object v7, Lpv/b;->a:La5/f;

    .line 842
    .line 843
    invoke-static {v5, v7}, Ljava/util/Collections;->max(Ljava/util/Collection;Ljava/util/Comparator;)Ljava/lang/Object;

    .line 844
    .line 845
    .line 846
    move-result-object v5

    .line 847
    check-cast v5, Ljava/util/Map$Entry;

    .line 848
    .line 849
    invoke-interface {v5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 850
    .line 851
    .line 852
    move-result-object v5

    .line 853
    check-cast v5, Ljava/lang/String;

    .line 854
    .line 855
    invoke-static {v5}, Lm20/k;->b(Ljava/lang/String;)Z

    .line 856
    .line 857
    .line 858
    move-result v7

    .line 859
    if-nez v7, :cond_13

    .line 860
    .line 861
    goto :goto_e

    .line 862
    :cond_13
    :goto_d
    const-string v5, "und"

    .line 863
    .line 864
    :goto_e
    invoke-direct {v2, v3, v4, v0, v5}, Lh/w;-><init>(Ljava/lang/String;Landroid/graphics/Rect;Ljava/util/List;Ljava/lang/String;)V

    .line 865
    .line 866
    .line 867
    add-int/lit8 v0, v6, 0x1

    .line 868
    .line 869
    array-length v3, v1

    .line 870
    if-ge v3, v0, :cond_16

    .line 871
    .line 872
    shr-int/lit8 v4, v3, 0x1

    .line 873
    .line 874
    add-int/2addr v3, v4

    .line 875
    add-int/lit8 v3, v3, 0x1

    .line 876
    .line 877
    if-ge v3, v0, :cond_14

    .line 878
    .line 879
    invoke-static {v6}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 880
    .line 881
    .line 882
    move-result v3

    .line 883
    add-int/2addr v3, v3

    .line 884
    :cond_14
    if-gez v3, :cond_15

    .line 885
    .line 886
    const v15, 0x7fffffff

    .line 887
    .line 888
    .line 889
    goto :goto_f

    .line 890
    :cond_15
    move v15, v3

    .line 891
    :goto_f
    invoke-static {v1, v15}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 892
    .line 893
    .line 894
    move-result-object v1

    .line 895
    :cond_16
    aput-object v2, v1, v6

    .line 896
    .line 897
    add-int/lit8 v3, v24, 0x1

    .line 898
    .line 899
    move/from16 v2, p0

    .line 900
    .line 901
    move/from16 v5, p1

    .line 902
    .line 903
    move v6, v0

    .line 904
    move/from16 v4, v16

    .line 905
    .line 906
    move/from16 v9, v17

    .line 907
    .line 908
    move-object/from16 v0, v21

    .line 909
    .line 910
    const/4 v8, 0x4

    .line 911
    goto/16 :goto_5

    .line 912
    .line 913
    :cond_17
    invoke-static {v6, v1}, Llp/o;->m(I[Ljava/lang/Object;)Llp/u;

    .line 914
    .line 915
    .line 916
    move-result-object v0

    .line 917
    new-instance v1, Lov/d;

    .line 918
    .line 919
    new-instance v2, Lwe0/b;

    .line 920
    .line 921
    invoke-direct {v2, v10}, Lwe0/b;-><init>(I)V

    .line 922
    .line 923
    .line 924
    invoke-static {v0, v2}, Llp/cg;->d(Ljava/util/List;Llp/jg;)Ljava/util/AbstractList;

    .line 925
    .line 926
    .line 927
    move-result-object v2

    .line 928
    invoke-static {v2}, Llp/eg;->g(Ljava/util/AbstractList;)Ljava/lang/String;

    .line 929
    .line 930
    .line 931
    move-result-object v2

    .line 932
    invoke-direct {v1, v2, v0}, Lov/d;-><init>(Ljava/lang/String;Llp/u;)V

    .line 933
    .line 934
    .line 935
    return-object v1

    .line 936
    :catch_2
    move-exception v0

    .line 937
    new-instance v1, Lbv/a;

    .line 938
    .line 939
    const-string v2, "Failed to run legacy text recognizer."

    .line 940
    .line 941
    invoke-direct {v1, v2, v0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 942
    .line 943
    .line 944
    throw v1

    .line 945
    :cond_18
    new-instance v0, Lbv/a;

    .line 946
    .line 947
    const-string v1, "Waiting for the text recognition module to be downloaded. Please wait."

    .line 948
    .line 949
    const/16 v2, 0xe

    .line 950
    .line 951
    invoke-direct {v0, v1, v2}, Lbv/a;-><init>(Ljava/lang/String;I)V

    .line 952
    .line 953
    .line 954
    throw v0
.end method

.method public b()V
    .locals 2

    .line 1
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lf01/g;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-boolean v1, p0, La8/b;->e:Z

    .line 7
    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    iget-object v1, p0, La8/b;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lf01/c;

    .line 13
    .line 14
    iget-object v1, v1, Lf01/c;->g:La8/b;

    .line 15
    .line 16
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    const/4 v1, 0x0

    .line 23
    invoke-virtual {v0, p0, v1}, Lf01/g;->b(La8/b;Z)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :catchall_0
    move-exception p0

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    :goto_0
    const/4 v1, 0x1

    .line 30
    iput-boolean v1, p0, La8/b;->e:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    .line 32
    monitor-exit v0

    .line 33
    return-void

    .line 34
    :cond_1
    :try_start_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 35
    .line 36
    const-string v1, "Check failed."

    .line 37
    .line 38
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 42
    :goto_1
    monitor-exit v0

    .line 43
    throw p0
.end method

.method public c(Lo8/c0;)V
    .locals 0

    .line 1
    iget-object p0, p0, La8/b;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lo8/q;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lo8/q;->c(Lo8/c0;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public d()V
    .locals 3

    .line 1
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lf01/g;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-boolean v1, p0, La8/b;->e:Z

    .line 7
    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    iget-object v1, p0, La8/b;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lf01/c;

    .line 13
    .line 14
    iget-object v1, v1, Lf01/c;->g:La8/b;

    .line 15
    .line 16
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    const/4 v2, 0x1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    invoke-virtual {v0, p0, v2}, Lf01/g;->b(La8/b;Z)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :catchall_0
    move-exception p0

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    :goto_0
    iput-boolean v2, p0, La8/b;->e:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    .line 31
    monitor-exit v0

    .line 32
    return-void

    .line 33
    :cond_1
    :try_start_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 34
    .line 35
    const-string v1, "Check failed."

    .line 36
    .line 37
    invoke-direct {p0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 41
    :goto_1
    monitor-exit v0

    .line 42
    throw p0
.end method

.method public e(Z)V
    .locals 3

    .line 1
    iget v0, p0, La8/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lll/d;

    .line 9
    .line 10
    monitor-enter v0

    .line 11
    :try_start_0
    iget-boolean v1, p0, La8/b;->e:Z

    .line 12
    .line 13
    if-nez v1, :cond_1

    .line 14
    .line 15
    iget-object v1, p0, La8/b;->f:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Lll/a;

    .line 18
    .line 19
    iget-object v1, v1, Lll/a;->g:La8/b;

    .line 20
    .line 21
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    invoke-static {v0, p0, p1}, Lll/d;->a(Lll/d;La8/b;Z)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :catchall_0
    move-exception p0

    .line 32
    goto :goto_1

    .line 33
    :cond_0
    :goto_0
    const/4 p1, 0x1

    .line 34
    iput-boolean p1, p0, La8/b;->e:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    .line 36
    monitor-exit v0

    .line 37
    return-void

    .line 38
    :cond_1
    :try_start_1
    const-string p0, "editor is closed"

    .line 39
    .line 40
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 46
    :goto_1
    monitor-exit v0

    .line 47
    throw p0

    .line 48
    :pswitch_0
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v0, Lcm/d;

    .line 51
    .line 52
    iget-object v1, v0, Lcm/d;->k:Ljava/lang/Object;

    .line 53
    .line 54
    monitor-enter v1

    .line 55
    :try_start_2
    iget-boolean v2, p0, La8/b;->e:Z

    .line 56
    .line 57
    if-nez v2, :cond_3

    .line 58
    .line 59
    iget-object v2, p0, La8/b;->f:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v2, Lcm/a;

    .line 62
    .line 63
    iget-object v2, v2, Lcm/a;->g:La8/b;

    .line 64
    .line 65
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    if-eqz v2, :cond_2

    .line 70
    .line 71
    invoke-static {v0, p0, p1}, Lcm/d;->a(Lcm/d;La8/b;Z)V

    .line 72
    .line 73
    .line 74
    goto :goto_2

    .line 75
    :catchall_1
    move-exception p0

    .line 76
    goto :goto_3

    .line 77
    :cond_2
    :goto_2
    const/4 p1, 0x1

    .line 78
    iput-boolean p1, p0, La8/b;->e:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 79
    .line 80
    monitor-exit v1

    .line 81
    return-void

    .line 82
    :cond_3
    :try_start_3
    const-string p0, "editor is closed"

    .line 83
    .line 84
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 85
    .line 86
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 90
    :goto_3
    monitor-exit v1

    .line 91
    throw p0

    .line 92
    nop

    .line 93
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public g()V
    .locals 3

    .line 1
    iget-object v0, p0, La8/b;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lf01/c;

    .line 4
    .line 5
    iget-object v1, v0, Lf01/c;->g:La8/b;

    .line 6
    .line 7
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    iget-object v1, p0, La8/b;->h:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v1, Lf01/g;

    .line 16
    .line 17
    iget-boolean v2, v1, Lf01/g;->o:Z

    .line 18
    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x0

    .line 22
    invoke-virtual {v1, p0, v0}, Lf01/g;->b(La8/b;Z)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :cond_0
    const/4 p0, 0x1

    .line 27
    iput-boolean p0, v0, Lf01/c;->f:Z

    .line 28
    .line 29
    :cond_1
    return-void
.end method

.method public h(I)Lu01/y;
    .locals 4

    .line 1
    iget v0, p0, La8/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lll/d;

    .line 9
    .line 10
    monitor-enter v0

    .line 11
    :try_start_0
    iget-boolean v1, p0, La8/b;->e:Z

    .line 12
    .line 13
    if-nez v1, :cond_1

    .line 14
    .line 15
    iget-object v1, p0, La8/b;->g:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, [Z

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    aput-boolean v2, v1, p1

    .line 21
    .line 22
    iget-object p0, p0, La8/b;->f:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Lll/a;

    .line 25
    .line 26
    iget-object p0, p0, Lll/a;->d:Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    iget-object p1, v0, Lll/d;->s:Lll/c;

    .line 33
    .line 34
    move-object v1, p0

    .line 35
    check-cast v1, Lu01/y;

    .line 36
    .line 37
    invoke-virtual {p1, v1}, Lu01/k;->j(Lu01/y;)Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-nez v2, :cond_0

    .line 42
    .line 43
    const/4 v2, 0x0

    .line 44
    invoke-virtual {p1, v1, v2}, Lll/c;->E(Lu01/y;Z)Lu01/f0;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-static {p1}, Lxl/c;->a(Ljava/io/Closeable;)V

    .line 49
    .line 50
    .line 51
    :cond_0
    check-cast p0, Lu01/y;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 52
    .line 53
    monitor-exit v0

    .line 54
    return-object p0

    .line 55
    :catchall_0
    move-exception p0

    .line 56
    goto :goto_0

    .line 57
    :cond_1
    :try_start_1
    const-string p0, "editor is closed"

    .line 58
    .line 59
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 65
    :goto_0
    monitor-exit v0

    .line 66
    throw p0

    .line 67
    :pswitch_0
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v0, Lcm/d;

    .line 70
    .line 71
    iget-object v1, v0, Lcm/d;->k:Ljava/lang/Object;

    .line 72
    .line 73
    monitor-enter v1

    .line 74
    :try_start_2
    iget-boolean v2, p0, La8/b;->e:Z

    .line 75
    .line 76
    if-nez v2, :cond_2

    .line 77
    .line 78
    iget-object v2, p0, La8/b;->g:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v2, [Z

    .line 81
    .line 82
    const/4 v3, 0x1

    .line 83
    aput-boolean v3, v2, p1

    .line 84
    .line 85
    iget-object p0, p0, La8/b;->f:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast p0, Lcm/a;

    .line 88
    .line 89
    iget-object p0, p0, Lcm/a;->d:Ljava/util/ArrayList;

    .line 90
    .line 91
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    iget-object p1, v0, Lcm/d;->t:Lcm/c;

    .line 96
    .line 97
    move-object v0, p0

    .line 98
    check-cast v0, Lu01/y;

    .line 99
    .line 100
    invoke-static {p1, v0}, Lkp/h8;->a(Lu01/k;Lu01/y;)V

    .line 101
    .line 102
    .line 103
    check-cast p0, Lu01/y;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 104
    .line 105
    monitor-exit v1

    .line 106
    return-object p0

    .line 107
    :catchall_1
    move-exception p0

    .line 108
    goto :goto_1

    .line 109
    :cond_2
    :try_start_3
    const-string p0, "editor is closed"

    .line 110
    .line 111
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 112
    .line 113
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 117
    :goto_1
    monitor-exit v1

    .line 118
    throw p0

    .line 119
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public declared-synchronized i()V
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, La8/b;->e:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    return-void

    .line 8
    :cond_0
    :try_start_1
    invoke-virtual {p0}, La8/b;->o()Ljava/lang/Boolean;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, La8/b;->g:Ljava/lang/Object;

    .line 13
    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    new-instance v0, Lc1/y;

    .line 17
    .line 18
    const/4 v1, 0x4

    .line 19
    invoke-direct {v0, v1}, Lc1/y;-><init>(I)V

    .line 20
    .line 21
    .line 22
    iget-object v1, p0, La8/b;->f:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v1, Ldt/c;

    .line 25
    .line 26
    check-cast v1, Lgs/m;

    .line 27
    .line 28
    iget-object v2, v1, Lgs/m;->c:Ljava/util/concurrent/Executor;

    .line 29
    .line 30
    invoke-virtual {v1, v2, v0}, Lgs/m;->a(Ljava/util/concurrent/Executor;Ldt/a;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :catchall_0
    move-exception v0

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    :goto_0
    const/4 v0, 0x1

    .line 37
    iput-boolean v0, p0, La8/b;->e:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 38
    .line 39
    monitor-exit p0

    .line 40
    return-void

    .line 41
    :goto_1
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 42
    throw v0
.end method

.method public j()V
    .locals 3

    .line 1
    iget v0, p0, La8/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Llp/a4;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    :try_start_0
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    const/4 v2, 0x2

    .line 17
    invoke-virtual {v0, v1, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :catch_0
    move-exception v0

    .line 22
    const-string v1, "LegacyTextDelegate"

    .line 23
    .line 24
    const-string v2, "Failed to release legacy text recognizer."

    .line 25
    .line 26
    invoke-static {v1, v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 27
    .line 28
    .line 29
    :goto_0
    const/4 v0, 0x0

    .line 30
    iput-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 31
    .line 32
    :cond_0
    return-void

    .line 33
    :pswitch_0
    iget-object v0, p0, La8/b;->f:Ljava/lang/Object;

    .line 34
    .line 35
    monitor-enter v0

    .line 36
    :try_start_1
    iget-object v1, p0, La8/b;->g:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v1, Ljava/util/ArrayDeque;

    .line 39
    .line 40
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 41
    .line 42
    .line 43
    move-result v1

    .line 44
    if-eqz v1, :cond_1

    .line 45
    .line 46
    const/4 v1, 0x0

    .line 47
    iput-boolean v1, p0, La8/b;->e:Z

    .line 48
    .line 49
    monitor-exit v0

    .line 50
    goto :goto_1

    .line 51
    :catchall_0
    move-exception p0

    .line 52
    goto :goto_2

    .line 53
    :cond_1
    iget-object v1, p0, La8/b;->g:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v1, Ljava/util/ArrayDeque;

    .line 56
    .line 57
    invoke-virtual {v1}, Ljava/util/ArrayDeque;->remove()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    check-cast v1, Lfv/r;

    .line 62
    .line 63
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 64
    iget-object v0, v1, Lfv/r;->a:Ljava/util/concurrent/Executor;

    .line 65
    .line 66
    iget-object v1, v1, Lfv/r;->b:Ljava/lang/Runnable;

    .line 67
    .line 68
    invoke-virtual {p0, v0, v1}, La8/b;->v(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 69
    .line 70
    .line 71
    :goto_1
    return-void

    .line 72
    :goto_2
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 73
    throw p0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x4
        :pswitch_0
    .end packed-switch
.end method

.method public declared-synchronized k()Z
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    invoke-virtual {p0}, La8/b;->i()V

    .line 3
    .line 4
    .line 5
    iget-object v0, p0, La8/b;->g:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Ljava/lang/Boolean;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception v0

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v0, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 21
    .line 22
    iget-object v0, v0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Lsr/f;

    .line 23
    .line 24
    invoke-virtual {v0}, Lsr/f;->h()Z

    .line 25
    .line 26
    .line 27
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    :goto_0
    monitor-exit p0

    .line 29
    return v0

    .line 30
    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 31
    throw v0
.end method

.method public l()V
    .locals 5

    .line 1
    iget-object v0, p0, La8/b;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/content/Context;

    .line 4
    .line 5
    iget-object v1, p0, La8/b;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Llp/a4;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    goto :goto_1

    .line 12
    :cond_0
    :try_start_0
    sget-object v1, Lzo/d;->b:Lrb0/a;

    .line 13
    .line 14
    const-string v2, "com.google.android.gms.vision.dynamite"

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, Lzo/d;->c(Landroid/content/Context;Lzo/c;Ljava/lang/String;)Lzo/d;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    const-string v2, "com.google.android.gms.vision.text.ChimeraNativeTextRecognizerCreator"

    .line 21
    .line 22
    invoke-virtual {v1, v2}, Lzo/d;->b(Ljava/lang/String;)Landroid/os/IBinder;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    sget v2, Llp/c6;->d:I

    .line 27
    .line 28
    const-string v2, "com.google.android.gms.vision.text.internal.client.INativeTextRecognizerCreator"

    .line 29
    .line 30
    if-nez v1, :cond_1

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    goto :goto_0

    .line 34
    :cond_1
    invoke-interface {v1, v2}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    instance-of v4, v3, Llp/d7;

    .line 39
    .line 40
    if-eqz v4, :cond_2

    .line 41
    .line 42
    move-object v1, v3

    .line 43
    check-cast v1, Llp/d7;

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    new-instance v3, Llp/b5;

    .line 47
    .line 48
    const/4 v4, 0x7

    .line 49
    invoke-direct {v3, v1, v2, v4}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 50
    .line 51
    .line 52
    move-object v1, v3

    .line 53
    :goto_0
    new-instance v2, Lyo/b;

    .line 54
    .line 55
    invoke-direct {v2, v0}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iget-object v3, p0, La8/b;->g:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v3, Llp/xb;

    .line 61
    .line 62
    check-cast v1, Llp/b5;

    .line 63
    .line 64
    invoke-virtual {v1, v2, v3}, Llp/b5;->W(Lyo/b;Llp/xb;)Llp/a4;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    iput-object v1, p0, La8/b;->h:Ljava/lang/Object;

    .line 69
    .line 70
    if-nez v1, :cond_3

    .line 71
    .line 72
    iget-boolean v1, p0, La8/b;->e:Z

    .line 73
    .line 74
    if-nez v1, :cond_3

    .line 75
    .line 76
    const-string v1, "LegacyTextDelegate"

    .line 77
    .line 78
    const-string v2, "Request OCR optional module download."

    .line 79
    .line 80
    invoke-static {v1, v2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 81
    .line 82
    .line 83
    const-string v1, "ocr"

    .line 84
    .line 85
    sget-object v2, Lfv/h;->a:[Ljo/d;

    .line 86
    .line 87
    sget-object v2, Lip/d;->e:Lip/b;

    .line 88
    .line 89
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    const/4 v2, 0x1

    .line 94
    invoke-static {v2, v1}, Llp/ta;->a(I[Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    new-instance v3, Lip/g;

    .line 98
    .line 99
    invoke-direct {v3, v1, v2}, Lip/g;-><init>([Ljava/lang/Object;I)V

    .line 100
    .line 101
    .line 102
    invoke-static {v0, v3}, Lfv/h;->a(Landroid/content/Context;Ljava/util/List;)V

    .line 103
    .line 104
    .line 105
    iput-boolean v2, p0, La8/b;->e:Z
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Lzo/a; {:try_start_0 .. :try_end_0} :catch_0

    .line 106
    .line 107
    :cond_3
    :goto_1
    return-void

    .line 108
    :catch_0
    move-exception p0

    .line 109
    new-instance v0, Lbv/a;

    .line 110
    .line 111
    const-string v1, "Failed to load deprecated vision dynamite module."

    .line 112
    .line 113
    invoke-direct {v0, v1, p0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 114
    .line 115
    .line 116
    throw v0

    .line 117
    :catch_1
    move-exception p0

    .line 118
    new-instance v0, Lbv/a;

    .line 119
    .line 120
    const-string v1, "Failed to create legacy text recognizer."

    .line 121
    .line 122
    invoke-direct {v0, v1, p0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 123
    .line 124
    .line 125
    throw v0
.end method

.method public m()V
    .locals 3

    .line 1
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/util/SparseArray;

    .line 4
    .line 5
    iget-object v1, p0, La8/b;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lo8/q;

    .line 8
    .line 9
    invoke-interface {v1}, Lo8/q;->m()V

    .line 10
    .line 11
    .line 12
    iget-boolean p0, p0, La8/b;->e:Z

    .line 13
    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    :goto_0
    invoke-virtual {v0}, Landroid/util/SparseArray;->size()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-ge p0, v1, :cond_0

    .line 22
    .line 23
    invoke-virtual {v0, p0}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, Ll9/k;

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    iput-boolean v2, v1, Ll9/k;->i:Z

    .line 31
    .line 32
    add-int/lit8 p0, p0, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    return-void
.end method

.method public n(I)Lu01/f0;
    .locals 4

    .line 1
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lf01/g;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    iget-boolean v1, p0, La8/b;->e:Z

    .line 7
    .line 8
    if-nez v1, :cond_2

    .line 9
    .line 10
    iget-object v1, p0, La8/b;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lf01/c;

    .line 13
    .line 14
    iget-object v1, v1, Lf01/c;->g:La8/b;

    .line 15
    .line 16
    invoke-static {v1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-nez v1, :cond_0

    .line 21
    .line 22
    new-instance p0, Lu01/e;

    .line 23
    .line 24
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    .line 26
    .line 27
    monitor-exit v0

    .line 28
    return-object p0

    .line 29
    :cond_0
    :try_start_1
    iget-object v1, p0, La8/b;->f:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v1, Lf01/c;

    .line 32
    .line 33
    iget-boolean v1, v1, Lf01/c;->e:Z

    .line 34
    .line 35
    if-nez v1, :cond_1

    .line 36
    .line 37
    iget-object v1, p0, La8/b;->g:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v1, [Z

    .line 40
    .line 41
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    const/4 v2, 0x1

    .line 45
    aput-boolean v2, v1, p1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :catchall_0
    move-exception p0

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    :goto_0
    iget-object v1, p0, La8/b;->f:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v1, Lf01/c;

    .line 53
    .line 54
    iget-object v1, v1, Lf01/c;->d:Ljava/util/ArrayList;

    .line 55
    .line 56
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    check-cast p1, Lu01/y;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 61
    .line 62
    :try_start_2
    iget-object v1, v0, Lf01/g;->e:Lf01/f;

    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    const-string v2, "file"

    .line 68
    .line 69
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    const/4 v2, 0x0

    .line 73
    invoke-virtual {v1, p1, v2}, Lf01/f;->E(Lu01/y;Z)Lu01/f0;

    .line 74
    .line 75
    .line 76
    move-result-object p1
    :try_end_2
    .catch Ljava/io/FileNotFoundException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 77
    :try_start_3
    new-instance v1, Lf01/h;

    .line 78
    .line 79
    new-instance v2, Let/g;

    .line 80
    .line 81
    const/4 v3, 0x1

    .line 82
    invoke-direct {v2, v3, v0, p0}, Let/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    invoke-direct {v1, p1, v2}, Lf01/h;-><init>(Lu01/f0;Lay0/k;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 86
    .line 87
    .line 88
    monitor-exit v0

    .line 89
    return-object v1

    .line 90
    :catch_0
    :try_start_4
    new-instance p0, Lu01/e;

    .line 91
    .line 92
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 93
    .line 94
    .line 95
    monitor-exit v0

    .line 96
    return-object p0

    .line 97
    :cond_2
    :try_start_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 98
    .line 99
    const-string p1, "Check failed."

    .line 100
    .line 101
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 105
    :goto_1
    monitor-exit v0

    .line 106
    throw p0
.end method

.method public o()Ljava/lang/Boolean;
    .locals 5

    .line 1
    const-string v0, "firebase_messaging_auto_init_enabled"

    .line 2
    .line 3
    iget-object p0, p0, La8/b;->h:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 6
    .line 7
    iget-object p0, p0, Lcom/google/firebase/messaging/FirebaseMessaging;->a:Lsr/f;

    .line 8
    .line 9
    invoke-virtual {p0}, Lsr/f;->a()V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lsr/f;->a:Landroid/content/Context;

    .line 13
    .line 14
    const-string v1, "com.google.firebase.messaging"

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    invoke-virtual {p0, v1, v2}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const-string v3, "auto_init"

    .line 22
    .line 23
    invoke-interface {v1, v3}, Landroid/content/SharedPreferences;->contains(Ljava/lang/String;)Z

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    if-eqz v4, :cond_0

    .line 28
    .line 29
    invoke-interface {v1, v3, v2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0

    .line 38
    :cond_0
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    if-eqz v1, :cond_1

    .line 43
    .line 44
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    const/16 v2, 0x80

    .line 49
    .line 50
    invoke-virtual {v1, p0, v2}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    if-eqz p0, :cond_1

    .line 55
    .line 56
    iget-object v1, p0, Landroid/content/pm/ApplicationInfo;->metaData:Landroid/os/Bundle;

    .line 57
    .line 58
    if-eqz v1, :cond_1

    .line 59
    .line 60
    invoke-virtual {v1, v0}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_1

    .line 65
    .line 66
    iget-object p0, p0, Landroid/content/pm/ApplicationInfo;->metaData:Landroid/os/Bundle;

    .line 67
    .line 68
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;)Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 73
    .line 74
    .line 75
    move-result-object p0
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 76
    return-object p0

    .line 77
    :catch_0
    :cond_1
    const/4 p0, 0x0

    .line 78
    return-object p0
.end method

.method public p()V
    .locals 3

    .line 1
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lw7/t;

    .line 4
    .line 5
    iget-boolean v1, p0, La8/b;->e:Z

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    new-instance v1, La0/d;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v1, p0, v2}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, v1}, Lw7/t;->c(Ljava/lang/Runnable;)Z

    .line 17
    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    iput-boolean v0, p0, La8/b;->e:Z

    .line 21
    .line 22
    return-void
.end method

.method public q(II)Lo8/i0;
    .locals 3

    .line 1
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/util/SparseArray;

    .line 4
    .line 5
    iget-object v1, p0, La8/b;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Lo8/q;

    .line 8
    .line 9
    const/4 v2, 0x3

    .line 10
    if-eq p2, v2, :cond_0

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    iput-boolean v0, p0, La8/b;->e:Z

    .line 14
    .line 15
    invoke-interface {v1, p1, p2}, Lo8/q;->q(II)Lo8/i0;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0

    .line 20
    :cond_0
    invoke-virtual {v0, p1}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    check-cast v2, Ll9/k;

    .line 25
    .line 26
    if-eqz v2, :cond_1

    .line 27
    .line 28
    return-object v2

    .line 29
    :cond_1
    new-instance v2, Ll9/k;

    .line 30
    .line 31
    invoke-interface {v1, p1, p2}, Lo8/q;->q(II)Lo8/i0;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    iget-object p0, p0, La8/b;->g:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Ll9/h;

    .line 38
    .line 39
    invoke-direct {v2, p2, p0}, Ll9/k;-><init>(Lo8/i0;Ll9/h;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0, p1, v2}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-object v2
.end method

.method public r(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, La8/b;->f:Ljava/lang/Object;

    .line 3
    .line 4
    check-cast v0, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 5
    .line 6
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Los/e;

    .line 11
    .line 12
    invoke-virtual {v0, p1, p2}, Los/e;->b(Ljava/lang/String;Ljava/lang/String;)Z

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    if-nez p1, :cond_0

    .line 17
    .line 18
    const/4 p1, 0x0

    .line 19
    monitor-exit p0

    .line 20
    return p1

    .line 21
    :catchall_0
    move-exception p1

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    iget-object p1, p0, La8/b;->f:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p1, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 26
    .line 27
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    check-cast p2, Los/e;

    .line 32
    .line 33
    const/4 v0, 0x1

    .line 34
    invoke-virtual {p1, p2, v0}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->set(Ljava/lang/Object;Z)V

    .line 35
    .line 36
    .line 37
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    new-instance p1, Lm8/o;

    .line 39
    .line 40
    const/4 p2, 0x4

    .line 41
    invoke-direct {p1, p0, p2}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 42
    .line 43
    .line 44
    iget-object p2, p0, La8/b;->g:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p2, Ljava/util/concurrent/atomic/AtomicReference;

    .line 47
    .line 48
    :cond_1
    const/4 v1, 0x0

    .line 49
    invoke-virtual {p2, v1, p1}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-eqz v1, :cond_2

    .line 54
    .line 55
    iget-object p0, p0, La8/b;->h:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p0, Lss/b;

    .line 58
    .line 59
    iget-object p0, p0, Lss/b;->g:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p0, Lns/d;

    .line 62
    .line 63
    iget-object p0, p0, Lns/d;->b:Lns/b;

    .line 64
    .line 65
    invoke-virtual {p0, p1}, Lns/b;->a(Ljava/lang/Runnable;)Laq/t;

    .line 66
    .line 67
    .line 68
    return v0

    .line 69
    :cond_2
    invoke-virtual {p2}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    if-eqz v1, :cond_1

    .line 74
    .line 75
    return v0

    .line 76
    :goto_0
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 77
    throw p1
.end method

.method public s(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V
    .locals 2

    .line 1
    iget-object v0, p0, La8/b;->f:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-boolean v1, p0, La8/b;->e:Z

    .line 5
    .line 6
    if-eqz v1, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, La8/b;->g:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Ljava/util/ArrayDeque;

    .line 11
    .line 12
    new-instance v1, Lfv/r;

    .line 13
    .line 14
    invoke-direct {v1, p1, p2}, Lfv/r;-><init>(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, v1}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    monitor-exit v0

    .line 21
    return-void

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 v1, 0x1

    .line 25
    iput-boolean v1, p0, La8/b;->e:Z

    .line 26
    .line 27
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    invoke-virtual {p0, p1, p2}, La8/b;->v(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :goto_0
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 33
    throw p0
.end method

.method public t()Ljava/lang/String;
    .locals 3

    .line 1
    iget-boolean v0, p0, La8/b;->e:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, La8/b;->e:Z

    .line 7
    .line 8
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lvp/w0;

    .line 11
    .line 12
    iget-object v1, p0, La8/b;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Ljava/lang/String;

    .line 15
    .line 16
    invoke-virtual {v0}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const/4 v2, 0x0

    .line 21
    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iput-object v0, p0, La8/b;->g:Ljava/lang/Object;

    .line 26
    .line 27
    :cond_0
    iget-object p0, p0, La8/b;->g:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Ljava/lang/String;

    .line 30
    .line 31
    return-object p0
.end method

.method public u(Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-object v0, p0, La8/b;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvp/w0;

    .line 4
    .line 5
    invoke-virtual {v0}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object v1, p0, La8/b;->f:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v1, Ljava/lang/String;

    .line 16
    .line 17
    invoke-interface {v0, v1, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 18
    .line 19
    .line 20
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, La8/b;->g:Ljava/lang/Object;

    .line 24
    .line 25
    return-void
.end method

.method public v(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V
    .locals 2

    .line 1
    new-instance v0, Lk0/g;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1, p0, p2}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    :try_start_0
    invoke-interface {p1, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/util/concurrent/RejectedExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :catch_0
    invoke-virtual {p0}, La8/b;->j()V

    .line 12
    .line 13
    .line 14
    return-void
.end method
