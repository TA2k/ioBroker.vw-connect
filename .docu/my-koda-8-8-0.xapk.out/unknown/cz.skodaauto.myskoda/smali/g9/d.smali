.class public final Lg9/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/o;


# static fields
.field public static final f0:[B

.field public static final g0:[B

.field public static final h0:[B

.field public static final i0:[B

.field public static final j0:Ljava/util/UUID;

.field public static final k0:Ljava/util/Map;


# instance fields
.field public A:J

.field public B:Z

.field public C:J

.field public D:J

.field public E:J

.field public F:Lq3/b;

.field public G:Lq3/b;

.field public H:Z

.field public I:Z

.field public J:I

.field public K:J

.field public L:J

.field public M:I

.field public N:I

.field public O:[I

.field public P:I

.field public Q:I

.field public R:I

.field public S:I

.field public T:Z

.field public U:J

.field public V:I

.field public W:I

.field public X:I

.field public Y:Z

.field public Z:Z

.field public final a:Lg9/b;

.field public a0:Z

.field public final b:Lg9/e;

.field public b0:I

.field public final c:Landroid/util/SparseArray;

.field public c0:B

.field public final d:Z

.field public d0:Z

.field public final e:Z

.field public e0:Lo8/q;

.field public final f:Ll9/h;

.field public final g:Lw7/p;

.field public final h:Lw7/p;

.field public final i:Lw7/p;

.field public final j:Lw7/p;

.field public final k:Lw7/p;

.field public final l:Lw7/p;

.field public final m:Lw7/p;

.field public final n:Lw7/p;

.field public final o:Lw7/p;

.field public final p:Lw7/p;

.field public q:Ljava/nio/ByteBuffer;

.field public r:J

.field public s:J

.field public t:J

.field public u:J

.field public v:J

.field public w:Z

.field public x:Lg9/c;

.field public y:Z

.field public z:I


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    new-array v1, v0, [B

    .line 4
    .line 5
    fill-array-data v1, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v1, Lg9/d;->f0:[B

    .line 9
    .line 10
    sget-object v1, Lw7/w;->a:Ljava/lang/String;

    .line 11
    .line 12
    sget-object v1, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 13
    .line 14
    const-string v2, "Format: Start, End, ReadOrder, Layer, Style, Name, MarginL, MarginR, MarginV, Effect, Text"

    .line 15
    .line 16
    invoke-virtual {v2, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    sput-object v1, Lg9/d;->g0:[B

    .line 21
    .line 22
    new-array v0, v0, [B

    .line 23
    .line 24
    fill-array-data v0, :array_1

    .line 25
    .line 26
    .line 27
    sput-object v0, Lg9/d;->h0:[B

    .line 28
    .line 29
    const/16 v0, 0x26

    .line 30
    .line 31
    new-array v0, v0, [B

    .line 32
    .line 33
    fill-array-data v0, :array_2

    .line 34
    .line 35
    .line 36
    sput-object v0, Lg9/d;->i0:[B

    .line 37
    .line 38
    new-instance v0, Ljava/util/UUID;

    .line 39
    .line 40
    const-wide v1, 0x100000000001000L

    .line 41
    .line 42
    .line 43
    .line 44
    .line 45
    const-wide v3, -0x7fffff55ffc7648fL    # -3.607411173533E-312

    .line 46
    .line 47
    .line 48
    .line 49
    .line 50
    invoke-direct {v0, v1, v2, v3, v4}, Ljava/util/UUID;-><init>(JJ)V

    .line 51
    .line 52
    .line 53
    sput-object v0, Lg9/d;->j0:Ljava/util/UUID;

    .line 54
    .line 55
    new-instance v0, Ljava/util/HashMap;

    .line 56
    .line 57
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 58
    .line 59
    .line 60
    const-string v1, "htc_video_rotA-090"

    .line 61
    .line 62
    const/16 v2, 0x5a

    .line 63
    .line 64
    const/4 v3, 0x0

    .line 65
    const-string v4, "htc_video_rotA-000"

    .line 66
    .line 67
    invoke-static {v3, v0, v4, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->w(ILjava/util/HashMap;Ljava/lang/String;ILjava/lang/String;)V

    .line 68
    .line 69
    .line 70
    const-string v1, "htc_video_rotA-270"

    .line 71
    .line 72
    const/16 v2, 0x10e

    .line 73
    .line 74
    const/16 v3, 0xb4

    .line 75
    .line 76
    const-string v4, "htc_video_rotA-180"

    .line 77
    .line 78
    invoke-static {v3, v0, v4, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->w(ILjava/util/HashMap;Ljava/lang/String;ILjava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    sput-object v0, Lg9/d;->k0:Ljava/util/Map;

    .line 86
    .line 87
    return-void

    .line 88
    nop

    .line 89
    :array_0
    .array-data 1
        0x31t
        0xat
        0x30t
        0x30t
        0x3at
        0x30t
        0x30t
        0x3at
        0x30t
        0x30t
        0x2ct
        0x30t
        0x30t
        0x30t
        0x20t
        0x2dt
        0x2dt
        0x3et
        0x20t
        0x30t
        0x30t
        0x3at
        0x30t
        0x30t
        0x3at
        0x30t
        0x30t
        0x2ct
        0x30t
        0x30t
        0x30t
        0xat
    .end array-data

    .line 90
    .line 91
    .line 92
    .line 93
    .line 94
    .line 95
    .line 96
    .line 97
    .line 98
    .line 99
    .line 100
    .line 101
    .line 102
    .line 103
    .line 104
    .line 105
    .line 106
    .line 107
    .line 108
    .line 109
    :array_1
    .array-data 1
        0x44t
        0x69t
        0x61t
        0x6ct
        0x6ft
        0x67t
        0x75t
        0x65t
        0x3at
        0x20t
        0x30t
        0x3at
        0x30t
        0x30t
        0x3at
        0x30t
        0x30t
        0x3at
        0x30t
        0x30t
        0x2ct
        0x30t
        0x3at
        0x30t
        0x30t
        0x3at
        0x30t
        0x30t
        0x3at
        0x30t
        0x30t
        0x2ct
    .end array-data

    .line 110
    .line 111
    .line 112
    .line 113
    .line 114
    .line 115
    .line 116
    .line 117
    .line 118
    .line 119
    .line 120
    .line 121
    .line 122
    .line 123
    .line 124
    .line 125
    .line 126
    .line 127
    .line 128
    .line 129
    :array_2
    .array-data 1
        0x57t
        0x45t
        0x42t
        0x56t
        0x54t
        0x54t
        0xat
        0xat
        0x30t
        0x30t
        0x3at
        0x30t
        0x30t
        0x3at
        0x30t
        0x30t
        0x2et
        0x30t
        0x30t
        0x30t
        0x20t
        0x2dt
        0x2dt
        0x3et
        0x20t
        0x30t
        0x30t
        0x3at
        0x30t
        0x30t
        0x3at
        0x30t
        0x30t
        0x2et
        0x30t
        0x30t
        0x30t
        0xat
    .end array-data
.end method

.method public constructor <init>(Ll9/h;I)V
    .locals 5

    .line 1
    new-instance v0, Lg9/b;

    .line 2
    .line 3
    invoke-direct {v0}, Lg9/b;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    const-wide/16 v1, -0x1

    .line 10
    .line 11
    iput-wide v1, p0, Lg9/d;->s:J

    .line 12
    .line 13
    const-wide v3, -0x7fffffffffffffffL    # -4.9E-324

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    iput-wide v3, p0, Lg9/d;->t:J

    .line 19
    .line 20
    iput-wide v3, p0, Lg9/d;->u:J

    .line 21
    .line 22
    iput-wide v3, p0, Lg9/d;->v:J

    .line 23
    .line 24
    iput-wide v1, p0, Lg9/d;->C:J

    .line 25
    .line 26
    iput-wide v1, p0, Lg9/d;->D:J

    .line 27
    .line 28
    iput-wide v3, p0, Lg9/d;->E:J

    .line 29
    .line 30
    iput-object v0, p0, Lg9/d;->a:Lg9/b;

    .line 31
    .line 32
    new-instance v1, La0/j;

    .line 33
    .line 34
    const/16 v2, 0x15

    .line 35
    .line 36
    invoke-direct {v1, p0, v2}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 37
    .line 38
    .line 39
    iput-object v1, v0, Lg9/b;->d:La0/j;

    .line 40
    .line 41
    iput-object p1, p0, Lg9/d;->f:Ll9/h;

    .line 42
    .line 43
    and-int/lit8 p1, p2, 0x1

    .line 44
    .line 45
    const/4 v0, 0x0

    .line 46
    const/4 v1, 0x1

    .line 47
    if-nez p1, :cond_0

    .line 48
    .line 49
    move p1, v1

    .line 50
    goto :goto_0

    .line 51
    :cond_0
    move p1, v0

    .line 52
    :goto_0
    iput-boolean p1, p0, Lg9/d;->d:Z

    .line 53
    .line 54
    and-int/lit8 p1, p2, 0x2

    .line 55
    .line 56
    if-nez p1, :cond_1

    .line 57
    .line 58
    move v0, v1

    .line 59
    :cond_1
    iput-boolean v0, p0, Lg9/d;->e:Z

    .line 60
    .line 61
    new-instance p1, Lg9/e;

    .line 62
    .line 63
    invoke-direct {p1}, Lg9/e;-><init>()V

    .line 64
    .line 65
    .line 66
    iput-object p1, p0, Lg9/d;->b:Lg9/e;

    .line 67
    .line 68
    new-instance p1, Landroid/util/SparseArray;

    .line 69
    .line 70
    invoke-direct {p1}, Landroid/util/SparseArray;-><init>()V

    .line 71
    .line 72
    .line 73
    iput-object p1, p0, Lg9/d;->c:Landroid/util/SparseArray;

    .line 74
    .line 75
    new-instance p1, Lw7/p;

    .line 76
    .line 77
    const/4 p2, 0x4

    .line 78
    invoke-direct {p1, p2}, Lw7/p;-><init>(I)V

    .line 79
    .line 80
    .line 81
    iput-object p1, p0, Lg9/d;->i:Lw7/p;

    .line 82
    .line 83
    new-instance p1, Lw7/p;

    .line 84
    .line 85
    invoke-static {p2}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    const/4 v2, -0x1

    .line 90
    invoke-virtual {v0, v2}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    invoke-direct {p1, v0}, Lw7/p;-><init>([B)V

    .line 99
    .line 100
    .line 101
    iput-object p1, p0, Lg9/d;->j:Lw7/p;

    .line 102
    .line 103
    new-instance p1, Lw7/p;

    .line 104
    .line 105
    invoke-direct {p1, p2}, Lw7/p;-><init>(I)V

    .line 106
    .line 107
    .line 108
    iput-object p1, p0, Lg9/d;->k:Lw7/p;

    .line 109
    .line 110
    new-instance p1, Lw7/p;

    .line 111
    .line 112
    sget-object v0, Lx7/n;->a:[B

    .line 113
    .line 114
    invoke-direct {p1, v0}, Lw7/p;-><init>([B)V

    .line 115
    .line 116
    .line 117
    iput-object p1, p0, Lg9/d;->g:Lw7/p;

    .line 118
    .line 119
    new-instance p1, Lw7/p;

    .line 120
    .line 121
    invoke-direct {p1, p2}, Lw7/p;-><init>(I)V

    .line 122
    .line 123
    .line 124
    iput-object p1, p0, Lg9/d;->h:Lw7/p;

    .line 125
    .line 126
    new-instance p1, Lw7/p;

    .line 127
    .line 128
    invoke-direct {p1}, Lw7/p;-><init>()V

    .line 129
    .line 130
    .line 131
    iput-object p1, p0, Lg9/d;->l:Lw7/p;

    .line 132
    .line 133
    new-instance p1, Lw7/p;

    .line 134
    .line 135
    invoke-direct {p1}, Lw7/p;-><init>()V

    .line 136
    .line 137
    .line 138
    iput-object p1, p0, Lg9/d;->m:Lw7/p;

    .line 139
    .line 140
    new-instance p1, Lw7/p;

    .line 141
    .line 142
    const/16 p2, 0x8

    .line 143
    .line 144
    invoke-direct {p1, p2}, Lw7/p;-><init>(I)V

    .line 145
    .line 146
    .line 147
    iput-object p1, p0, Lg9/d;->n:Lw7/p;

    .line 148
    .line 149
    new-instance p1, Lw7/p;

    .line 150
    .line 151
    invoke-direct {p1}, Lw7/p;-><init>()V

    .line 152
    .line 153
    .line 154
    iput-object p1, p0, Lg9/d;->o:Lw7/p;

    .line 155
    .line 156
    new-instance p1, Lw7/p;

    .line 157
    .line 158
    invoke-direct {p1}, Lw7/p;-><init>()V

    .line 159
    .line 160
    .line 161
    iput-object p1, p0, Lg9/d;->p:Lw7/p;

    .line 162
    .line 163
    new-array p1, v1, [I

    .line 164
    .line 165
    iput-object p1, p0, Lg9/d;->O:[I

    .line 166
    .line 167
    return-void
.end method

.method public static i(JLjava/lang/String;J)[B
    .locals 7

    .line 1
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    cmp-long v0, p0, v0

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v0, 0x0

    .line 13
    :goto_0
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 14
    .line 15
    .line 16
    const-wide v0, 0xd693a400L

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    div-long v2, p0, v0

    .line 22
    .line 23
    long-to-int v2, v2

    .line 24
    int-to-long v3, v2

    .line 25
    mul-long/2addr v3, v0

    .line 26
    sub-long/2addr p0, v3

    .line 27
    const-wide/32 v0, 0x3938700

    .line 28
    .line 29
    .line 30
    div-long v3, p0, v0

    .line 31
    .line 32
    long-to-int v3, v3

    .line 33
    int-to-long v4, v3

    .line 34
    mul-long/2addr v4, v0

    .line 35
    sub-long/2addr p0, v4

    .line 36
    const-wide/32 v0, 0xf4240

    .line 37
    .line 38
    .line 39
    div-long v4, p0, v0

    .line 40
    .line 41
    long-to-int v4, v4

    .line 42
    int-to-long v5, v4

    .line 43
    mul-long/2addr v5, v0

    .line 44
    sub-long/2addr p0, v5

    .line 45
    div-long/2addr p0, p3

    .line 46
    long-to-int p0, p0

    .line 47
    sget-object p1, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 48
    .line 49
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 50
    .line 51
    .line 52
    move-result-object p3

    .line 53
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object p4

    .line 57
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    filled-new-array {p3, p4, v0, p0}, [Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-static {p1, p2, p0}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    sget-object p1, Lw7/w;->a:Ljava/lang/String;

    .line 74
    .line 75
    sget-object p1, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 76
    .line 77
    invoke-virtual {p0, p1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0
.end method


# virtual methods
.method public final a(Lo8/p;)Z
    .locals 14

    .line 1
    new-instance p0, Lb11/a;

    .line 2
    .line 3
    const/4 v0, 0x3

    .line 4
    const/4 v1, 0x0

    .line 5
    invoke-direct {p0, v1, v0}, Lb11/a;-><init>(BI)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lb11/a;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lw7/p;

    .line 11
    .line 12
    check-cast p1, Lo8/l;

    .line 13
    .line 14
    iget-wide v1, p1, Lo8/l;->f:J

    .line 15
    .line 16
    const-wide/16 v3, -0x1

    .line 17
    .line 18
    cmp-long v3, v1, v3

    .line 19
    .line 20
    const-wide/16 v4, 0x400

    .line 21
    .line 22
    if-eqz v3, :cond_1

    .line 23
    .line 24
    cmp-long v6, v1, v4

    .line 25
    .line 26
    if-lez v6, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move-wide v4, v1

    .line 30
    :cond_1
    :goto_0
    long-to-int v4, v4

    .line 31
    iget-object v5, v0, Lw7/p;->a:[B

    .line 32
    .line 33
    const/4 v6, 0x0

    .line 34
    const/4 v7, 0x4

    .line 35
    invoke-virtual {p1, v5, v6, v7, v6}, Lo8/l;->b([BIIZ)Z

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Lw7/p;->y()J

    .line 39
    .line 40
    .line 41
    move-result-wide v8

    .line 42
    iput v7, p0, Lb11/a;->e:I

    .line 43
    .line 44
    :goto_1
    const-wide/32 v10, 0x1a45dfa3

    .line 45
    .line 46
    .line 47
    cmp-long v5, v8, v10

    .line 48
    .line 49
    const/4 v7, 0x1

    .line 50
    if-eqz v5, :cond_3

    .line 51
    .line 52
    iget v5, p0, Lb11/a;->e:I

    .line 53
    .line 54
    add-int/2addr v5, v7

    .line 55
    iput v5, p0, Lb11/a;->e:I

    .line 56
    .line 57
    if-ne v5, v4, :cond_2

    .line 58
    .line 59
    goto :goto_3

    .line 60
    :cond_2
    iget-object v5, v0, Lw7/p;->a:[B

    .line 61
    .line 62
    invoke-virtual {p1, v5, v6, v7, v6}, Lo8/l;->b([BIIZ)Z

    .line 63
    .line 64
    .line 65
    const/16 v5, 0x8

    .line 66
    .line 67
    shl-long v7, v8, v5

    .line 68
    .line 69
    const-wide/16 v9, -0x100

    .line 70
    .line 71
    and-long/2addr v7, v9

    .line 72
    iget-object v5, v0, Lw7/p;->a:[B

    .line 73
    .line 74
    aget-byte v5, v5, v6

    .line 75
    .line 76
    and-int/lit16 v5, v5, 0xff

    .line 77
    .line 78
    int-to-long v9, v5

    .line 79
    or-long v8, v7, v9

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_3
    invoke-virtual {p0, p1}, Lb11/a;->i(Lo8/l;)J

    .line 83
    .line 84
    .line 85
    move-result-wide v4

    .line 86
    iget v0, p0, Lb11/a;->e:I

    .line 87
    .line 88
    int-to-long v8, v0

    .line 89
    const-wide/high16 v10, -0x8000000000000000L

    .line 90
    .line 91
    cmp-long v0, v4, v10

    .line 92
    .line 93
    if-eqz v0, :cond_8

    .line 94
    .line 95
    if-eqz v3, :cond_4

    .line 96
    .line 97
    add-long v12, v8, v4

    .line 98
    .line 99
    cmp-long v0, v12, v1

    .line 100
    .line 101
    if-ltz v0, :cond_4

    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_4
    :goto_2
    iget v0, p0, Lb11/a;->e:I

    .line 105
    .line 106
    int-to-long v0, v0

    .line 107
    add-long v2, v8, v4

    .line 108
    .line 109
    cmp-long v0, v0, v2

    .line 110
    .line 111
    if-gez v0, :cond_7

    .line 112
    .line 113
    invoke-virtual {p0, p1}, Lb11/a;->i(Lo8/l;)J

    .line 114
    .line 115
    .line 116
    move-result-wide v0

    .line 117
    cmp-long v0, v0, v10

    .line 118
    .line 119
    if-nez v0, :cond_5

    .line 120
    .line 121
    goto :goto_3

    .line 122
    :cond_5
    invoke-virtual {p0, p1}, Lb11/a;->i(Lo8/l;)J

    .line 123
    .line 124
    .line 125
    move-result-wide v0

    .line 126
    const-wide/16 v2, 0x0

    .line 127
    .line 128
    cmp-long v2, v0, v2

    .line 129
    .line 130
    if-ltz v2, :cond_8

    .line 131
    .line 132
    const-wide/32 v12, 0x7fffffff

    .line 133
    .line 134
    .line 135
    cmp-long v3, v0, v12

    .line 136
    .line 137
    if-lez v3, :cond_6

    .line 138
    .line 139
    goto :goto_3

    .line 140
    :cond_6
    if-eqz v2, :cond_4

    .line 141
    .line 142
    long-to-int v0, v0

    .line 143
    invoke-virtual {p1, v0, v6}, Lo8/l;->c(IZ)Z

    .line 144
    .line 145
    .line 146
    iget v1, p0, Lb11/a;->e:I

    .line 147
    .line 148
    add-int/2addr v1, v0

    .line 149
    iput v1, p0, Lb11/a;->e:I

    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_7
    if-nez v0, :cond_8

    .line 153
    .line 154
    return v7

    .line 155
    :cond_8
    :goto_3
    return v6
.end method

.method public final b()V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Lo8/q;)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lg9/d;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    new-instance v0, La8/b;

    .line 6
    .line 7
    iget-object v1, p0, Lg9/d;->f:Ll9/h;

    .line 8
    .line 9
    invoke-direct {v0, p1, v1}, La8/b;-><init>(Lo8/q;Ll9/h;)V

    .line 10
    .line 11
    .line 12
    move-object p1, v0

    .line 13
    :cond_0
    iput-object p1, p0, Lg9/d;->e0:Lo8/q;

    .line 14
    .line 15
    return-void
.end method

.method public final d(JJ)V
    .locals 0

    .line 1
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    iput-wide p1, p0, Lg9/d;->E:J

    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    iput p1, p0, Lg9/d;->J:I

    .line 10
    .line 11
    iget-object p2, p0, Lg9/d;->a:Lg9/b;

    .line 12
    .line 13
    iput p1, p2, Lg9/b;->e:I

    .line 14
    .line 15
    iget-object p3, p2, Lg9/b;->b:Ljava/util/ArrayDeque;

    .line 16
    .line 17
    invoke-virtual {p3}, Ljava/util/ArrayDeque;->clear()V

    .line 18
    .line 19
    .line 20
    iget-object p2, p2, Lg9/b;->c:Lg9/e;

    .line 21
    .line 22
    iput p1, p2, Lg9/e;->b:I

    .line 23
    .line 24
    iput p1, p2, Lg9/e;->c:I

    .line 25
    .line 26
    iget-object p2, p0, Lg9/d;->b:Lg9/e;

    .line 27
    .line 28
    iput p1, p2, Lg9/e;->b:I

    .line 29
    .line 30
    iput p1, p2, Lg9/e;->c:I

    .line 31
    .line 32
    invoke-virtual {p0}, Lg9/d;->l()V

    .line 33
    .line 34
    .line 35
    move p2, p1

    .line 36
    :goto_0
    iget-object p3, p0, Lg9/d;->c:Landroid/util/SparseArray;

    .line 37
    .line 38
    invoke-virtual {p3}, Landroid/util/SparseArray;->size()I

    .line 39
    .line 40
    .line 41
    move-result p4

    .line 42
    if-ge p2, p4, :cond_1

    .line 43
    .line 44
    invoke-virtual {p3, p2}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p3

    .line 48
    check-cast p3, Lg9/c;

    .line 49
    .line 50
    iget-object p3, p3, Lg9/c;->V:Lo8/j0;

    .line 51
    .line 52
    if-eqz p3, :cond_0

    .line 53
    .line 54
    iput-boolean p1, p3, Lo8/j0;->b:Z

    .line 55
    .line 56
    iput p1, p3, Lo8/j0;->c:I

    .line 57
    .line 58
    :cond_0
    add-int/lit8 p2, p2, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_1
    return-void
.end method

.method public final e(I)V
    .locals 1

    .line 1
    iget-object v0, p0, Lg9/d;->F:Lq3/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lg9/d;->G:Lq3/b;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v0, "Element "

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string p1, " must be in a Cues"

    .line 21
    .line 22
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    const/4 p1, 0x0

    .line 30
    invoke-static {p1, p0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    throw p0
.end method

.method public final f(I)V
    .locals 1

    .line 1
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    const-string v0, "Element "

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    const-string p1, " must be in a TrackEntry"

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    const/4 p1, 0x0

    .line 26
    invoke-static {p1, p0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    throw p0
.end method

.method public final g(Lg9/c;JIII)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v1, Lg9/c;->V:Lo8/j0;

    .line 6
    .line 7
    const/4 v9, 0x1

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    move-object v3, v2

    .line 11
    iget-object v2, v1, Lg9/c;->Z:Lo8/i0;

    .line 12
    .line 13
    iget-object v8, v1, Lg9/c;->k:Lo8/h0;

    .line 14
    .line 15
    move/from16 v5, p4

    .line 16
    .line 17
    move/from16 v6, p5

    .line 18
    .line 19
    move/from16 v7, p6

    .line 20
    .line 21
    move-object v1, v3

    .line 22
    move-wide/from16 v3, p2

    .line 23
    .line 24
    invoke-virtual/range {v1 .. v8}, Lo8/j0;->b(Lo8/i0;JIIILo8/h0;)V

    .line 25
    .line 26
    .line 27
    goto/16 :goto_7

    .line 28
    .line 29
    :cond_0
    iget-object v2, v1, Lg9/c;->c:Ljava/lang/String;

    .line 30
    .line 31
    const-string v3, "S_TEXT/UTF8"

    .line 32
    .line 33
    invoke-virtual {v3, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    const/4 v4, 0x2

    .line 38
    const-string v5, "S_TEXT/WEBVTT"

    .line 39
    .line 40
    const-string v6, "S_TEXT/SSA"

    .line 41
    .line 42
    const-string v7, "S_TEXT/ASS"

    .line 43
    .line 44
    const/4 v8, 0x0

    .line 45
    if-nez v2, :cond_1

    .line 46
    .line 47
    iget-object v2, v1, Lg9/c;->c:Ljava/lang/String;

    .line 48
    .line 49
    invoke-virtual {v7, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    if-nez v2, :cond_1

    .line 54
    .line 55
    iget-object v2, v1, Lg9/c;->c:Ljava/lang/String;

    .line 56
    .line 57
    invoke-virtual {v6, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    if-nez v2, :cond_1

    .line 62
    .line 63
    iget-object v2, v1, Lg9/c;->c:Ljava/lang/String;

    .line 64
    .line 65
    invoke-virtual {v5, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    if-eqz v2, :cond_3

    .line 70
    .line 71
    :cond_1
    iget v2, v0, Lg9/d;->N:I

    .line 72
    .line 73
    const-string v10, "MatroskaExtractor"

    .line 74
    .line 75
    if-le v2, v9, :cond_2

    .line 76
    .line 77
    const-string v2, "Skipping subtitle sample in laced block."

    .line 78
    .line 79
    invoke-static {v10, v2}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_2
    iget-wide v11, v0, Lg9/d;->L:J

    .line 84
    .line 85
    const-wide v13, -0x7fffffffffffffffL    # -4.9E-324

    .line 86
    .line 87
    .line 88
    .line 89
    .line 90
    cmp-long v2, v11, v13

    .line 91
    .line 92
    if-nez v2, :cond_4

    .line 93
    .line 94
    const-string v2, "Skipping subtitle sample with no duration."

    .line 95
    .line 96
    invoke-static {v10, v2}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    :cond_3
    :goto_0
    move/from16 v2, p5

    .line 100
    .line 101
    goto/16 :goto_5

    .line 102
    .line 103
    :cond_4
    iget-object v2, v1, Lg9/c;->c:Ljava/lang/String;

    .line 104
    .line 105
    iget-object v10, v0, Lg9/d;->m:Lw7/p;

    .line 106
    .line 107
    iget-object v13, v10, Lw7/p;->a:[B

    .line 108
    .line 109
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 110
    .line 111
    .line 112
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 113
    .line 114
    .line 115
    move-result v14

    .line 116
    const/4 v15, -0x1

    .line 117
    sparse-switch v14, :sswitch_data_0

    .line 118
    .line 119
    .line 120
    goto :goto_1

    .line 121
    :sswitch_0
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v2

    .line 125
    if-nez v2, :cond_5

    .line 126
    .line 127
    goto :goto_1

    .line 128
    :cond_5
    const/4 v15, 0x3

    .line 129
    goto :goto_1

    .line 130
    :sswitch_1
    invoke-virtual {v2, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v2

    .line 134
    if-nez v2, :cond_6

    .line 135
    .line 136
    goto :goto_1

    .line 137
    :cond_6
    move v15, v4

    .line 138
    goto :goto_1

    .line 139
    :sswitch_2
    invoke-virtual {v2, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v2

    .line 143
    if-nez v2, :cond_7

    .line 144
    .line 145
    goto :goto_1

    .line 146
    :cond_7
    move v15, v9

    .line 147
    goto :goto_1

    .line 148
    :sswitch_3
    invoke-virtual {v2, v7}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v2

    .line 152
    if-nez v2, :cond_8

    .line 153
    .line 154
    goto :goto_1

    .line 155
    :cond_8
    move v15, v8

    .line 156
    :goto_1
    const-wide/16 v2, 0x3e8

    .line 157
    .line 158
    packed-switch v15, :pswitch_data_0

    .line 159
    .line 160
    .line 161
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 162
    .line 163
    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 164
    .line 165
    .line 166
    throw v0

    .line 167
    :pswitch_0
    const-string v5, "%02d:%02d:%02d,%03d"

    .line 168
    .line 169
    invoke-static {v11, v12, v5, v2, v3}, Lg9/d;->i(JLjava/lang/String;J)[B

    .line 170
    .line 171
    .line 172
    move-result-object v2

    .line 173
    const/16 v3, 0x13

    .line 174
    .line 175
    goto :goto_2

    .line 176
    :pswitch_1
    const-string v5, "%02d:%02d:%02d.%03d"

    .line 177
    .line 178
    invoke-static {v11, v12, v5, v2, v3}, Lg9/d;->i(JLjava/lang/String;J)[B

    .line 179
    .line 180
    .line 181
    move-result-object v2

    .line 182
    const/16 v3, 0x19

    .line 183
    .line 184
    goto :goto_2

    .line 185
    :pswitch_2
    const-string v2, "%01d:%02d:%02d:%02d"

    .line 186
    .line 187
    const-wide/16 v5, 0x2710

    .line 188
    .line 189
    invoke-static {v11, v12, v2, v5, v6}, Lg9/d;->i(JLjava/lang/String;J)[B

    .line 190
    .line 191
    .line 192
    move-result-object v2

    .line 193
    const/16 v3, 0x15

    .line 194
    .line 195
    :goto_2
    array-length v5, v2

    .line 196
    invoke-static {v2, v8, v13, v3, v5}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 197
    .line 198
    .line 199
    iget v2, v10, Lw7/p;->b:I

    .line 200
    .line 201
    :goto_3
    iget v3, v10, Lw7/p;->c:I

    .line 202
    .line 203
    if-ge v2, v3, :cond_a

    .line 204
    .line 205
    iget-object v3, v10, Lw7/p;->a:[B

    .line 206
    .line 207
    aget-byte v3, v3, v2

    .line 208
    .line 209
    if-nez v3, :cond_9

    .line 210
    .line 211
    invoke-virtual {v10, v2}, Lw7/p;->H(I)V

    .line 212
    .line 213
    .line 214
    goto :goto_4

    .line 215
    :cond_9
    add-int/lit8 v2, v2, 0x1

    .line 216
    .line 217
    goto :goto_3

    .line 218
    :cond_a
    :goto_4
    iget-object v2, v1, Lg9/c;->Z:Lo8/i0;

    .line 219
    .line 220
    iget v3, v10, Lw7/p;->c:I

    .line 221
    .line 222
    invoke-interface {v2, v10, v3, v8}, Lo8/i0;->a(Lw7/p;II)V

    .line 223
    .line 224
    .line 225
    iget v2, v10, Lw7/p;->c:I

    .line 226
    .line 227
    add-int v2, p5, v2

    .line 228
    .line 229
    :goto_5
    const/high16 v3, 0x10000000

    .line 230
    .line 231
    and-int v3, p4, v3

    .line 232
    .line 233
    if-eqz v3, :cond_c

    .line 234
    .line 235
    iget v3, v0, Lg9/d;->N:I

    .line 236
    .line 237
    iget-object v5, v0, Lg9/d;->p:Lw7/p;

    .line 238
    .line 239
    if-le v3, v9, :cond_b

    .line 240
    .line 241
    invoke-virtual {v5, v8}, Lw7/p;->F(I)V

    .line 242
    .line 243
    .line 244
    goto :goto_6

    .line 245
    :cond_b
    iget v3, v5, Lw7/p;->c:I

    .line 246
    .line 247
    iget-object v6, v1, Lg9/c;->Z:Lo8/i0;

    .line 248
    .line 249
    invoke-interface {v6, v5, v3, v4}, Lo8/i0;->a(Lw7/p;II)V

    .line 250
    .line 251
    .line 252
    add-int/2addr v2, v3

    .line 253
    :cond_c
    :goto_6
    move v14, v2

    .line 254
    iget-object v10, v1, Lg9/c;->Z:Lo8/i0;

    .line 255
    .line 256
    iget-object v1, v1, Lg9/c;->k:Lo8/h0;

    .line 257
    .line 258
    move-wide/from16 v11, p2

    .line 259
    .line 260
    move/from16 v13, p4

    .line 261
    .line 262
    move/from16 v15, p6

    .line 263
    .line 264
    move-object/from16 v16, v1

    .line 265
    .line 266
    invoke-interface/range {v10 .. v16}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 267
    .line 268
    .line 269
    :goto_7
    iput-boolean v9, v0, Lg9/d;->I:Z

    .line 270
    .line 271
    return-void

    .line 272
    nop

    .line 273
    :sswitch_data_0
    .sparse-switch
        0x2c0618eb -> :sswitch_3
        0x2c065c6b -> :sswitch_2
        0x3e4ca2d8 -> :sswitch_1
        0x54c61e47 -> :sswitch_0
    .end sparse-switch

    .line 274
    .line 275
    .line 276
    .line 277
    .line 278
    .line 279
    .line 280
    .line 281
    .line 282
    .line 283
    .line 284
    .line 285
    .line 286
    .line 287
    .line 288
    .line 289
    .line 290
    .line 291
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final h(Lo8/p;Lo8/s;)I
    .locals 42

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const/4 v3, 0x0

    .line 4
    iput-boolean v3, v0, Lg9/d;->I:Z

    .line 5
    .line 6
    const/4 v5, 0x1

    .line 7
    :goto_0
    const/4 v6, -0x1

    .line 8
    if-eqz v5, :cond_ba

    .line 9
    .line 10
    iget-boolean v7, v0, Lg9/d;->I:Z

    .line 11
    .line 12
    if-nez v7, :cond_ba

    .line 13
    .line 14
    iget-object v7, v0, Lg9/d;->a:Lg9/b;

    .line 15
    .line 16
    iget-object v8, v7, Lg9/b;->c:Lg9/e;

    .line 17
    .line 18
    iget-object v9, v7, Lg9/b;->b:Ljava/util/ArrayDeque;

    .line 19
    .line 20
    iget-object v5, v7, Lg9/b;->d:La0/j;

    .line 21
    .line 22
    invoke-static {v5}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    :goto_1
    invoke-virtual {v9}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v5

    .line 29
    check-cast v5, Lg9/a;

    .line 30
    .line 31
    const-wide/16 v17, 0x0

    .line 32
    .line 33
    const-wide/16 v20, -0x1

    .line 34
    .line 35
    const v11, 0x1654ae6b

    .line 36
    .line 37
    .line 38
    const v15, 0x1549a966

    .line 39
    .line 40
    .line 41
    const/16 v10, 0x4dbb

    .line 42
    .line 43
    const/16 v13, 0xae

    .line 44
    .line 45
    const/16 v23, 0x8

    .line 46
    .line 47
    const/16 v14, 0xa0

    .line 48
    .line 49
    const/high16 v25, -0x40800000    # -1.0f

    .line 50
    .line 51
    const v3, 0x1c53bb6b

    .line 52
    .line 53
    .line 54
    if-eqz v5, :cond_8c

    .line 55
    .line 56
    invoke-interface/range {p1 .. p1}, Lo8/p;->getPosition()J

    .line 57
    .line 58
    .line 59
    move-result-wide v26

    .line 60
    iget-wide v4, v5, Lg9/a;->b:J

    .line 61
    .line 62
    cmp-long v4, v26, v4

    .line 63
    .line 64
    if-ltz v4, :cond_8c

    .line 65
    .line 66
    iget-object v4, v7, Lg9/b;->d:La0/j;

    .line 67
    .line 68
    invoke-virtual {v9}, Ljava/util/ArrayDeque;->pop()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v5

    .line 72
    check-cast v5, Lg9/a;

    .line 73
    .line 74
    iget v5, v5, Lg9/a;->a:I

    .line 75
    .line 76
    iget-object v4, v4, La0/j;->e:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v4, Lg9/d;

    .line 79
    .line 80
    iget-object v7, v4, Lg9/d;->c:Landroid/util/SparseArray;

    .line 81
    .line 82
    iget-object v8, v4, Lg9/d;->e0:Lo8/q;

    .line 83
    .line 84
    invoke-static {v8}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    const-string v8, "A_OPUS"

    .line 88
    .line 89
    if-eq v5, v14, :cond_86

    .line 90
    .line 91
    const-string v9, "video/webm"

    .line 92
    .line 93
    const-string v14, "MatroskaExtractor"

    .line 94
    .line 95
    if-eq v5, v13, :cond_13

    .line 96
    .line 97
    if-eq v5, v10, :cond_11

    .line 98
    .line 99
    const/16 v6, 0x6240

    .line 100
    .line 101
    if-eq v5, v6, :cond_f

    .line 102
    .line 103
    const/16 v6, 0x6d80

    .line 104
    .line 105
    if-eq v5, v6, :cond_d

    .line 106
    .line 107
    const-wide v8, -0x7fffffffffffffffL    # -4.9E-324

    .line 108
    .line 109
    .line 110
    .line 111
    .line 112
    if-eq v5, v15, :cond_b

    .line 113
    .line 114
    if-eq v5, v11, :cond_9

    .line 115
    .line 116
    if-eq v5, v3, :cond_0

    .line 117
    .line 118
    goto/16 :goto_34

    .line 119
    .line 120
    :cond_0
    iget-boolean v3, v4, Lg9/d;->y:Z

    .line 121
    .line 122
    if-nez v3, :cond_7

    .line 123
    .line 124
    iget-object v3, v4, Lg9/d;->e0:Lo8/q;

    .line 125
    .line 126
    iget-object v5, v4, Lg9/d;->F:Lq3/b;

    .line 127
    .line 128
    iget-object v6, v4, Lg9/d;->G:Lq3/b;

    .line 129
    .line 130
    iget-wide v10, v4, Lg9/d;->s:J

    .line 131
    .line 132
    cmp-long v7, v10, v20

    .line 133
    .line 134
    if-eqz v7, :cond_6

    .line 135
    .line 136
    iget-wide v10, v4, Lg9/d;->v:J

    .line 137
    .line 138
    cmp-long v7, v10, v8

    .line 139
    .line 140
    if-eqz v7, :cond_6

    .line 141
    .line 142
    if-eqz v5, :cond_6

    .line 143
    .line 144
    iget v7, v5, Lq3/b;->b:I

    .line 145
    .line 146
    if-eqz v7, :cond_6

    .line 147
    .line 148
    if-eqz v6, :cond_6

    .line 149
    .line 150
    iget v8, v6, Lq3/b;->b:I

    .line 151
    .line 152
    if-eq v8, v7, :cond_1

    .line 153
    .line 154
    goto/16 :goto_5

    .line 155
    .line 156
    :cond_1
    new-array v8, v7, [I

    .line 157
    .line 158
    new-array v9, v7, [J

    .line 159
    .line 160
    new-array v10, v7, [J

    .line 161
    .line 162
    new-array v11, v7, [J

    .line 163
    .line 164
    const/4 v13, 0x0

    .line 165
    :goto_2
    if-ge v13, v7, :cond_2

    .line 166
    .line 167
    invoke-virtual {v5, v13}, Lq3/b;->d(I)J

    .line 168
    .line 169
    .line 170
    move-result-wide v15

    .line 171
    aput-wide v15, v11, v13

    .line 172
    .line 173
    iget-wide v0, v4, Lg9/d;->s:J

    .line 174
    .line 175
    invoke-virtual {v6, v13}, Lq3/b;->d(I)J

    .line 176
    .line 177
    .line 178
    move-result-wide v15

    .line 179
    add-long/2addr v15, v0

    .line 180
    aput-wide v15, v9, v13

    .line 181
    .line 182
    add-int/lit8 v13, v13, 0x1

    .line 183
    .line 184
    move-object/from16 v0, p0

    .line 185
    .line 186
    goto :goto_2

    .line 187
    :cond_2
    const/4 v0, 0x0

    .line 188
    :goto_3
    add-int/lit8 v1, v7, -0x1

    .line 189
    .line 190
    if-ge v0, v1, :cond_3

    .line 191
    .line 192
    add-int/lit8 v1, v0, 0x1

    .line 193
    .line 194
    aget-wide v5, v9, v1

    .line 195
    .line 196
    aget-wide v15, v9, v0

    .line 197
    .line 198
    sub-long/2addr v5, v15

    .line 199
    long-to-int v5, v5

    .line 200
    aput v5, v8, v0

    .line 201
    .line 202
    aget-wide v5, v11, v1

    .line 203
    .line 204
    aget-wide v15, v11, v0

    .line 205
    .line 206
    sub-long/2addr v5, v15

    .line 207
    aput-wide v5, v10, v0

    .line 208
    .line 209
    move v0, v1

    .line 210
    goto :goto_3

    .line 211
    :cond_3
    move v0, v1

    .line 212
    :goto_4
    if-lez v0, :cond_4

    .line 213
    .line 214
    aget-wide v5, v11, v0

    .line 215
    .line 216
    iget-wide v12, v4, Lg9/d;->v:J

    .line 217
    .line 218
    cmp-long v5, v5, v12

    .line 219
    .line 220
    if-lez v5, :cond_4

    .line 221
    .line 222
    add-int/lit8 v0, v0, -0x1

    .line 223
    .line 224
    goto :goto_4

    .line 225
    :cond_4
    iget-wide v5, v4, Lg9/d;->s:J

    .line 226
    .line 227
    iget-wide v12, v4, Lg9/d;->r:J

    .line 228
    .line 229
    add-long/2addr v5, v12

    .line 230
    aget-wide v12, v9, v0

    .line 231
    .line 232
    sub-long/2addr v5, v12

    .line 233
    long-to-int v5, v5

    .line 234
    aput v5, v8, v0

    .line 235
    .line 236
    iget-wide v5, v4, Lg9/d;->v:J

    .line 237
    .line 238
    aget-wide v12, v11, v0

    .line 239
    .line 240
    sub-long/2addr v5, v12

    .line 241
    aput-wide v5, v10, v0

    .line 242
    .line 243
    if-ge v0, v1, :cond_5

    .line 244
    .line 245
    const-string v1, "Discarding trailing cue points with timestamps greater than total duration"

    .line 246
    .line 247
    invoke-static {v14, v1}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 248
    .line 249
    .line 250
    add-int/lit8 v0, v0, 0x1

    .line 251
    .line 252
    invoke-static {v8, v0}, Ljava/util/Arrays;->copyOf([II)[I

    .line 253
    .line 254
    .line 255
    move-result-object v8

    .line 256
    invoke-static {v9, v0}, Ljava/util/Arrays;->copyOf([JI)[J

    .line 257
    .line 258
    .line 259
    move-result-object v9

    .line 260
    invoke-static {v10, v0}, Ljava/util/Arrays;->copyOf([JI)[J

    .line 261
    .line 262
    .line 263
    move-result-object v10

    .line 264
    invoke-static {v11, v0}, Ljava/util/Arrays;->copyOf([JI)[J

    .line 265
    .line 266
    .line 267
    move-result-object v11

    .line 268
    :cond_5
    new-instance v0, Lo8/k;

    .line 269
    .line 270
    invoke-direct {v0, v8, v9, v10, v11}, Lo8/k;-><init>([I[J[J[J)V

    .line 271
    .line 272
    .line 273
    goto :goto_6

    .line 274
    :cond_6
    :goto_5
    new-instance v0, Lo8/t;

    .line 275
    .line 276
    iget-wide v5, v4, Lg9/d;->v:J

    .line 277
    .line 278
    invoke-direct {v0, v5, v6}, Lo8/t;-><init>(J)V

    .line 279
    .line 280
    .line 281
    :goto_6
    invoke-interface {v3, v0}, Lo8/q;->c(Lo8/c0;)V

    .line 282
    .line 283
    .line 284
    const/4 v0, 0x1

    .line 285
    iput-boolean v0, v4, Lg9/d;->y:Z

    .line 286
    .line 287
    :cond_7
    const/4 v0, 0x0

    .line 288
    iput-object v0, v4, Lg9/d;->F:Lq3/b;

    .line 289
    .line 290
    iput-object v0, v4, Lg9/d;->G:Lq3/b;

    .line 291
    .line 292
    :cond_8
    :goto_7
    const/4 v0, 0x0

    .line 293
    goto/16 :goto_37

    .line 294
    .line 295
    :cond_9
    const/4 v0, 0x0

    .line 296
    invoke-virtual {v7}, Landroid/util/SparseArray;->size()I

    .line 297
    .line 298
    .line 299
    move-result v1

    .line 300
    if-eqz v1, :cond_a

    .line 301
    .line 302
    iget-object v0, v4, Lg9/d;->e0:Lo8/q;

    .line 303
    .line 304
    invoke-interface {v0}, Lo8/q;->m()V

    .line 305
    .line 306
    .line 307
    goto :goto_7

    .line 308
    :cond_a
    const-string v1, "No valid tracks were found"

    .line 309
    .line 310
    invoke-static {v0, v1}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 311
    .line 312
    .line 313
    move-result-object v0

    .line 314
    throw v0

    .line 315
    :cond_b
    iget-wide v0, v4, Lg9/d;->t:J

    .line 316
    .line 317
    cmp-long v0, v0, v8

    .line 318
    .line 319
    if-nez v0, :cond_c

    .line 320
    .line 321
    const-wide/32 v0, 0xf4240

    .line 322
    .line 323
    .line 324
    iput-wide v0, v4, Lg9/d;->t:J

    .line 325
    .line 326
    :cond_c
    iget-wide v0, v4, Lg9/d;->u:J

    .line 327
    .line 328
    cmp-long v3, v0, v8

    .line 329
    .line 330
    if-eqz v3, :cond_8

    .line 331
    .line 332
    invoke-virtual {v4, v0, v1}, Lg9/d;->m(J)J

    .line 333
    .line 334
    .line 335
    move-result-wide v0

    .line 336
    iput-wide v0, v4, Lg9/d;->v:J

    .line 337
    .line 338
    goto :goto_7

    .line 339
    :cond_d
    invoke-virtual {v4, v5}, Lg9/d;->f(I)V

    .line 340
    .line 341
    .line 342
    iget-object v0, v4, Lg9/d;->x:Lg9/c;

    .line 343
    .line 344
    iget-boolean v1, v0, Lg9/c;->i:Z

    .line 345
    .line 346
    if-eqz v1, :cond_8

    .line 347
    .line 348
    iget-object v0, v0, Lg9/c;->j:[B

    .line 349
    .line 350
    if-nez v0, :cond_e

    .line 351
    .line 352
    goto/16 :goto_34

    .line 353
    .line 354
    :cond_e
    const-string v0, "Combining encryption and compression is not supported"

    .line 355
    .line 356
    const/4 v1, 0x0

    .line 357
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 358
    .line 359
    .line 360
    move-result-object v0

    .line 361
    throw v0

    .line 362
    :cond_f
    invoke-virtual {v4, v5}, Lg9/d;->f(I)V

    .line 363
    .line 364
    .line 365
    iget-object v0, v4, Lg9/d;->x:Lg9/c;

    .line 366
    .line 367
    iget-boolean v1, v0, Lg9/c;->i:Z

    .line 368
    .line 369
    if-eqz v1, :cond_8

    .line 370
    .line 371
    iget-object v1, v0, Lg9/c;->k:Lo8/h0;

    .line 372
    .line 373
    if-eqz v1, :cond_10

    .line 374
    .line 375
    new-instance v3, Lt7/k;

    .line 376
    .line 377
    new-instance v4, Lt7/j;

    .line 378
    .line 379
    sget-object v5, Lt7/e;->a:Ljava/util/UUID;

    .line 380
    .line 381
    iget-object v1, v1, Lo8/h0;->b:[B

    .line 382
    .line 383
    const/4 v6, 0x0

    .line 384
    invoke-direct {v4, v5, v6, v9, v1}, Lt7/j;-><init>(Ljava/util/UUID;Ljava/lang/String;Ljava/lang/String;[B)V

    .line 385
    .line 386
    .line 387
    filled-new-array {v4}, [Lt7/j;

    .line 388
    .line 389
    .line 390
    move-result-object v1

    .line 391
    const/4 v4, 0x1

    .line 392
    invoke-direct {v3, v6, v4, v1}, Lt7/k;-><init>(Ljava/lang/String;Z[Lt7/j;)V

    .line 393
    .line 394
    .line 395
    iput-object v3, v0, Lg9/c;->m:Lt7/k;

    .line 396
    .line 397
    goto :goto_7

    .line 398
    :cond_10
    const/4 v6, 0x0

    .line 399
    const-string v0, "Encrypted Track found but ContentEncKeyID was not found"

    .line 400
    .line 401
    invoke-static {v6, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 402
    .line 403
    .line 404
    move-result-object v0

    .line 405
    throw v0

    .line 406
    :cond_11
    iget v0, v4, Lg9/d;->z:I

    .line 407
    .line 408
    if-eq v0, v6, :cond_12

    .line 409
    .line 410
    iget-wide v5, v4, Lg9/d;->A:J

    .line 411
    .line 412
    cmp-long v1, v5, v20

    .line 413
    .line 414
    if-eqz v1, :cond_12

    .line 415
    .line 416
    if-ne v0, v3, :cond_8

    .line 417
    .line 418
    iput-wide v5, v4, Lg9/d;->C:J

    .line 419
    .line 420
    goto/16 :goto_7

    .line 421
    .line 422
    :cond_12
    const-string v0, "Mandatory element SeekID or SeekPosition not found"

    .line 423
    .line 424
    const/4 v1, 0x0

    .line 425
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 426
    .line 427
    .line 428
    move-result-object v0

    .line 429
    throw v0

    .line 430
    :cond_13
    iget-object v0, v4, Lg9/d;->x:Lg9/c;

    .line 431
    .line 432
    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 433
    .line 434
    .line 435
    iget-object v1, v0, Lg9/c;->c:Ljava/lang/String;

    .line 436
    .line 437
    if-eqz v1, :cond_85

    .line 438
    .line 439
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 440
    .line 441
    .line 442
    move-result v3

    .line 443
    const-string v5, "A_MPEG/L3"

    .line 444
    .line 445
    const-string v10, "A_MPEG/L2"

    .line 446
    .line 447
    const-string v11, "A_VORBIS"

    .line 448
    .line 449
    const-string v12, "A_TRUEHD"

    .line 450
    .line 451
    const-string v13, "A_MS/ACM"

    .line 452
    .line 453
    const-string v15, "V_MPEG4/ISO/SP"

    .line 454
    .line 455
    const-string v6, "V_MPEG4/ISO/AP"

    .line 456
    .line 457
    move/from16 v17, v3

    .line 458
    .line 459
    const/16 v29, 0x14

    .line 460
    .line 461
    sparse-switch v17, :sswitch_data_0

    .line 462
    .line 463
    .line 464
    :goto_8
    const/4 v3, -0x1

    .line 465
    goto/16 :goto_9

    .line 466
    .line 467
    :sswitch_0
    invoke-virtual {v1, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 468
    .line 469
    .line 470
    move-result v17

    .line 471
    if-nez v17, :cond_14

    .line 472
    .line 473
    goto :goto_8

    .line 474
    :cond_14
    const/16 v17, 0x21

    .line 475
    .line 476
    move/from16 v3, v17

    .line 477
    .line 478
    goto/16 :goto_9

    .line 479
    .line 480
    :sswitch_1
    const-string v3, "A_FLAC"

    .line 481
    .line 482
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 483
    .line 484
    .line 485
    move-result v3

    .line 486
    if-nez v3, :cond_15

    .line 487
    .line 488
    goto :goto_8

    .line 489
    :cond_15
    const/16 v3, 0x20

    .line 490
    .line 491
    goto/16 :goto_9

    .line 492
    .line 493
    :sswitch_2
    const-string v3, "A_EAC3"

    .line 494
    .line 495
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 496
    .line 497
    .line 498
    move-result v3

    .line 499
    if-nez v3, :cond_16

    .line 500
    .line 501
    goto :goto_8

    .line 502
    :cond_16
    const/16 v3, 0x1f

    .line 503
    .line 504
    goto/16 :goto_9

    .line 505
    .line 506
    :sswitch_3
    const-string v3, "V_MPEG2"

    .line 507
    .line 508
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 509
    .line 510
    .line 511
    move-result v3

    .line 512
    if-nez v3, :cond_17

    .line 513
    .line 514
    goto :goto_8

    .line 515
    :cond_17
    const/16 v3, 0x1e

    .line 516
    .line 517
    goto/16 :goto_9

    .line 518
    .line 519
    :sswitch_4
    const-string v3, "S_TEXT/UTF8"

    .line 520
    .line 521
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 522
    .line 523
    .line 524
    move-result v3

    .line 525
    if-nez v3, :cond_18

    .line 526
    .line 527
    goto :goto_8

    .line 528
    :cond_18
    const/16 v3, 0x1d

    .line 529
    .line 530
    goto/16 :goto_9

    .line 531
    .line 532
    :sswitch_5
    const-string v3, "S_TEXT/WEBVTT"

    .line 533
    .line 534
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 535
    .line 536
    .line 537
    move-result v3

    .line 538
    if-nez v3, :cond_19

    .line 539
    .line 540
    goto :goto_8

    .line 541
    :cond_19
    const/16 v3, 0x1c

    .line 542
    .line 543
    goto/16 :goto_9

    .line 544
    .line 545
    :sswitch_6
    const-string v3, "V_MPEGH/ISO/HEVC"

    .line 546
    .line 547
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 548
    .line 549
    .line 550
    move-result v3

    .line 551
    if-nez v3, :cond_1a

    .line 552
    .line 553
    goto :goto_8

    .line 554
    :cond_1a
    const/16 v3, 0x1b

    .line 555
    .line 556
    goto/16 :goto_9

    .line 557
    .line 558
    :sswitch_7
    const-string v3, "S_TEXT/SSA"

    .line 559
    .line 560
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 561
    .line 562
    .line 563
    move-result v3

    .line 564
    if-nez v3, :cond_1b

    .line 565
    .line 566
    goto :goto_8

    .line 567
    :cond_1b
    const/16 v3, 0x1a

    .line 568
    .line 569
    goto/16 :goto_9

    .line 570
    .line 571
    :sswitch_8
    const-string v3, "S_TEXT/ASS"

    .line 572
    .line 573
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 574
    .line 575
    .line 576
    move-result v3

    .line 577
    if-nez v3, :cond_1c

    .line 578
    .line 579
    goto :goto_8

    .line 580
    :cond_1c
    const/16 v3, 0x19

    .line 581
    .line 582
    goto/16 :goto_9

    .line 583
    .line 584
    :sswitch_9
    const-string v3, "A_PCM/INT/LIT"

    .line 585
    .line 586
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 587
    .line 588
    .line 589
    move-result v3

    .line 590
    if-nez v3, :cond_1d

    .line 591
    .line 592
    goto/16 :goto_8

    .line 593
    .line 594
    :cond_1d
    const/16 v3, 0x18

    .line 595
    .line 596
    goto/16 :goto_9

    .line 597
    .line 598
    :sswitch_a
    const-string v3, "A_PCM/INT/BIG"

    .line 599
    .line 600
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 601
    .line 602
    .line 603
    move-result v3

    .line 604
    if-nez v3, :cond_1e

    .line 605
    .line 606
    goto/16 :goto_8

    .line 607
    .line 608
    :cond_1e
    const/16 v3, 0x17

    .line 609
    .line 610
    goto/16 :goto_9

    .line 611
    .line 612
    :sswitch_b
    const-string v3, "A_PCM/FLOAT/IEEE"

    .line 613
    .line 614
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 615
    .line 616
    .line 617
    move-result v3

    .line 618
    if-nez v3, :cond_1f

    .line 619
    .line 620
    goto/16 :goto_8

    .line 621
    .line 622
    :cond_1f
    const/16 v3, 0x16

    .line 623
    .line 624
    goto/16 :goto_9

    .line 625
    .line 626
    :sswitch_c
    const-string v3, "A_DTS/EXPRESS"

    .line 627
    .line 628
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 629
    .line 630
    .line 631
    move-result v3

    .line 632
    if-nez v3, :cond_20

    .line 633
    .line 634
    goto/16 :goto_8

    .line 635
    .line 636
    :cond_20
    const/16 v3, 0x15

    .line 637
    .line 638
    goto/16 :goto_9

    .line 639
    .line 640
    :sswitch_d
    const-string v3, "V_THEORA"

    .line 641
    .line 642
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 643
    .line 644
    .line 645
    move-result v3

    .line 646
    if-nez v3, :cond_21

    .line 647
    .line 648
    goto/16 :goto_8

    .line 649
    .line 650
    :cond_21
    move/from16 v3, v29

    .line 651
    .line 652
    goto/16 :goto_9

    .line 653
    .line 654
    :sswitch_e
    const-string v3, "S_HDMV/PGS"

    .line 655
    .line 656
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 657
    .line 658
    .line 659
    move-result v3

    .line 660
    if-nez v3, :cond_22

    .line 661
    .line 662
    goto/16 :goto_8

    .line 663
    .line 664
    :cond_22
    const/16 v3, 0x13

    .line 665
    .line 666
    goto/16 :goto_9

    .line 667
    .line 668
    :sswitch_f
    const-string v3, "V_VP9"

    .line 669
    .line 670
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 671
    .line 672
    .line 673
    move-result v3

    .line 674
    if-nez v3, :cond_23

    .line 675
    .line 676
    goto/16 :goto_8

    .line 677
    .line 678
    :cond_23
    const/16 v3, 0x12

    .line 679
    .line 680
    goto/16 :goto_9

    .line 681
    .line 682
    :sswitch_10
    const-string v3, "V_VP8"

    .line 683
    .line 684
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 685
    .line 686
    .line 687
    move-result v3

    .line 688
    if-nez v3, :cond_24

    .line 689
    .line 690
    goto/16 :goto_8

    .line 691
    .line 692
    :cond_24
    const/16 v3, 0x11

    .line 693
    .line 694
    goto/16 :goto_9

    .line 695
    .line 696
    :sswitch_11
    const-string v3, "V_AV1"

    .line 697
    .line 698
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 699
    .line 700
    .line 701
    move-result v3

    .line 702
    if-nez v3, :cond_25

    .line 703
    .line 704
    goto/16 :goto_8

    .line 705
    .line 706
    :cond_25
    const/16 v3, 0x10

    .line 707
    .line 708
    goto/16 :goto_9

    .line 709
    .line 710
    :sswitch_12
    const-string v3, "A_DTS"

    .line 711
    .line 712
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 713
    .line 714
    .line 715
    move-result v3

    .line 716
    if-nez v3, :cond_26

    .line 717
    .line 718
    goto/16 :goto_8

    .line 719
    .line 720
    :cond_26
    const/16 v3, 0xf

    .line 721
    .line 722
    goto/16 :goto_9

    .line 723
    .line 724
    :sswitch_13
    const-string v3, "A_AC3"

    .line 725
    .line 726
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 727
    .line 728
    .line 729
    move-result v3

    .line 730
    if-nez v3, :cond_27

    .line 731
    .line 732
    goto/16 :goto_8

    .line 733
    .line 734
    :cond_27
    const/16 v3, 0xe

    .line 735
    .line 736
    goto/16 :goto_9

    .line 737
    .line 738
    :sswitch_14
    const-string v3, "A_AAC"

    .line 739
    .line 740
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 741
    .line 742
    .line 743
    move-result v3

    .line 744
    if-nez v3, :cond_28

    .line 745
    .line 746
    goto/16 :goto_8

    .line 747
    .line 748
    :cond_28
    const/16 v3, 0xd

    .line 749
    .line 750
    goto/16 :goto_9

    .line 751
    .line 752
    :sswitch_15
    const-string v3, "A_DTS/LOSSLESS"

    .line 753
    .line 754
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 755
    .line 756
    .line 757
    move-result v3

    .line 758
    if-nez v3, :cond_29

    .line 759
    .line 760
    goto/16 :goto_8

    .line 761
    .line 762
    :cond_29
    const/16 v3, 0xc

    .line 763
    .line 764
    goto/16 :goto_9

    .line 765
    .line 766
    :sswitch_16
    const-string v3, "S_VOBSUB"

    .line 767
    .line 768
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 769
    .line 770
    .line 771
    move-result v3

    .line 772
    if-nez v3, :cond_2a

    .line 773
    .line 774
    goto/16 :goto_8

    .line 775
    .line 776
    :cond_2a
    const/16 v3, 0xb

    .line 777
    .line 778
    goto/16 :goto_9

    .line 779
    .line 780
    :sswitch_17
    const-string v3, "V_MPEG4/ISO/AVC"

    .line 781
    .line 782
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 783
    .line 784
    .line 785
    move-result v3

    .line 786
    if-nez v3, :cond_2b

    .line 787
    .line 788
    goto/16 :goto_8

    .line 789
    .line 790
    :cond_2b
    const/16 v3, 0xa

    .line 791
    .line 792
    goto/16 :goto_9

    .line 793
    .line 794
    :sswitch_18
    const-string v3, "V_MPEG4/ISO/ASP"

    .line 795
    .line 796
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 797
    .line 798
    .line 799
    move-result v3

    .line 800
    if-nez v3, :cond_2c

    .line 801
    .line 802
    goto/16 :goto_8

    .line 803
    .line 804
    :cond_2c
    const/16 v3, 0x9

    .line 805
    .line 806
    goto/16 :goto_9

    .line 807
    .line 808
    :sswitch_19
    const-string v3, "S_DVBSUB"

    .line 809
    .line 810
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 811
    .line 812
    .line 813
    move-result v3

    .line 814
    if-nez v3, :cond_2d

    .line 815
    .line 816
    goto/16 :goto_8

    .line 817
    .line 818
    :cond_2d
    move/from16 v3, v23

    .line 819
    .line 820
    goto :goto_9

    .line 821
    :sswitch_1a
    const-string v3, "V_MS/VFW/FOURCC"

    .line 822
    .line 823
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 824
    .line 825
    .line 826
    move-result v3

    .line 827
    if-nez v3, :cond_2e

    .line 828
    .line 829
    goto/16 :goto_8

    .line 830
    .line 831
    :cond_2e
    const/4 v3, 0x7

    .line 832
    goto :goto_9

    .line 833
    :sswitch_1b
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 834
    .line 835
    .line 836
    move-result v3

    .line 837
    if-nez v3, :cond_2f

    .line 838
    .line 839
    goto/16 :goto_8

    .line 840
    .line 841
    :cond_2f
    const/4 v3, 0x6

    .line 842
    goto :goto_9

    .line 843
    :sswitch_1c
    invoke-virtual {v1, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 844
    .line 845
    .line 846
    move-result v3

    .line 847
    if-nez v3, :cond_30

    .line 848
    .line 849
    goto/16 :goto_8

    .line 850
    .line 851
    :cond_30
    const/4 v3, 0x5

    .line 852
    goto :goto_9

    .line 853
    :sswitch_1d
    invoke-virtual {v1, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 854
    .line 855
    .line 856
    move-result v3

    .line 857
    if-nez v3, :cond_31

    .line 858
    .line 859
    goto/16 :goto_8

    .line 860
    .line 861
    :cond_31
    const/4 v3, 0x4

    .line 862
    goto :goto_9

    .line 863
    :sswitch_1e
    invoke-virtual {v1, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 864
    .line 865
    .line 866
    move-result v3

    .line 867
    if-nez v3, :cond_32

    .line 868
    .line 869
    goto/16 :goto_8

    .line 870
    .line 871
    :cond_32
    const/4 v3, 0x3

    .line 872
    goto :goto_9

    .line 873
    :sswitch_1f
    invoke-virtual {v1, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 874
    .line 875
    .line 876
    move-result v3

    .line 877
    if-nez v3, :cond_33

    .line 878
    .line 879
    goto/16 :goto_8

    .line 880
    .line 881
    :cond_33
    const/4 v3, 0x2

    .line 882
    goto :goto_9

    .line 883
    :sswitch_20
    invoke-virtual {v1, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 884
    .line 885
    .line 886
    move-result v3

    .line 887
    if-nez v3, :cond_34

    .line 888
    .line 889
    goto/16 :goto_8

    .line 890
    .line 891
    :cond_34
    const/4 v3, 0x1

    .line 892
    goto :goto_9

    .line 893
    :sswitch_21
    invoke-virtual {v1, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 894
    .line 895
    .line 896
    move-result v3

    .line 897
    if-nez v3, :cond_35

    .line 898
    .line 899
    goto/16 :goto_8

    .line 900
    .line 901
    :cond_35
    const/4 v3, 0x0

    .line 902
    :goto_9
    packed-switch v3, :pswitch_data_0

    .line 903
    .line 904
    .line 905
    :goto_a
    const/4 v1, 0x0

    .line 906
    goto/16 :goto_33

    .line 907
    .line 908
    :pswitch_0
    iget-object v3, v4, Lg9/d;->e0:Lo8/q;

    .line 909
    .line 910
    move-object/from16 v32, v9

    .line 911
    .line 912
    iget v9, v0, Lg9/c;->d:I

    .line 913
    .line 914
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 915
    .line 916
    .line 917
    move-result v33

    .line 918
    sparse-switch v33, :sswitch_data_1

    .line 919
    .line 920
    .line 921
    :goto_b
    const/4 v15, -0x1

    .line 922
    goto/16 :goto_c

    .line 923
    .line 924
    :sswitch_22
    invoke-virtual {v1, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 925
    .line 926
    .line 927
    move-result v5

    .line 928
    if-nez v5, :cond_36

    .line 929
    .line 930
    goto :goto_b

    .line 931
    :cond_36
    const/16 v15, 0x21

    .line 932
    .line 933
    goto/16 :goto_c

    .line 934
    .line 935
    :sswitch_23
    const-string v5, "A_FLAC"

    .line 936
    .line 937
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 938
    .line 939
    .line 940
    move-result v5

    .line 941
    if-nez v5, :cond_37

    .line 942
    .line 943
    goto :goto_b

    .line 944
    :cond_37
    const/16 v15, 0x20

    .line 945
    .line 946
    goto/16 :goto_c

    .line 947
    .line 948
    :sswitch_24
    const-string v5, "A_EAC3"

    .line 949
    .line 950
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 951
    .line 952
    .line 953
    move-result v5

    .line 954
    if-nez v5, :cond_38

    .line 955
    .line 956
    goto :goto_b

    .line 957
    :cond_38
    const/16 v15, 0x1f

    .line 958
    .line 959
    goto/16 :goto_c

    .line 960
    .line 961
    :sswitch_25
    const-string v5, "V_MPEG2"

    .line 962
    .line 963
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 964
    .line 965
    .line 966
    move-result v5

    .line 967
    if-nez v5, :cond_39

    .line 968
    .line 969
    goto :goto_b

    .line 970
    :cond_39
    const/16 v15, 0x1e

    .line 971
    .line 972
    goto/16 :goto_c

    .line 973
    .line 974
    :sswitch_26
    const-string v5, "S_TEXT/UTF8"

    .line 975
    .line 976
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 977
    .line 978
    .line 979
    move-result v5

    .line 980
    if-nez v5, :cond_3a

    .line 981
    .line 982
    goto :goto_b

    .line 983
    :cond_3a
    const/16 v15, 0x1d

    .line 984
    .line 985
    goto/16 :goto_c

    .line 986
    .line 987
    :sswitch_27
    const-string v5, "S_TEXT/WEBVTT"

    .line 988
    .line 989
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 990
    .line 991
    .line 992
    move-result v5

    .line 993
    if-nez v5, :cond_3b

    .line 994
    .line 995
    goto :goto_b

    .line 996
    :cond_3b
    const/16 v15, 0x1c

    .line 997
    .line 998
    goto/16 :goto_c

    .line 999
    .line 1000
    :sswitch_28
    const-string v5, "V_MPEGH/ISO/HEVC"

    .line 1001
    .line 1002
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1003
    .line 1004
    .line 1005
    move-result v5

    .line 1006
    if-nez v5, :cond_3c

    .line 1007
    .line 1008
    goto :goto_b

    .line 1009
    :cond_3c
    const/16 v15, 0x1b

    .line 1010
    .line 1011
    goto/16 :goto_c

    .line 1012
    .line 1013
    :sswitch_29
    const-string v5, "S_TEXT/SSA"

    .line 1014
    .line 1015
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1016
    .line 1017
    .line 1018
    move-result v5

    .line 1019
    if-nez v5, :cond_3d

    .line 1020
    .line 1021
    goto :goto_b

    .line 1022
    :cond_3d
    const/16 v15, 0x1a

    .line 1023
    .line 1024
    goto/16 :goto_c

    .line 1025
    .line 1026
    :sswitch_2a
    const-string v5, "S_TEXT/ASS"

    .line 1027
    .line 1028
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1029
    .line 1030
    .line 1031
    move-result v5

    .line 1032
    if-nez v5, :cond_3e

    .line 1033
    .line 1034
    goto :goto_b

    .line 1035
    :cond_3e
    const/16 v15, 0x19

    .line 1036
    .line 1037
    goto/16 :goto_c

    .line 1038
    .line 1039
    :sswitch_2b
    const-string v5, "A_PCM/INT/LIT"

    .line 1040
    .line 1041
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1042
    .line 1043
    .line 1044
    move-result v5

    .line 1045
    if-nez v5, :cond_3f

    .line 1046
    .line 1047
    goto :goto_b

    .line 1048
    :cond_3f
    const/16 v15, 0x18

    .line 1049
    .line 1050
    goto/16 :goto_c

    .line 1051
    .line 1052
    :sswitch_2c
    const-string v5, "A_PCM/INT/BIG"

    .line 1053
    .line 1054
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1055
    .line 1056
    .line 1057
    move-result v5

    .line 1058
    if-nez v5, :cond_40

    .line 1059
    .line 1060
    goto/16 :goto_b

    .line 1061
    .line 1062
    :cond_40
    const/16 v15, 0x17

    .line 1063
    .line 1064
    goto/16 :goto_c

    .line 1065
    .line 1066
    :sswitch_2d
    const-string v5, "A_PCM/FLOAT/IEEE"

    .line 1067
    .line 1068
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1069
    .line 1070
    .line 1071
    move-result v5

    .line 1072
    if-nez v5, :cond_41

    .line 1073
    .line 1074
    goto/16 :goto_b

    .line 1075
    .line 1076
    :cond_41
    const/16 v15, 0x16

    .line 1077
    .line 1078
    goto/16 :goto_c

    .line 1079
    .line 1080
    :sswitch_2e
    const-string v5, "A_DTS/EXPRESS"

    .line 1081
    .line 1082
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1083
    .line 1084
    .line 1085
    move-result v5

    .line 1086
    if-nez v5, :cond_42

    .line 1087
    .line 1088
    goto/16 :goto_b

    .line 1089
    .line 1090
    :cond_42
    const/16 v15, 0x15

    .line 1091
    .line 1092
    goto/16 :goto_c

    .line 1093
    .line 1094
    :sswitch_2f
    const-string v5, "V_THEORA"

    .line 1095
    .line 1096
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1097
    .line 1098
    .line 1099
    move-result v5

    .line 1100
    if-nez v5, :cond_43

    .line 1101
    .line 1102
    goto/16 :goto_b

    .line 1103
    .line 1104
    :cond_43
    move/from16 v15, v29

    .line 1105
    .line 1106
    goto/16 :goto_c

    .line 1107
    .line 1108
    :sswitch_30
    const-string v5, "S_HDMV/PGS"

    .line 1109
    .line 1110
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1111
    .line 1112
    .line 1113
    move-result v5

    .line 1114
    if-nez v5, :cond_44

    .line 1115
    .line 1116
    goto/16 :goto_b

    .line 1117
    .line 1118
    :cond_44
    const/16 v15, 0x13

    .line 1119
    .line 1120
    goto/16 :goto_c

    .line 1121
    .line 1122
    :sswitch_31
    const-string v5, "V_VP9"

    .line 1123
    .line 1124
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1125
    .line 1126
    .line 1127
    move-result v5

    .line 1128
    if-nez v5, :cond_45

    .line 1129
    .line 1130
    goto/16 :goto_b

    .line 1131
    .line 1132
    :cond_45
    const/16 v15, 0x12

    .line 1133
    .line 1134
    goto/16 :goto_c

    .line 1135
    .line 1136
    :sswitch_32
    const-string v5, "V_VP8"

    .line 1137
    .line 1138
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1139
    .line 1140
    .line 1141
    move-result v5

    .line 1142
    if-nez v5, :cond_46

    .line 1143
    .line 1144
    goto/16 :goto_b

    .line 1145
    .line 1146
    :cond_46
    const/16 v15, 0x11

    .line 1147
    .line 1148
    goto/16 :goto_c

    .line 1149
    .line 1150
    :sswitch_33
    const-string v5, "V_AV1"

    .line 1151
    .line 1152
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1153
    .line 1154
    .line 1155
    move-result v5

    .line 1156
    if-nez v5, :cond_47

    .line 1157
    .line 1158
    goto/16 :goto_b

    .line 1159
    .line 1160
    :cond_47
    const/16 v15, 0x10

    .line 1161
    .line 1162
    goto/16 :goto_c

    .line 1163
    .line 1164
    :sswitch_34
    const-string v5, "A_DTS"

    .line 1165
    .line 1166
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1167
    .line 1168
    .line 1169
    move-result v5

    .line 1170
    if-nez v5, :cond_48

    .line 1171
    .line 1172
    goto/16 :goto_b

    .line 1173
    .line 1174
    :cond_48
    const/16 v15, 0xf

    .line 1175
    .line 1176
    goto/16 :goto_c

    .line 1177
    .line 1178
    :sswitch_35
    const-string v5, "A_AC3"

    .line 1179
    .line 1180
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1181
    .line 1182
    .line 1183
    move-result v5

    .line 1184
    if-nez v5, :cond_49

    .line 1185
    .line 1186
    goto/16 :goto_b

    .line 1187
    .line 1188
    :cond_49
    const/16 v15, 0xe

    .line 1189
    .line 1190
    goto/16 :goto_c

    .line 1191
    .line 1192
    :sswitch_36
    const-string v5, "A_AAC"

    .line 1193
    .line 1194
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1195
    .line 1196
    .line 1197
    move-result v5

    .line 1198
    if-nez v5, :cond_4a

    .line 1199
    .line 1200
    goto/16 :goto_b

    .line 1201
    .line 1202
    :cond_4a
    const/16 v15, 0xd

    .line 1203
    .line 1204
    goto/16 :goto_c

    .line 1205
    .line 1206
    :sswitch_37
    const-string v5, "A_DTS/LOSSLESS"

    .line 1207
    .line 1208
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1209
    .line 1210
    .line 1211
    move-result v5

    .line 1212
    if-nez v5, :cond_4b

    .line 1213
    .line 1214
    goto/16 :goto_b

    .line 1215
    .line 1216
    :cond_4b
    const/16 v15, 0xc

    .line 1217
    .line 1218
    goto/16 :goto_c

    .line 1219
    .line 1220
    :sswitch_38
    const-string v5, "S_VOBSUB"

    .line 1221
    .line 1222
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1223
    .line 1224
    .line 1225
    move-result v5

    .line 1226
    if-nez v5, :cond_4c

    .line 1227
    .line 1228
    goto/16 :goto_b

    .line 1229
    .line 1230
    :cond_4c
    const/16 v15, 0xb

    .line 1231
    .line 1232
    goto/16 :goto_c

    .line 1233
    .line 1234
    :sswitch_39
    const-string v5, "V_MPEG4/ISO/AVC"

    .line 1235
    .line 1236
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1237
    .line 1238
    .line 1239
    move-result v5

    .line 1240
    if-nez v5, :cond_4d

    .line 1241
    .line 1242
    goto/16 :goto_b

    .line 1243
    .line 1244
    :cond_4d
    const/16 v15, 0xa

    .line 1245
    .line 1246
    goto/16 :goto_c

    .line 1247
    .line 1248
    :sswitch_3a
    const-string v5, "V_MPEG4/ISO/ASP"

    .line 1249
    .line 1250
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1251
    .line 1252
    .line 1253
    move-result v5

    .line 1254
    if-nez v5, :cond_4e

    .line 1255
    .line 1256
    goto/16 :goto_b

    .line 1257
    .line 1258
    :cond_4e
    const/16 v15, 0x9

    .line 1259
    .line 1260
    goto/16 :goto_c

    .line 1261
    .line 1262
    :sswitch_3b
    const-string v5, "S_DVBSUB"

    .line 1263
    .line 1264
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1265
    .line 1266
    .line 1267
    move-result v5

    .line 1268
    if-nez v5, :cond_4f

    .line 1269
    .line 1270
    goto/16 :goto_b

    .line 1271
    .line 1272
    :cond_4f
    move/from16 v15, v23

    .line 1273
    .line 1274
    goto :goto_c

    .line 1275
    :sswitch_3c
    const-string v5, "V_MS/VFW/FOURCC"

    .line 1276
    .line 1277
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1278
    .line 1279
    .line 1280
    move-result v5

    .line 1281
    if-nez v5, :cond_50

    .line 1282
    .line 1283
    goto/16 :goto_b

    .line 1284
    .line 1285
    :cond_50
    const/4 v15, 0x7

    .line 1286
    goto :goto_c

    .line 1287
    :sswitch_3d
    invoke-virtual {v1, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1288
    .line 1289
    .line 1290
    move-result v5

    .line 1291
    if-nez v5, :cond_51

    .line 1292
    .line 1293
    goto/16 :goto_b

    .line 1294
    .line 1295
    :cond_51
    const/4 v15, 0x6

    .line 1296
    goto :goto_c

    .line 1297
    :sswitch_3e
    invoke-virtual {v1, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1298
    .line 1299
    .line 1300
    move-result v5

    .line 1301
    if-nez v5, :cond_52

    .line 1302
    .line 1303
    goto/16 :goto_b

    .line 1304
    .line 1305
    :cond_52
    const/4 v15, 0x5

    .line 1306
    goto :goto_c

    .line 1307
    :sswitch_3f
    invoke-virtual {v1, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1308
    .line 1309
    .line 1310
    move-result v5

    .line 1311
    if-nez v5, :cond_53

    .line 1312
    .line 1313
    goto/16 :goto_b

    .line 1314
    .line 1315
    :cond_53
    const/4 v15, 0x4

    .line 1316
    goto :goto_c

    .line 1317
    :sswitch_40
    invoke-virtual {v1, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1318
    .line 1319
    .line 1320
    move-result v5

    .line 1321
    if-nez v5, :cond_54

    .line 1322
    .line 1323
    goto/16 :goto_b

    .line 1324
    .line 1325
    :cond_54
    const/4 v15, 0x3

    .line 1326
    goto :goto_c

    .line 1327
    :sswitch_41
    invoke-virtual {v1, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1328
    .line 1329
    .line 1330
    move-result v5

    .line 1331
    if-nez v5, :cond_55

    .line 1332
    .line 1333
    goto/16 :goto_b

    .line 1334
    .line 1335
    :cond_55
    const/4 v15, 0x2

    .line 1336
    goto :goto_c

    .line 1337
    :sswitch_42
    invoke-virtual {v1, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1338
    .line 1339
    .line 1340
    move-result v5

    .line 1341
    if-nez v5, :cond_56

    .line 1342
    .line 1343
    goto/16 :goto_b

    .line 1344
    .line 1345
    :cond_56
    const/4 v15, 0x1

    .line 1346
    goto :goto_c

    .line 1347
    :sswitch_43
    invoke-virtual {v1, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1348
    .line 1349
    .line 1350
    move-result v5

    .line 1351
    if-nez v5, :cond_57

    .line 1352
    .line 1353
    goto/16 :goto_b

    .line 1354
    .line 1355
    :cond_57
    const/4 v15, 0x0

    .line 1356
    :goto_c
    const-string v6, "application/dvbsubs"

    .line 1357
    .line 1358
    const-string v8, "application/vobsub"

    .line 1359
    .line 1360
    const-string v10, "application/pgs"

    .line 1361
    .line 1362
    const-string v11, "video/x-unknown"

    .line 1363
    .line 1364
    const-string v12, "text/x-ssa"

    .line 1365
    .line 1366
    const-string v13, "text/vtt"

    .line 1367
    .line 1368
    const-string v5, "application/x-subrip"

    .line 1369
    .line 1370
    move/from16 v34, v9

    .line 1371
    .line 1372
    const-string v9, ". Setting mimeType to audio/x-unknown"

    .line 1373
    .line 1374
    const-string v35, "audio/raw"

    .line 1375
    .line 1376
    const-string v36, "audio/x-unknown"

    .line 1377
    .line 1378
    packed-switch v15, :pswitch_data_1

    .line 1379
    .line 1380
    .line 1381
    const-string v0, "Unrecognized codec identifier."

    .line 1382
    .line 1383
    const/4 v1, 0x0

    .line 1384
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 1385
    .line 1386
    .line 1387
    move-result-object v0

    .line 1388
    throw v0

    .line 1389
    :pswitch_1
    new-instance v1, Ljava/util/ArrayList;

    .line 1390
    .line 1391
    const/4 v9, 0x3

    .line 1392
    invoke-direct {v1, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 1393
    .line 1394
    .line 1395
    iget-object v9, v0, Lg9/c;->c:Ljava/lang/String;

    .line 1396
    .line 1397
    invoke-virtual {v0, v9}, Lg9/c;->a(Ljava/lang/String;)[B

    .line 1398
    .line 1399
    .line 1400
    move-result-object v9

    .line 1401
    invoke-virtual {v1, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1402
    .line 1403
    .line 1404
    invoke-static/range {v23 .. v23}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 1405
    .line 1406
    .line 1407
    move-result-object v9

    .line 1408
    sget-object v11, Ljava/nio/ByteOrder;->LITTLE_ENDIAN:Ljava/nio/ByteOrder;

    .line 1409
    .line 1410
    invoke-virtual {v9, v11}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 1411
    .line 1412
    .line 1413
    move-result-object v9

    .line 1414
    iget-wide v14, v0, Lg9/c;->T:J

    .line 1415
    .line 1416
    invoke-virtual {v9, v14, v15}, Ljava/nio/ByteBuffer;->putLong(J)Ljava/nio/ByteBuffer;

    .line 1417
    .line 1418
    .line 1419
    move-result-object v9

    .line 1420
    invoke-virtual {v9}, Ljava/nio/ByteBuffer;->array()[B

    .line 1421
    .line 1422
    .line 1423
    move-result-object v9

    .line 1424
    invoke-virtual {v1, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1425
    .line 1426
    .line 1427
    invoke-static/range {v23 .. v23}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 1428
    .line 1429
    .line 1430
    move-result-object v9

    .line 1431
    invoke-virtual {v9, v11}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 1432
    .line 1433
    .line 1434
    move-result-object v9

    .line 1435
    iget-wide v14, v0, Lg9/c;->U:J

    .line 1436
    .line 1437
    invoke-virtual {v9, v14, v15}, Ljava/nio/ByteBuffer;->putLong(J)Ljava/nio/ByteBuffer;

    .line 1438
    .line 1439
    .line 1440
    move-result-object v9

    .line 1441
    invoke-virtual {v9}, Ljava/nio/ByteBuffer;->array()[B

    .line 1442
    .line 1443
    .line 1444
    move-result-object v9

    .line 1445
    invoke-virtual {v1, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1446
    .line 1447
    .line 1448
    const-string v11, "audio/opus"

    .line 1449
    .line 1450
    const/16 v9, 0x1680

    .line 1451
    .line 1452
    move-object/from16 v29, v4

    .line 1453
    .line 1454
    move v4, v9

    .line 1455
    const/4 v2, 0x0

    .line 1456
    :goto_d
    move-object v9, v1

    .line 1457
    const/4 v1, -0x1

    .line 1458
    goto/16 :goto_26

    .line 1459
    .line 1460
    :pswitch_2
    invoke-virtual {v0, v1}, Lg9/c;->a(Ljava/lang/String;)[B

    .line 1461
    .line 1462
    .line 1463
    move-result-object v1

    .line 1464
    invoke-static {v1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 1465
    .line 1466
    .line 1467
    move-result-object v1

    .line 1468
    const-string v11, "audio/flac"

    .line 1469
    .line 1470
    :goto_e
    move-object v9, v1

    .line 1471
    move-object/from16 v29, v4

    .line 1472
    .line 1473
    :goto_f
    const/4 v1, -0x1

    .line 1474
    const/4 v2, 0x0

    .line 1475
    :goto_10
    const/4 v4, -0x1

    .line 1476
    goto/16 :goto_26

    .line 1477
    .line 1478
    :pswitch_3
    const-string v11, "audio/eac3"

    .line 1479
    .line 1480
    :goto_11
    :pswitch_4
    move-object/from16 v29, v4

    .line 1481
    .line 1482
    :goto_12
    const/4 v1, -0x1

    .line 1483
    :goto_13
    const/4 v2, 0x0

    .line 1484
    const/4 v4, -0x1

    .line 1485
    :goto_14
    const/4 v9, 0x0

    .line 1486
    goto/16 :goto_26

    .line 1487
    .line 1488
    :pswitch_5
    const-string v11, "video/mpeg2"

    .line 1489
    .line 1490
    goto :goto_11

    .line 1491
    :pswitch_6
    move-object/from16 v29, v4

    .line 1492
    .line 1493
    move-object v11, v5

    .line 1494
    goto :goto_12

    .line 1495
    :pswitch_7
    move-object/from16 v29, v4

    .line 1496
    .line 1497
    move-object v11, v13

    .line 1498
    goto :goto_12

    .line 1499
    :pswitch_8
    new-instance v1, Lw7/p;

    .line 1500
    .line 1501
    iget-object v9, v0, Lg9/c;->c:Ljava/lang/String;

    .line 1502
    .line 1503
    invoke-virtual {v0, v9}, Lg9/c;->a(Ljava/lang/String;)[B

    .line 1504
    .line 1505
    .line 1506
    move-result-object v9

    .line 1507
    invoke-direct {v1, v9}, Lw7/p;-><init>([B)V

    .line 1508
    .line 1509
    .line 1510
    const/4 v9, 0x0

    .line 1511
    const/4 v11, 0x0

    .line 1512
    invoke-static {v1, v9, v11}, Lo8/x;->a(Lw7/p;ZLun/a;)Lo8/x;

    .line 1513
    .line 1514
    .line 1515
    move-result-object v1

    .line 1516
    iget-object v9, v1, Lo8/x;->a:Ljava/util/List;

    .line 1517
    .line 1518
    iget v11, v1, Lo8/x;->b:I

    .line 1519
    .line 1520
    iput v11, v0, Lg9/c;->a0:I

    .line 1521
    .line 1522
    iget-object v1, v1, Lo8/x;->n:Ljava/lang/String;

    .line 1523
    .line 1524
    const-string v11, "video/hevc"

    .line 1525
    .line 1526
    :goto_15
    move-object v2, v1

    .line 1527
    move-object/from16 v29, v4

    .line 1528
    .line 1529
    :goto_16
    const/4 v1, -0x1

    .line 1530
    goto :goto_10

    .line 1531
    :pswitch_9
    sget-object v9, Lg9/d;->g0:[B

    .line 1532
    .line 1533
    invoke-virtual {v0, v1}, Lg9/c;->a(Ljava/lang/String;)[B

    .line 1534
    .line 1535
    .line 1536
    move-result-object v1

    .line 1537
    invoke-static {v9, v1}, Lhr/h0;->v(Ljava/lang/Object;Ljava/lang/Object;)Lhr/x0;

    .line 1538
    .line 1539
    .line 1540
    move-result-object v1

    .line 1541
    move-object v9, v1

    .line 1542
    move-object/from16 v29, v4

    .line 1543
    .line 1544
    move-object v11, v12

    .line 1545
    goto :goto_f

    .line 1546
    :pswitch_a
    iget v1, v0, Lg9/c;->R:I

    .line 1547
    .line 1548
    sget-object v11, Lw7/w;->a:Ljava/lang/String;

    .line 1549
    .line 1550
    sget-object v11, Ljava/nio/ByteOrder;->LITTLE_ENDIAN:Ljava/nio/ByteOrder;

    .line 1551
    .line 1552
    invoke-static {v1, v11}, Lw7/w;->s(ILjava/nio/ByteOrder;)I

    .line 1553
    .line 1554
    .line 1555
    move-result v1

    .line 1556
    if-nez v1, :cond_58

    .line 1557
    .line 1558
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1559
    .line 1560
    const-string v11, "Unsupported little endian PCM bit depth: "

    .line 1561
    .line 1562
    invoke-direct {v1, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1563
    .line 1564
    .line 1565
    iget v11, v0, Lg9/c;->R:I

    .line 1566
    .line 1567
    invoke-virtual {v1, v11}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1568
    .line 1569
    .line 1570
    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1571
    .line 1572
    .line 1573
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1574
    .line 1575
    .line 1576
    move-result-object v1

    .line 1577
    invoke-static {v14, v1}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 1578
    .line 1579
    .line 1580
    :goto_17
    move-object/from16 v29, v4

    .line 1581
    .line 1582
    :goto_18
    move-object/from16 v11, v36

    .line 1583
    .line 1584
    goto :goto_12

    .line 1585
    :cond_58
    :goto_19
    move-object/from16 v29, v4

    .line 1586
    .line 1587
    :cond_59
    move-object/from16 v11, v35

    .line 1588
    .line 1589
    goto :goto_13

    .line 1590
    :pswitch_b
    iget v1, v0, Lg9/c;->R:I

    .line 1591
    .line 1592
    move/from16 v11, v23

    .line 1593
    .line 1594
    if-ne v1, v11, :cond_5a

    .line 1595
    .line 1596
    move-object/from16 v29, v4

    .line 1597
    .line 1598
    move-object/from16 v11, v35

    .line 1599
    .line 1600
    const/4 v1, 0x3

    .line 1601
    goto :goto_13

    .line 1602
    :cond_5a
    const/16 v11, 0x10

    .line 1603
    .line 1604
    if-ne v1, v11, :cond_5b

    .line 1605
    .line 1606
    const/high16 v1, 0x10000000

    .line 1607
    .line 1608
    goto :goto_19

    .line 1609
    :cond_5b
    const/16 v11, 0x18

    .line 1610
    .line 1611
    if-ne v1, v11, :cond_5c

    .line 1612
    .line 1613
    const/high16 v1, 0x50000000

    .line 1614
    .line 1615
    goto :goto_19

    .line 1616
    :cond_5c
    const/16 v11, 0x20

    .line 1617
    .line 1618
    if-ne v1, v11, :cond_5d

    .line 1619
    .line 1620
    const/high16 v1, 0x60000000

    .line 1621
    .line 1622
    goto :goto_19

    .line 1623
    :cond_5d
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1624
    .line 1625
    const-string v11, "Unsupported big endian PCM bit depth: "

    .line 1626
    .line 1627
    invoke-direct {v1, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1628
    .line 1629
    .line 1630
    iget v11, v0, Lg9/c;->R:I

    .line 1631
    .line 1632
    invoke-virtual {v1, v11}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1633
    .line 1634
    .line 1635
    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1636
    .line 1637
    .line 1638
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1639
    .line 1640
    .line 1641
    move-result-object v1

    .line 1642
    invoke-static {v14, v1}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 1643
    .line 1644
    .line 1645
    goto :goto_17

    .line 1646
    :pswitch_c
    iget v1, v0, Lg9/c;->R:I

    .line 1647
    .line 1648
    const/16 v11, 0x20

    .line 1649
    .line 1650
    if-ne v1, v11, :cond_5e

    .line 1651
    .line 1652
    move-object/from16 v29, v4

    .line 1653
    .line 1654
    move-object/from16 v11, v35

    .line 1655
    .line 1656
    const/4 v1, 0x4

    .line 1657
    goto/16 :goto_13

    .line 1658
    .line 1659
    :cond_5e
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1660
    .line 1661
    const-string v11, "Unsupported floating point PCM bit depth: "

    .line 1662
    .line 1663
    invoke-direct {v1, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1664
    .line 1665
    .line 1666
    iget v11, v0, Lg9/c;->R:I

    .line 1667
    .line 1668
    invoke-virtual {v1, v11}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1669
    .line 1670
    .line 1671
    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1672
    .line 1673
    .line 1674
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1675
    .line 1676
    .line 1677
    move-result-object v1

    .line 1678
    invoke-static {v14, v1}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 1679
    .line 1680
    .line 1681
    goto :goto_17

    .line 1682
    :pswitch_d
    move-object/from16 v29, v4

    .line 1683
    .line 1684
    move-object v11, v10

    .line 1685
    goto/16 :goto_12

    .line 1686
    .line 1687
    :pswitch_e
    iget-object v1, v0, Lg9/c;->l:[B

    .line 1688
    .line 1689
    if-nez v1, :cond_5f

    .line 1690
    .line 1691
    const/4 v1, 0x0

    .line 1692
    goto :goto_1a

    .line 1693
    :cond_5f
    invoke-static {v1}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 1694
    .line 1695
    .line 1696
    move-result-object v1

    .line 1697
    :goto_1a
    const-string v11, "video/x-vnd.on2.vp9"

    .line 1698
    .line 1699
    goto/16 :goto_e

    .line 1700
    .line 1701
    :pswitch_f
    const-string v11, "video/x-vnd.on2.vp8"

    .line 1702
    .line 1703
    goto/16 :goto_11

    .line 1704
    .line 1705
    :pswitch_10
    iget-object v1, v0, Lg9/c;->l:[B

    .line 1706
    .line 1707
    if-nez v1, :cond_60

    .line 1708
    .line 1709
    const/4 v1, 0x0

    .line 1710
    goto :goto_1b

    .line 1711
    :cond_60
    invoke-static {v1}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 1712
    .line 1713
    .line 1714
    move-result-object v1

    .line 1715
    :goto_1b
    const-string v11, "video/av01"

    .line 1716
    .line 1717
    goto/16 :goto_e

    .line 1718
    .line 1719
    :pswitch_11
    const-string v11, "audio/vnd.dts"

    .line 1720
    .line 1721
    goto/16 :goto_11

    .line 1722
    .line 1723
    :pswitch_12
    const-string v11, "audio/ac3"

    .line 1724
    .line 1725
    goto/16 :goto_11

    .line 1726
    .line 1727
    :pswitch_13
    invoke-virtual {v0, v1}, Lg9/c;->a(Ljava/lang/String;)[B

    .line 1728
    .line 1729
    .line 1730
    move-result-object v1

    .line 1731
    invoke-static {v1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 1732
    .line 1733
    .line 1734
    move-result-object v1

    .line 1735
    iget-object v9, v0, Lg9/c;->l:[B

    .line 1736
    .line 1737
    new-instance v11, Lm9/f;

    .line 1738
    .line 1739
    array-length v14, v9

    .line 1740
    invoke-direct {v11, v14, v9}, Lm9/f;-><init>(I[B)V

    .line 1741
    .line 1742
    .line 1743
    const/4 v9, 0x0

    .line 1744
    invoke-static {v11, v9}, Lo8/b;->n(Lm9/f;Z)Lo8/a;

    .line 1745
    .line 1746
    .line 1747
    move-result-object v11

    .line 1748
    iget v9, v11, Lo8/a;->b:I

    .line 1749
    .line 1750
    iput v9, v0, Lg9/c;->S:I

    .line 1751
    .line 1752
    iget v9, v11, Lo8/a;->c:I

    .line 1753
    .line 1754
    iput v9, v0, Lg9/c;->Q:I

    .line 1755
    .line 1756
    iget-object v9, v11, Lo8/a;->a:Ljava/lang/String;

    .line 1757
    .line 1758
    const-string v11, "audio/mp4a-latm"

    .line 1759
    .line 1760
    move-object/from16 v29, v4

    .line 1761
    .line 1762
    move-object v2, v9

    .line 1763
    const/4 v4, -0x1

    .line 1764
    goto/16 :goto_d

    .line 1765
    .line 1766
    :pswitch_14
    const-string v11, "audio/vnd.dts.hd"

    .line 1767
    .line 1768
    goto/16 :goto_11

    .line 1769
    .line 1770
    :pswitch_15
    invoke-virtual {v0, v1}, Lg9/c;->a(Ljava/lang/String;)[B

    .line 1771
    .line 1772
    .line 1773
    move-result-object v1

    .line 1774
    invoke-static {v1}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 1775
    .line 1776
    .line 1777
    move-result-object v1

    .line 1778
    move-object v9, v1

    .line 1779
    move-object/from16 v29, v4

    .line 1780
    .line 1781
    move-object v11, v8

    .line 1782
    goto/16 :goto_f

    .line 1783
    .line 1784
    :pswitch_16
    new-instance v1, Lw7/p;

    .line 1785
    .line 1786
    iget-object v9, v0, Lg9/c;->c:Ljava/lang/String;

    .line 1787
    .line 1788
    invoke-virtual {v0, v9}, Lg9/c;->a(Ljava/lang/String;)[B

    .line 1789
    .line 1790
    .line 1791
    move-result-object v9

    .line 1792
    invoke-direct {v1, v9}, Lw7/p;-><init>([B)V

    .line 1793
    .line 1794
    .line 1795
    invoke-static {v1}, Lo8/d;->a(Lw7/p;)Lo8/d;

    .line 1796
    .line 1797
    .line 1798
    move-result-object v1

    .line 1799
    iget-object v9, v1, Lo8/d;->a:Ljava/util/ArrayList;

    .line 1800
    .line 1801
    iget v11, v1, Lo8/d;->b:I

    .line 1802
    .line 1803
    iput v11, v0, Lg9/c;->a0:I

    .line 1804
    .line 1805
    iget-object v1, v1, Lo8/d;->l:Ljava/lang/String;

    .line 1806
    .line 1807
    const-string v11, "video/avc"

    .line 1808
    .line 1809
    goto/16 :goto_15

    .line 1810
    .line 1811
    :pswitch_17
    const/4 v15, 0x4

    .line 1812
    new-array v9, v15, [B

    .line 1813
    .line 1814
    invoke-virtual {v0, v1}, Lg9/c;->a(Ljava/lang/String;)[B

    .line 1815
    .line 1816
    .line 1817
    move-result-object v1

    .line 1818
    const/4 v11, 0x0

    .line 1819
    invoke-static {v1, v11, v9, v11, v15}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 1820
    .line 1821
    .line 1822
    invoke-static {v9}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 1823
    .line 1824
    .line 1825
    move-result-object v1

    .line 1826
    move-object v9, v1

    .line 1827
    move-object/from16 v29, v4

    .line 1828
    .line 1829
    move-object v11, v6

    .line 1830
    goto/16 :goto_f

    .line 1831
    .line 1832
    :pswitch_18
    new-instance v1, Lw7/p;

    .line 1833
    .line 1834
    iget-object v9, v0, Lg9/c;->c:Ljava/lang/String;

    .line 1835
    .line 1836
    invoke-virtual {v0, v9}, Lg9/c;->a(Ljava/lang/String;)[B

    .line 1837
    .line 1838
    .line 1839
    move-result-object v9

    .line 1840
    invoke-direct {v1, v9}, Lw7/p;-><init>([B)V

    .line 1841
    .line 1842
    .line 1843
    const/16 v9, 0x10

    .line 1844
    .line 1845
    :try_start_0
    invoke-virtual {v1, v9}, Lw7/p;->J(I)V

    .line 1846
    .line 1847
    .line 1848
    invoke-virtual {v1}, Lw7/p;->n()J

    .line 1849
    .line 1850
    .line 1851
    move-result-wide v18

    .line 1852
    const-wide/32 v22, 0x58564944

    .line 1853
    .line 1854
    .line 1855
    cmp-long v9, v18, v22

    .line 1856
    .line 1857
    if-nez v9, :cond_61

    .line 1858
    .line 1859
    new-instance v1, Landroid/util/Pair;

    .line 1860
    .line 1861
    const-string v9, "video/divx"
    :try_end_0
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_1

    .line 1862
    .line 1863
    const/4 v11, 0x0

    .line 1864
    :try_start_1
    invoke-direct {v1, v9, v11}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_1 .. :try_end_1} :catch_0

    .line 1865
    .line 1866
    .line 1867
    :goto_1c
    const/4 v9, 0x0

    .line 1868
    goto/16 :goto_1e

    .line 1869
    .line 1870
    :catch_0
    move-object v9, v11

    .line 1871
    goto/16 :goto_1f

    .line 1872
    .line 1873
    :catch_1
    const/4 v9, 0x0

    .line 1874
    goto/16 :goto_1f

    .line 1875
    .line 1876
    :cond_61
    const-wide/32 v22, 0x33363248

    .line 1877
    .line 1878
    .line 1879
    cmp-long v9, v18, v22

    .line 1880
    .line 1881
    if-nez v9, :cond_62

    .line 1882
    .line 1883
    :try_start_2
    new-instance v1, Landroid/util/Pair;

    .line 1884
    .line 1885
    const-string v9, "video/3gpp"
    :try_end_2
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_2 .. :try_end_2} :catch_1

    .line 1886
    .line 1887
    const/4 v11, 0x0

    .line 1888
    :try_start_3
    invoke-direct {v1, v9, v11}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_3
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_3 .. :try_end_3} :catch_0

    .line 1889
    .line 1890
    .line 1891
    goto :goto_1c

    .line 1892
    :cond_62
    const-wide/32 v22, 0x31435657

    .line 1893
    .line 1894
    .line 1895
    cmp-long v9, v18, v22

    .line 1896
    .line 1897
    if-nez v9, :cond_66

    .line 1898
    .line 1899
    :try_start_4
    iget v9, v1, Lw7/p;->b:I

    .line 1900
    .line 1901
    add-int/lit8 v9, v9, 0x14

    .line 1902
    .line 1903
    iget-object v1, v1, Lw7/p;->a:[B

    .line 1904
    .line 1905
    :goto_1d
    array-length v11, v1

    .line 1906
    const/4 v15, 0x4

    .line 1907
    sub-int/2addr v11, v15

    .line 1908
    if-ge v9, v11, :cond_65

    .line 1909
    .line 1910
    aget-byte v11, v1, v9

    .line 1911
    .line 1912
    if-nez v11, :cond_63

    .line 1913
    .line 1914
    add-int/lit8 v11, v9, 0x1

    .line 1915
    .line 1916
    aget-byte v11, v1, v11

    .line 1917
    .line 1918
    if-nez v11, :cond_63

    .line 1919
    .line 1920
    add-int/lit8 v11, v9, 0x2

    .line 1921
    .line 1922
    aget-byte v11, v1, v11

    .line 1923
    .line 1924
    const/4 v14, 0x1

    .line 1925
    if-ne v11, v14, :cond_63

    .line 1926
    .line 1927
    add-int/lit8 v11, v9, 0x3

    .line 1928
    .line 1929
    aget-byte v11, v1, v11

    .line 1930
    .line 1931
    const/16 v14, 0xf

    .line 1932
    .line 1933
    if-ne v11, v14, :cond_64

    .line 1934
    .line 1935
    array-length v11, v1

    .line 1936
    invoke-static {v1, v9, v11}, Ljava/util/Arrays;->copyOfRange([BII)[B

    .line 1937
    .line 1938
    .line 1939
    move-result-object v1

    .line 1940
    new-instance v9, Landroid/util/Pair;

    .line 1941
    .line 1942
    const-string v11, "video/wvc1"

    .line 1943
    .line 1944
    invoke-static {v1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 1945
    .line 1946
    .line 1947
    move-result-object v1

    .line 1948
    invoke-direct {v9, v11, v1}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1949
    .line 1950
    .line 1951
    move-object v1, v9

    .line 1952
    goto :goto_1c

    .line 1953
    :cond_63
    const/16 v14, 0xf

    .line 1954
    .line 1955
    :cond_64
    add-int/lit8 v9, v9, 0x1

    .line 1956
    .line 1957
    goto :goto_1d

    .line 1958
    :cond_65
    const-string v0, "Failed to find FourCC VC1 initialization data"
    :try_end_4
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_4 .. :try_end_4} :catch_1

    .line 1959
    .line 1960
    const/4 v1, 0x0

    .line 1961
    :try_start_5
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 1962
    .line 1963
    .line 1964
    move-result-object v0
    :try_end_5
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_5 .. :try_end_5} :catch_2

    .line 1965
    :try_start_6
    throw v0
    :try_end_6
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_6 .. :try_end_6} :catch_1

    .line 1966
    :catch_2
    move-object v9, v1

    .line 1967
    goto :goto_1f

    .line 1968
    :cond_66
    const-string v1, "Unknown FourCC. Setting mimeType to video/x-unknown"

    .line 1969
    .line 1970
    invoke-static {v14, v1}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 1971
    .line 1972
    .line 1973
    new-instance v1, Landroid/util/Pair;

    .line 1974
    .line 1975
    const/4 v9, 0x0

    .line 1976
    invoke-direct {v1, v11, v9}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1977
    .line 1978
    .line 1979
    :goto_1e
    iget-object v11, v1, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 1980
    .line 1981
    check-cast v11, Ljava/lang/String;

    .line 1982
    .line 1983
    iget-object v1, v1, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 1984
    .line 1985
    move-object/from16 v26, v1

    .line 1986
    .line 1987
    check-cast v26, Ljava/util/List;

    .line 1988
    .line 1989
    move-object/from16 v29, v4

    .line 1990
    .line 1991
    move-object v2, v9

    .line 1992
    move-object/from16 v9, v26

    .line 1993
    .line 1994
    goto/16 :goto_16

    .line 1995
    .line 1996
    :goto_1f
    const-string v0, "Error parsing FourCC private data"

    .line 1997
    .line 1998
    invoke-static {v9, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 1999
    .line 2000
    .line 2001
    move-result-object v0

    .line 2002
    throw v0

    .line 2003
    :pswitch_19
    const-string v11, "audio/mpeg"

    .line 2004
    .line 2005
    :goto_20
    move-object/from16 v29, v4

    .line 2006
    .line 2007
    const/4 v1, -0x1

    .line 2008
    const/4 v2, 0x0

    .line 2009
    const/16 v4, 0x1000

    .line 2010
    .line 2011
    goto/16 :goto_14

    .line 2012
    .line 2013
    :pswitch_1a
    const-string v11, "audio/mpeg-L2"

    .line 2014
    .line 2015
    goto :goto_20

    .line 2016
    :pswitch_1b
    invoke-virtual {v0, v1}, Lg9/c;->a(Ljava/lang/String;)[B

    .line 2017
    .line 2018
    .line 2019
    move-result-object v1

    .line 2020
    const-string v9, "Error parsing vorbis codec private"

    .line 2021
    .line 2022
    const/16 v24, 0x0

    .line 2023
    .line 2024
    :try_start_7
    aget-byte v11, v1, v24

    .line 2025
    .line 2026
    const/4 v14, 0x2

    .line 2027
    if-ne v11, v14, :cond_6c

    .line 2028
    .line 2029
    const/4 v11, 0x0

    .line 2030
    const/4 v14, 0x1

    .line 2031
    :goto_21
    aget-byte v15, v1, v14

    .line 2032
    .line 2033
    move/from16 v17, v14

    .line 2034
    .line 2035
    const/16 v14, 0xff

    .line 2036
    .line 2037
    and-int/2addr v15, v14

    .line 2038
    if-ne v15, v14, :cond_67

    .line 2039
    .line 2040
    add-int/lit16 v11, v11, 0xff

    .line 2041
    .line 2042
    add-int/lit8 v14, v17, 0x1

    .line 2043
    .line 2044
    goto :goto_21

    .line 2045
    :cond_67
    add-int/lit8 v17, v17, 0x1

    .line 2046
    .line 2047
    add-int/2addr v11, v15

    .line 2048
    const/4 v15, 0x0

    .line 2049
    :goto_22
    aget-byte v2, v1, v17

    .line 2050
    .line 2051
    and-int/2addr v2, v14

    .line 2052
    if-ne v2, v14, :cond_68

    .line 2053
    .line 2054
    add-int/lit16 v15, v15, 0xff

    .line 2055
    .line 2056
    add-int/lit8 v17, v17, 0x1

    .line 2057
    .line 2058
    goto :goto_22

    .line 2059
    :cond_68
    add-int/lit8 v14, v17, 0x1

    .line 2060
    .line 2061
    add-int/2addr v15, v2

    .line 2062
    aget-byte v2, v1, v14

    .line 2063
    .line 2064
    move/from16 v17, v15

    .line 2065
    .line 2066
    const/4 v15, 0x1

    .line 2067
    if-ne v2, v15, :cond_6b

    .line 2068
    .line 2069
    new-array v2, v11, [B

    .line 2070
    .line 2071
    const/4 v15, 0x0

    .line 2072
    invoke-static {v1, v14, v2, v15, v11}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 2073
    .line 2074
    .line 2075
    add-int/2addr v14, v11

    .line 2076
    aget-byte v11, v1, v14

    .line 2077
    .line 2078
    const/4 v15, 0x3

    .line 2079
    if-ne v11, v15, :cond_6a

    .line 2080
    .line 2081
    add-int v14, v14, v17

    .line 2082
    .line 2083
    aget-byte v11, v1, v14

    .line 2084
    .line 2085
    const/4 v15, 0x5

    .line 2086
    if-ne v11, v15, :cond_69

    .line 2087
    .line 2088
    array-length v11, v1

    .line 2089
    sub-int/2addr v11, v14

    .line 2090
    new-array v11, v11, [B

    .line 2091
    .line 2092
    array-length v15, v1

    .line 2093
    sub-int/2addr v15, v14

    .line 2094
    move-object/from16 v29, v4

    .line 2095
    .line 2096
    const/4 v4, 0x0

    .line 2097
    invoke-static {v1, v14, v11, v4, v15}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 2098
    .line 2099
    .line 2100
    new-instance v1, Ljava/util/ArrayList;

    .line 2101
    .line 2102
    const/4 v14, 0x2

    .line 2103
    invoke-direct {v1, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 2104
    .line 2105
    .line 2106
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2107
    .line 2108
    .line 2109
    invoke-virtual {v1, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_7
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_7 .. :try_end_7} :catch_3

    .line 2110
    .line 2111
    .line 2112
    const-string v11, "audio/vorbis"

    .line 2113
    .line 2114
    const/16 v2, 0x2000

    .line 2115
    .line 2116
    move-object v9, v1

    .line 2117
    move v4, v2

    .line 2118
    const/4 v1, -0x1

    .line 2119
    const/4 v2, 0x0

    .line 2120
    goto/16 :goto_26

    .line 2121
    .line 2122
    :catch_3
    const/4 v1, 0x0

    .line 2123
    goto :goto_23

    .line 2124
    :cond_69
    const/4 v1, 0x0

    .line 2125
    :try_start_8
    invoke-static {v1, v9}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 2126
    .line 2127
    .line 2128
    move-result-object v0

    .line 2129
    throw v0

    .line 2130
    :cond_6a
    const/4 v1, 0x0

    .line 2131
    invoke-static {v1, v9}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 2132
    .line 2133
    .line 2134
    move-result-object v0

    .line 2135
    throw v0

    .line 2136
    :cond_6b
    const/4 v1, 0x0

    .line 2137
    invoke-static {v1, v9}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 2138
    .line 2139
    .line 2140
    move-result-object v0

    .line 2141
    throw v0

    .line 2142
    :cond_6c
    const/4 v1, 0x0

    .line 2143
    invoke-static {v1, v9}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 2144
    .line 2145
    .line 2146
    move-result-object v0

    .line 2147
    throw v0
    :try_end_8
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_8 .. :try_end_8} :catch_4

    .line 2148
    :catch_4
    :goto_23
    invoke-static {v1, v9}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 2149
    .line 2150
    .line 2151
    move-result-object v0

    .line 2152
    throw v0

    .line 2153
    :pswitch_1c
    move-object/from16 v29, v4

    .line 2154
    .line 2155
    new-instance v1, Lo8/j0;

    .line 2156
    .line 2157
    invoke-direct {v1}, Lo8/j0;-><init>()V

    .line 2158
    .line 2159
    .line 2160
    iput-object v1, v0, Lg9/c;->V:Lo8/j0;

    .line 2161
    .line 2162
    const-string v11, "audio/true-hd"

    .line 2163
    .line 2164
    goto/16 :goto_12

    .line 2165
    .line 2166
    :pswitch_1d
    move-object/from16 v29, v4

    .line 2167
    .line 2168
    new-instance v1, Lw7/p;

    .line 2169
    .line 2170
    iget-object v2, v0, Lg9/c;->c:Ljava/lang/String;

    .line 2171
    .line 2172
    invoke-virtual {v0, v2}, Lg9/c;->a(Ljava/lang/String;)[B

    .line 2173
    .line 2174
    .line 2175
    move-result-object v2

    .line 2176
    invoke-direct {v1, v2}, Lw7/p;-><init>([B)V

    .line 2177
    .line 2178
    .line 2179
    :try_start_9
    invoke-virtual {v1}, Lw7/p;->p()I

    .line 2180
    .line 2181
    .line 2182
    move-result v2

    .line 2183
    const/4 v15, 0x1

    .line 2184
    if-ne v2, v15, :cond_6d

    .line 2185
    .line 2186
    goto :goto_24

    .line 2187
    :cond_6d
    const v4, 0xfffe

    .line 2188
    .line 2189
    .line 2190
    if-ne v2, v4, :cond_6e

    .line 2191
    .line 2192
    const/16 v11, 0x18

    .line 2193
    .line 2194
    invoke-virtual {v1, v11}, Lw7/p;->I(I)V

    .line 2195
    .line 2196
    .line 2197
    invoke-virtual {v1}, Lw7/p;->q()J

    .line 2198
    .line 2199
    .line 2200
    move-result-wide v17

    .line 2201
    sget-object v2, Lg9/d;->j0:Ljava/util/UUID;

    .line 2202
    .line 2203
    invoke-virtual {v2}, Ljava/util/UUID;->getMostSignificantBits()J

    .line 2204
    .line 2205
    .line 2206
    move-result-wide v22

    .line 2207
    cmp-long v4, v17, v22

    .line 2208
    .line 2209
    if-nez v4, :cond_6e

    .line 2210
    .line 2211
    invoke-virtual {v1}, Lw7/p;->q()J

    .line 2212
    .line 2213
    .line 2214
    move-result-wide v17

    .line 2215
    invoke-virtual {v2}, Ljava/util/UUID;->getLeastSignificantBits()J

    .line 2216
    .line 2217
    .line 2218
    move-result-wide v1
    :try_end_9
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_9 .. :try_end_9} :catch_5

    .line 2219
    cmp-long v1, v17, v1

    .line 2220
    .line 2221
    if-nez v1, :cond_6e

    .line 2222
    .line 2223
    :goto_24
    iget v1, v0, Lg9/c;->R:I

    .line 2224
    .line 2225
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 2226
    .line 2227
    sget-object v2, Ljava/nio/ByteOrder;->LITTLE_ENDIAN:Ljava/nio/ByteOrder;

    .line 2228
    .line 2229
    invoke-static {v1, v2}, Lw7/w;->s(ILjava/nio/ByteOrder;)I

    .line 2230
    .line 2231
    .line 2232
    move-result v1

    .line 2233
    if-nez v1, :cond_59

    .line 2234
    .line 2235
    new-instance v1, Ljava/lang/StringBuilder;

    .line 2236
    .line 2237
    const-string v2, "Unsupported PCM bit depth: "

    .line 2238
    .line 2239
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 2240
    .line 2241
    .line 2242
    iget v2, v0, Lg9/c;->R:I

    .line 2243
    .line 2244
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 2245
    .line 2246
    .line 2247
    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2248
    .line 2249
    .line 2250
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 2251
    .line 2252
    .line 2253
    move-result-object v1

    .line 2254
    invoke-static {v14, v1}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 2255
    .line 2256
    .line 2257
    goto/16 :goto_18

    .line 2258
    .line 2259
    :cond_6e
    const-string v1, "Non-PCM MS/ACM is unsupported. Setting mimeType to audio/x-unknown"

    .line 2260
    .line 2261
    invoke-static {v14, v1}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 2262
    .line 2263
    .line 2264
    goto/16 :goto_18

    .line 2265
    .line 2266
    :catch_5
    const-string v0, "Error parsing MS/ACM codec private"

    .line 2267
    .line 2268
    const/4 v1, 0x0

    .line 2269
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 2270
    .line 2271
    .line 2272
    move-result-object v0

    .line 2273
    throw v0

    .line 2274
    :pswitch_1e
    move-object/from16 v29, v4

    .line 2275
    .line 2276
    iget-object v1, v0, Lg9/c;->l:[B

    .line 2277
    .line 2278
    if-nez v1, :cond_6f

    .line 2279
    .line 2280
    const/4 v1, 0x0

    .line 2281
    goto :goto_25

    .line 2282
    :cond_6f
    invoke-static {v1}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 2283
    .line 2284
    .line 2285
    move-result-object v1

    .line 2286
    :goto_25
    const-string v11, "video/mp4v-es"

    .line 2287
    .line 2288
    move-object v9, v1

    .line 2289
    goto/16 :goto_f

    .line 2290
    .line 2291
    :goto_26
    iget-object v14, v0, Lg9/c;->P:[B

    .line 2292
    .line 2293
    if-eqz v14, :cond_70

    .line 2294
    .line 2295
    new-instance v14, Lw7/p;

    .line 2296
    .line 2297
    iget-object v15, v0, Lg9/c;->P:[B

    .line 2298
    .line 2299
    invoke-direct {v14, v15}, Lw7/p;-><init>([B)V

    .line 2300
    .line 2301
    .line 2302
    invoke-static {v14}, Lgr/f;->b(Lw7/p;)Lgr/f;

    .line 2303
    .line 2304
    .line 2305
    move-result-object v14

    .line 2306
    if-eqz v14, :cond_70

    .line 2307
    .line 2308
    iget-object v2, v14, Lgr/f;->a:Ljava/lang/String;

    .line 2309
    .line 2310
    const-string v11, "video/dolby-vision"

    .line 2311
    .line 2312
    :cond_70
    iget-boolean v14, v0, Lg9/c;->X:Z

    .line 2313
    .line 2314
    iget-boolean v15, v0, Lg9/c;->W:Z

    .line 2315
    .line 2316
    if-eqz v15, :cond_71

    .line 2317
    .line 2318
    const/4 v15, 0x2

    .line 2319
    goto :goto_27

    .line 2320
    :cond_71
    const/4 v15, 0x0

    .line 2321
    :goto_27
    or-int/2addr v14, v15

    .line 2322
    new-instance v15, Lt7/n;

    .line 2323
    .line 2324
    invoke-direct {v15}, Lt7/n;-><init>()V

    .line 2325
    .line 2326
    .line 2327
    invoke-static {v11}, Lt7/d0;->i(Ljava/lang/String;)Z

    .line 2328
    .line 2329
    .line 2330
    move-result v17

    .line 2331
    move-object/from16 v22, v7

    .line 2332
    .line 2333
    sget-object v7, Lg9/d;->k0:Ljava/util/Map;

    .line 2334
    .line 2335
    if-eqz v17, :cond_72

    .line 2336
    .line 2337
    iget v5, v0, Lg9/c;->Q:I

    .line 2338
    .line 2339
    iput v5, v15, Lt7/n;->E:I

    .line 2340
    .line 2341
    iget v5, v0, Lg9/c;->S:I

    .line 2342
    .line 2343
    iput v5, v15, Lt7/n;->F:I

    .line 2344
    .line 2345
    iput v1, v15, Lt7/n;->G:I

    .line 2346
    .line 2347
    const/4 v1, 0x1

    .line 2348
    goto/16 :goto_31

    .line 2349
    .line 2350
    :cond_72
    invoke-static {v11}, Lt7/d0;->l(Ljava/lang/String;)Z

    .line 2351
    .line 2352
    .line 2353
    move-result v1

    .line 2354
    if-eqz v1, :cond_80

    .line 2355
    .line 2356
    iget v1, v0, Lg9/c;->s:I

    .line 2357
    .line 2358
    if-nez v1, :cond_75

    .line 2359
    .line 2360
    iget v1, v0, Lg9/c;->q:I

    .line 2361
    .line 2362
    const/4 v5, -0x1

    .line 2363
    if-ne v1, v5, :cond_73

    .line 2364
    .line 2365
    iget v1, v0, Lg9/c;->n:I

    .line 2366
    .line 2367
    :cond_73
    iput v1, v0, Lg9/c;->q:I

    .line 2368
    .line 2369
    iget v1, v0, Lg9/c;->r:I

    .line 2370
    .line 2371
    if-ne v1, v5, :cond_74

    .line 2372
    .line 2373
    iget v1, v0, Lg9/c;->o:I

    .line 2374
    .line 2375
    :cond_74
    iput v1, v0, Lg9/c;->r:I

    .line 2376
    .line 2377
    goto :goto_28

    .line 2378
    :cond_75
    const/4 v5, -0x1

    .line 2379
    :goto_28
    iget v1, v0, Lg9/c;->q:I

    .line 2380
    .line 2381
    if-eq v1, v5, :cond_76

    .line 2382
    .line 2383
    iget v6, v0, Lg9/c;->r:I

    .line 2384
    .line 2385
    if-eq v6, v5, :cond_76

    .line 2386
    .line 2387
    iget v5, v0, Lg9/c;->o:I

    .line 2388
    .line 2389
    mul-int/2addr v5, v1

    .line 2390
    int-to-float v1, v5

    .line 2391
    iget v5, v0, Lg9/c;->n:I

    .line 2392
    .line 2393
    mul-int/2addr v5, v6

    .line 2394
    int-to-float v5, v5

    .line 2395
    div-float/2addr v1, v5

    .line 2396
    goto :goto_29

    .line 2397
    :cond_76
    move/from16 v1, v25

    .line 2398
    .line 2399
    :goto_29
    iget-boolean v5, v0, Lg9/c;->z:Z

    .line 2400
    .line 2401
    if-eqz v5, :cond_79

    .line 2402
    .line 2403
    iget v5, v0, Lg9/c;->F:F

    .line 2404
    .line 2405
    cmpl-float v5, v5, v25

    .line 2406
    .line 2407
    if-eqz v5, :cond_78

    .line 2408
    .line 2409
    iget v5, v0, Lg9/c;->G:F

    .line 2410
    .line 2411
    cmpl-float v5, v5, v25

    .line 2412
    .line 2413
    if-eqz v5, :cond_78

    .line 2414
    .line 2415
    iget v5, v0, Lg9/c;->H:F

    .line 2416
    .line 2417
    cmpl-float v5, v5, v25

    .line 2418
    .line 2419
    if-eqz v5, :cond_78

    .line 2420
    .line 2421
    iget v5, v0, Lg9/c;->I:F

    .line 2422
    .line 2423
    cmpl-float v5, v5, v25

    .line 2424
    .line 2425
    if-eqz v5, :cond_78

    .line 2426
    .line 2427
    iget v5, v0, Lg9/c;->J:F

    .line 2428
    .line 2429
    cmpl-float v5, v5, v25

    .line 2430
    .line 2431
    if-eqz v5, :cond_78

    .line 2432
    .line 2433
    iget v5, v0, Lg9/c;->K:F

    .line 2434
    .line 2435
    cmpl-float v5, v5, v25

    .line 2436
    .line 2437
    if-eqz v5, :cond_78

    .line 2438
    .line 2439
    iget v5, v0, Lg9/c;->L:F

    .line 2440
    .line 2441
    cmpl-float v5, v5, v25

    .line 2442
    .line 2443
    if-eqz v5, :cond_78

    .line 2444
    .line 2445
    iget v5, v0, Lg9/c;->M:F

    .line 2446
    .line 2447
    cmpl-float v5, v5, v25

    .line 2448
    .line 2449
    if-eqz v5, :cond_78

    .line 2450
    .line 2451
    iget v5, v0, Lg9/c;->N:F

    .line 2452
    .line 2453
    cmpl-float v5, v5, v25

    .line 2454
    .line 2455
    if-eqz v5, :cond_78

    .line 2456
    .line 2457
    iget v5, v0, Lg9/c;->O:F

    .line 2458
    .line 2459
    cmpl-float v5, v5, v25

    .line 2460
    .line 2461
    if-nez v5, :cond_77

    .line 2462
    .line 2463
    goto/16 :goto_2a

    .line 2464
    .line 2465
    :cond_77
    const/16 v5, 0x19

    .line 2466
    .line 2467
    new-array v5, v5, [B

    .line 2468
    .line 2469
    invoke-static {v5}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;

    .line 2470
    .line 2471
    .line 2472
    move-result-object v6

    .line 2473
    sget-object v8, Ljava/nio/ByteOrder;->LITTLE_ENDIAN:Ljava/nio/ByteOrder;

    .line 2474
    .line 2475
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 2476
    .line 2477
    .line 2478
    move-result-object v6

    .line 2479
    const/4 v8, 0x0

    .line 2480
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 2481
    .line 2482
    .line 2483
    iget v8, v0, Lg9/c;->F:F

    .line 2484
    .line 2485
    const v10, 0x47435000    # 50000.0f

    .line 2486
    .line 2487
    .line 2488
    mul-float/2addr v8, v10

    .line 2489
    const/high16 v12, 0x3f000000    # 0.5f

    .line 2490
    .line 2491
    add-float/2addr v8, v12

    .line 2492
    float-to-int v8, v8

    .line 2493
    int-to-short v8, v8

    .line 2494
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 2495
    .line 2496
    .line 2497
    iget v8, v0, Lg9/c;->G:F

    .line 2498
    .line 2499
    mul-float/2addr v8, v10

    .line 2500
    add-float/2addr v8, v12

    .line 2501
    float-to-int v8, v8

    .line 2502
    int-to-short v8, v8

    .line 2503
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 2504
    .line 2505
    .line 2506
    iget v8, v0, Lg9/c;->H:F

    .line 2507
    .line 2508
    mul-float/2addr v8, v10

    .line 2509
    add-float/2addr v8, v12

    .line 2510
    float-to-int v8, v8

    .line 2511
    int-to-short v8, v8

    .line 2512
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 2513
    .line 2514
    .line 2515
    iget v8, v0, Lg9/c;->I:F

    .line 2516
    .line 2517
    mul-float/2addr v8, v10

    .line 2518
    add-float/2addr v8, v12

    .line 2519
    float-to-int v8, v8

    .line 2520
    int-to-short v8, v8

    .line 2521
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 2522
    .line 2523
    .line 2524
    iget v8, v0, Lg9/c;->J:F

    .line 2525
    .line 2526
    mul-float/2addr v8, v10

    .line 2527
    add-float/2addr v8, v12

    .line 2528
    float-to-int v8, v8

    .line 2529
    int-to-short v8, v8

    .line 2530
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 2531
    .line 2532
    .line 2533
    iget v8, v0, Lg9/c;->K:F

    .line 2534
    .line 2535
    mul-float/2addr v8, v10

    .line 2536
    add-float/2addr v8, v12

    .line 2537
    float-to-int v8, v8

    .line 2538
    int-to-short v8, v8

    .line 2539
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 2540
    .line 2541
    .line 2542
    iget v8, v0, Lg9/c;->L:F

    .line 2543
    .line 2544
    mul-float/2addr v8, v10

    .line 2545
    add-float/2addr v8, v12

    .line 2546
    float-to-int v8, v8

    .line 2547
    int-to-short v8, v8

    .line 2548
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 2549
    .line 2550
    .line 2551
    iget v8, v0, Lg9/c;->M:F

    .line 2552
    .line 2553
    mul-float/2addr v8, v10

    .line 2554
    add-float/2addr v8, v12

    .line 2555
    float-to-int v8, v8

    .line 2556
    int-to-short v8, v8

    .line 2557
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 2558
    .line 2559
    .line 2560
    iget v8, v0, Lg9/c;->N:F

    .line 2561
    .line 2562
    add-float/2addr v8, v12

    .line 2563
    float-to-int v8, v8

    .line 2564
    int-to-short v8, v8

    .line 2565
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 2566
    .line 2567
    .line 2568
    iget v8, v0, Lg9/c;->O:F

    .line 2569
    .line 2570
    add-float/2addr v8, v12

    .line 2571
    float-to-int v8, v8

    .line 2572
    int-to-short v8, v8

    .line 2573
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 2574
    .line 2575
    .line 2576
    iget v8, v0, Lg9/c;->D:I

    .line 2577
    .line 2578
    int-to-short v8, v8

    .line 2579
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 2580
    .line 2581
    .line 2582
    iget v8, v0, Lg9/c;->E:I

    .line 2583
    .line 2584
    int-to-short v8, v8

    .line 2585
    invoke-virtual {v6, v8}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 2586
    .line 2587
    .line 2588
    move-object/from16 v41, v5

    .line 2589
    .line 2590
    goto :goto_2b

    .line 2591
    :cond_78
    :goto_2a
    const/16 v41, 0x0

    .line 2592
    .line 2593
    :goto_2b
    iget v5, v0, Lg9/c;->A:I

    .line 2594
    .line 2595
    iget v6, v0, Lg9/c;->C:I

    .line 2596
    .line 2597
    iget v8, v0, Lg9/c;->B:I

    .line 2598
    .line 2599
    iget v10, v0, Lg9/c;->p:I

    .line 2600
    .line 2601
    new-instance v35, Lt7/f;

    .line 2602
    .line 2603
    move/from16 v40, v10

    .line 2604
    .line 2605
    move/from16 v36, v5

    .line 2606
    .line 2607
    move/from16 v37, v6

    .line 2608
    .line 2609
    move/from16 v38, v8

    .line 2610
    .line 2611
    move/from16 v39, v10

    .line 2612
    .line 2613
    invoke-direct/range {v35 .. v41}, Lt7/f;-><init>(IIIII[B)V

    .line 2614
    .line 2615
    .line 2616
    move-object/from16 v5, v35

    .line 2617
    .line 2618
    goto :goto_2c

    .line 2619
    :cond_79
    const/4 v5, 0x0

    .line 2620
    :goto_2c
    iget-object v6, v0, Lg9/c;->b:Ljava/lang/String;

    .line 2621
    .line 2622
    if-eqz v6, :cond_7a

    .line 2623
    .line 2624
    invoke-interface {v7, v6}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 2625
    .line 2626
    .line 2627
    move-result v6

    .line 2628
    if-eqz v6, :cond_7a

    .line 2629
    .line 2630
    iget-object v6, v0, Lg9/c;->b:Ljava/lang/String;

    .line 2631
    .line 2632
    invoke-interface {v7, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2633
    .line 2634
    .line 2635
    move-result-object v6

    .line 2636
    check-cast v6, Ljava/lang/Integer;

    .line 2637
    .line 2638
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 2639
    .line 2640
    .line 2641
    move-result v6

    .line 2642
    goto :goto_2d

    .line 2643
    :cond_7a
    const/4 v6, -0x1

    .line 2644
    :goto_2d
    iget v8, v0, Lg9/c;->t:I

    .line 2645
    .line 2646
    if-nez v8, :cond_7f

    .line 2647
    .line 2648
    iget v8, v0, Lg9/c;->u:F

    .line 2649
    .line 2650
    const/4 v10, 0x0

    .line 2651
    invoke-static {v8, v10}, Ljava/lang/Float;->compare(FF)I

    .line 2652
    .line 2653
    .line 2654
    move-result v8

    .line 2655
    if-nez v8, :cond_7f

    .line 2656
    .line 2657
    iget v8, v0, Lg9/c;->v:F

    .line 2658
    .line 2659
    invoke-static {v8, v10}, Ljava/lang/Float;->compare(FF)I

    .line 2660
    .line 2661
    .line 2662
    move-result v8

    .line 2663
    if-nez v8, :cond_7f

    .line 2664
    .line 2665
    iget v8, v0, Lg9/c;->w:F

    .line 2666
    .line 2667
    invoke-static {v8, v10}, Ljava/lang/Float;->compare(FF)I

    .line 2668
    .line 2669
    .line 2670
    move-result v8

    .line 2671
    if-nez v8, :cond_7b

    .line 2672
    .line 2673
    const/4 v6, 0x0

    .line 2674
    goto :goto_2f

    .line 2675
    :cond_7b
    iget v8, v0, Lg9/c;->w:F

    .line 2676
    .line 2677
    const/high16 v10, 0x42b40000    # 90.0f

    .line 2678
    .line 2679
    invoke-static {v8, v10}, Ljava/lang/Float;->compare(FF)I

    .line 2680
    .line 2681
    .line 2682
    move-result v8

    .line 2683
    if-nez v8, :cond_7c

    .line 2684
    .line 2685
    const/16 v6, 0x5a

    .line 2686
    .line 2687
    goto :goto_2f

    .line 2688
    :cond_7c
    iget v8, v0, Lg9/c;->w:F

    .line 2689
    .line 2690
    const/high16 v10, -0x3ccc0000    # -180.0f

    .line 2691
    .line 2692
    invoke-static {v8, v10}, Ljava/lang/Float;->compare(FF)I

    .line 2693
    .line 2694
    .line 2695
    move-result v8

    .line 2696
    if-eqz v8, :cond_7e

    .line 2697
    .line 2698
    iget v8, v0, Lg9/c;->w:F

    .line 2699
    .line 2700
    const/high16 v10, 0x43340000    # 180.0f

    .line 2701
    .line 2702
    invoke-static {v8, v10}, Ljava/lang/Float;->compare(FF)I

    .line 2703
    .line 2704
    .line 2705
    move-result v8

    .line 2706
    if-nez v8, :cond_7d

    .line 2707
    .line 2708
    goto :goto_2e

    .line 2709
    :cond_7d
    iget v8, v0, Lg9/c;->w:F

    .line 2710
    .line 2711
    const/high16 v10, -0x3d4c0000    # -90.0f

    .line 2712
    .line 2713
    invoke-static {v8, v10}, Ljava/lang/Float;->compare(FF)I

    .line 2714
    .line 2715
    .line 2716
    move-result v8

    .line 2717
    if-nez v8, :cond_7f

    .line 2718
    .line 2719
    const/16 v6, 0x10e

    .line 2720
    .line 2721
    goto :goto_2f

    .line 2722
    :cond_7e
    :goto_2e
    const/16 v6, 0xb4

    .line 2723
    .line 2724
    :cond_7f
    :goto_2f
    iget v8, v0, Lg9/c;->n:I

    .line 2725
    .line 2726
    iput v8, v15, Lt7/n;->t:I

    .line 2727
    .line 2728
    iget v8, v0, Lg9/c;->o:I

    .line 2729
    .line 2730
    iput v8, v15, Lt7/n;->u:I

    .line 2731
    .line 2732
    iput v1, v15, Lt7/n;->z:F

    .line 2733
    .line 2734
    iput v6, v15, Lt7/n;->y:I

    .line 2735
    .line 2736
    iget-object v1, v0, Lg9/c;->x:[B

    .line 2737
    .line 2738
    iput-object v1, v15, Lt7/n;->A:[B

    .line 2739
    .line 2740
    iget v1, v0, Lg9/c;->y:I

    .line 2741
    .line 2742
    iput v1, v15, Lt7/n;->B:I

    .line 2743
    .line 2744
    iput-object v5, v15, Lt7/n;->C:Lt7/f;

    .line 2745
    .line 2746
    const/4 v1, 0x2

    .line 2747
    goto :goto_31

    .line 2748
    :cond_80
    invoke-virtual {v5, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2749
    .line 2750
    .line 2751
    move-result v1

    .line 2752
    if-nez v1, :cond_82

    .line 2753
    .line 2754
    invoke-virtual {v12, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2755
    .line 2756
    .line 2757
    move-result v1

    .line 2758
    if-nez v1, :cond_82

    .line 2759
    .line 2760
    invoke-virtual {v13, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2761
    .line 2762
    .line 2763
    move-result v1

    .line 2764
    if-nez v1, :cond_82

    .line 2765
    .line 2766
    invoke-virtual {v8, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2767
    .line 2768
    .line 2769
    move-result v1

    .line 2770
    if-nez v1, :cond_82

    .line 2771
    .line 2772
    invoke-virtual {v10, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2773
    .line 2774
    .line 2775
    move-result v1

    .line 2776
    if-nez v1, :cond_82

    .line 2777
    .line 2778
    invoke-virtual {v6, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2779
    .line 2780
    .line 2781
    move-result v1

    .line 2782
    if-eqz v1, :cond_81

    .line 2783
    .line 2784
    goto :goto_30

    .line 2785
    :cond_81
    const-string v0, "Unexpected MIME type."

    .line 2786
    .line 2787
    const/4 v1, 0x0

    .line 2788
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 2789
    .line 2790
    .line 2791
    move-result-object v0

    .line 2792
    throw v0

    .line 2793
    :cond_82
    :goto_30
    const/4 v1, 0x3

    .line 2794
    :goto_31
    iget-object v5, v0, Lg9/c;->b:Ljava/lang/String;

    .line 2795
    .line 2796
    if-eqz v5, :cond_83

    .line 2797
    .line 2798
    invoke-interface {v7, v5}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 2799
    .line 2800
    .line 2801
    move-result v5

    .line 2802
    if-nez v5, :cond_83

    .line 2803
    .line 2804
    iget-object v5, v0, Lg9/c;->b:Ljava/lang/String;

    .line 2805
    .line 2806
    iput-object v5, v15, Lt7/n;->b:Ljava/lang/String;

    .line 2807
    .line 2808
    :cond_83
    invoke-static/range {v34 .. v34}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 2809
    .line 2810
    .line 2811
    move-result-object v5

    .line 2812
    iput-object v5, v15, Lt7/n;->a:Ljava/lang/String;

    .line 2813
    .line 2814
    iget-boolean v5, v0, Lg9/c;->a:Z

    .line 2815
    .line 2816
    if-eqz v5, :cond_84

    .line 2817
    .line 2818
    goto :goto_32

    .line 2819
    :cond_84
    const-string v5, "video/x-matroska"

    .line 2820
    .line 2821
    move-object/from16 v32, v5

    .line 2822
    .line 2823
    :goto_32
    invoke-static/range {v32 .. v32}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 2824
    .line 2825
    .line 2826
    move-result-object v5

    .line 2827
    iput-object v5, v15, Lt7/n;->l:Ljava/lang/String;

    .line 2828
    .line 2829
    invoke-static {v11}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 2830
    .line 2831
    .line 2832
    move-result-object v5

    .line 2833
    iput-object v5, v15, Lt7/n;->m:Ljava/lang/String;

    .line 2834
    .line 2835
    iput v4, v15, Lt7/n;->n:I

    .line 2836
    .line 2837
    iget-object v4, v0, Lg9/c;->Y:Ljava/lang/String;

    .line 2838
    .line 2839
    iput-object v4, v15, Lt7/n;->d:Ljava/lang/String;

    .line 2840
    .line 2841
    iput v14, v15, Lt7/n;->e:I

    .line 2842
    .line 2843
    iput-object v9, v15, Lt7/n;->p:Ljava/util/List;

    .line 2844
    .line 2845
    iput-object v2, v15, Lt7/n;->j:Ljava/lang/String;

    .line 2846
    .line 2847
    iget-object v2, v0, Lg9/c;->m:Lt7/k;

    .line 2848
    .line 2849
    iput-object v2, v15, Lt7/n;->q:Lt7/k;

    .line 2850
    .line 2851
    new-instance v2, Lt7/o;

    .line 2852
    .line 2853
    invoke-direct {v2, v15}, Lt7/o;-><init>(Lt7/n;)V

    .line 2854
    .line 2855
    .line 2856
    iget v4, v0, Lg9/c;->d:I

    .line 2857
    .line 2858
    invoke-interface {v3, v4, v1}, Lo8/q;->q(II)Lo8/i0;

    .line 2859
    .line 2860
    .line 2861
    move-result-object v1

    .line 2862
    iput-object v1, v0, Lg9/c;->Z:Lo8/i0;

    .line 2863
    .line 2864
    invoke-interface {v1, v2}, Lo8/i0;->c(Lt7/o;)V

    .line 2865
    .line 2866
    .line 2867
    iget v1, v0, Lg9/c;->d:I

    .line 2868
    .line 2869
    move-object/from16 v2, v22

    .line 2870
    .line 2871
    invoke-virtual {v2, v1, v0}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 2872
    .line 2873
    .line 2874
    move-object/from16 v4, v29

    .line 2875
    .line 2876
    goto/16 :goto_a

    .line 2877
    .line 2878
    :goto_33
    iput-object v1, v4, Lg9/d;->x:Lg9/c;

    .line 2879
    .line 2880
    goto/16 :goto_7

    .line 2881
    .line 2882
    :cond_85
    const/4 v1, 0x0

    .line 2883
    const-string v0, "CodecId is missing in TrackEntry element"

    .line 2884
    .line 2885
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 2886
    .line 2887
    .line 2888
    move-result-object v0

    .line 2889
    throw v0

    .line 2890
    :cond_86
    move-object v2, v7

    .line 2891
    iget v0, v4, Lg9/d;->J:I

    .line 2892
    .line 2893
    const/4 v14, 0x2

    .line 2894
    if-eq v0, v14, :cond_87

    .line 2895
    .line 2896
    :goto_34
    goto/16 :goto_7

    .line 2897
    .line 2898
    :cond_87
    iget v0, v4, Lg9/d;->P:I

    .line 2899
    .line 2900
    invoke-virtual {v2, v0}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 2901
    .line 2902
    .line 2903
    move-result-object v0

    .line 2904
    check-cast v0, Lg9/c;

    .line 2905
    .line 2906
    iget-object v1, v0, Lg9/c;->Z:Lo8/i0;

    .line 2907
    .line 2908
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2909
    .line 2910
    .line 2911
    iget-wide v1, v4, Lg9/d;->U:J

    .line 2912
    .line 2913
    cmp-long v1, v1, v17

    .line 2914
    .line 2915
    if-lez v1, :cond_88

    .line 2916
    .line 2917
    iget-object v1, v0, Lg9/c;->c:Ljava/lang/String;

    .line 2918
    .line 2919
    invoke-virtual {v8, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2920
    .line 2921
    .line 2922
    move-result v1

    .line 2923
    if-eqz v1, :cond_88

    .line 2924
    .line 2925
    iget-object v1, v4, Lg9/d;->p:Lw7/p;

    .line 2926
    .line 2927
    const/16 v23, 0x8

    .line 2928
    .line 2929
    invoke-static/range {v23 .. v23}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 2930
    .line 2931
    .line 2932
    move-result-object v2

    .line 2933
    sget-object v3, Ljava/nio/ByteOrder;->LITTLE_ENDIAN:Ljava/nio/ByteOrder;

    .line 2934
    .line 2935
    invoke-virtual {v2, v3}, Ljava/nio/ByteBuffer;->order(Ljava/nio/ByteOrder;)Ljava/nio/ByteBuffer;

    .line 2936
    .line 2937
    .line 2938
    move-result-object v2

    .line 2939
    iget-wide v5, v4, Lg9/d;->U:J

    .line 2940
    .line 2941
    invoke-virtual {v2, v5, v6}, Ljava/nio/ByteBuffer;->putLong(J)Ljava/nio/ByteBuffer;

    .line 2942
    .line 2943
    .line 2944
    move-result-object v2

    .line 2945
    invoke-virtual {v2}, Ljava/nio/ByteBuffer;->array()[B

    .line 2946
    .line 2947
    .line 2948
    move-result-object v2

    .line 2949
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2950
    .line 2951
    .line 2952
    array-length v3, v2

    .line 2953
    invoke-virtual {v1, v3, v2}, Lw7/p;->G(I[B)V

    .line 2954
    .line 2955
    .line 2956
    :cond_88
    const/4 v1, 0x0

    .line 2957
    const/4 v2, 0x0

    .line 2958
    :goto_35
    iget v3, v4, Lg9/d;->N:I

    .line 2959
    .line 2960
    if-ge v1, v3, :cond_89

    .line 2961
    .line 2962
    iget-object v3, v4, Lg9/d;->O:[I

    .line 2963
    .line 2964
    aget v3, v3, v1

    .line 2965
    .line 2966
    add-int/2addr v2, v3

    .line 2967
    add-int/lit8 v1, v1, 0x1

    .line 2968
    .line 2969
    goto :goto_35

    .line 2970
    :cond_89
    const/4 v1, 0x0

    .line 2971
    :goto_36
    iget v3, v4, Lg9/d;->N:I

    .line 2972
    .line 2973
    if-ge v1, v3, :cond_8b

    .line 2974
    .line 2975
    iget-wide v5, v4, Lg9/d;->K:J

    .line 2976
    .line 2977
    iget v3, v0, Lg9/c;->f:I

    .line 2978
    .line 2979
    mul-int/2addr v3, v1

    .line 2980
    const/16 v7, 0x3e8

    .line 2981
    .line 2982
    div-int/2addr v3, v7

    .line 2983
    int-to-long v7, v3

    .line 2984
    add-long v31, v5, v7

    .line 2985
    .line 2986
    iget v3, v4, Lg9/d;->R:I

    .line 2987
    .line 2988
    if-nez v1, :cond_8a

    .line 2989
    .line 2990
    iget-boolean v5, v4, Lg9/d;->T:Z

    .line 2991
    .line 2992
    if-nez v5, :cond_8a

    .line 2993
    .line 2994
    or-int/lit8 v3, v3, 0x1

    .line 2995
    .line 2996
    :cond_8a
    move/from16 v33, v3

    .line 2997
    .line 2998
    iget-object v3, v4, Lg9/d;->O:[I

    .line 2999
    .line 3000
    aget v34, v3, v1

    .line 3001
    .line 3002
    sub-int v35, v2, v34

    .line 3003
    .line 3004
    move-object/from16 v30, v0

    .line 3005
    .line 3006
    move-object/from16 v29, v4

    .line 3007
    .line 3008
    invoke-virtual/range {v29 .. v35}, Lg9/d;->g(Lg9/c;JIII)V

    .line 3009
    .line 3010
    .line 3011
    add-int/lit8 v1, v1, 0x1

    .line 3012
    .line 3013
    move/from16 v2, v35

    .line 3014
    .line 3015
    goto :goto_36

    .line 3016
    :cond_8b
    const/4 v0, 0x0

    .line 3017
    iput v0, v4, Lg9/d;->J:I

    .line 3018
    .line 3019
    :goto_37
    move-object/from16 v1, p1

    .line 3020
    .line 3021
    move v4, v0

    .line 3022
    :goto_38
    const/4 v5, 0x1

    .line 3023
    goto/16 :goto_4f

    .line 3024
    .line 3025
    :cond_8c
    const/4 v0, 0x0

    .line 3026
    iget v1, v7, Lg9/b;->e:I

    .line 3027
    .line 3028
    const v2, 0x1f43b675

    .line 3029
    .line 3030
    .line 3031
    if-nez v1, :cond_93

    .line 3032
    .line 3033
    move-object/from16 v1, p1

    .line 3034
    .line 3035
    const/4 v4, 0x4

    .line 3036
    const/4 v5, 0x1

    .line 3037
    invoke-virtual {v8, v1, v5, v0, v4}, Lg9/e;->b(Lo8/p;ZZI)J

    .line 3038
    .line 3039
    .line 3040
    move-result-wide v29

    .line 3041
    const-wide/16 v5, -0x2

    .line 3042
    .line 3043
    cmp-long v5, v29, v5

    .line 3044
    .line 3045
    if-nez v5, :cond_91

    .line 3046
    .line 3047
    iget-object v5, v7, Lg9/b;->a:[B

    .line 3048
    .line 3049
    invoke-interface {v1}, Lo8/p;->e()V

    .line 3050
    .line 3051
    .line 3052
    :goto_39
    invoke-interface {v1, v5, v0, v4}, Lo8/p;->o([BII)V

    .line 3053
    .line 3054
    .line 3055
    aget-byte v4, v5, v0

    .line 3056
    .line 3057
    const/4 v0, 0x0

    .line 3058
    :goto_3a
    const/16 v6, 0x8

    .line 3059
    .line 3060
    if-ge v0, v6, :cond_8e

    .line 3061
    .line 3062
    sget-object v6, Lg9/e;->d:[J

    .line 3063
    .line 3064
    aget-wide v29, v6, v0

    .line 3065
    .line 3066
    int-to-long v13, v4

    .line 3067
    and-long v13, v29, v13

    .line 3068
    .line 3069
    cmp-long v13, v13, v17

    .line 3070
    .line 3071
    if-eqz v13, :cond_8d

    .line 3072
    .line 3073
    add-int/lit8 v0, v0, 0x1

    .line 3074
    .line 3075
    :goto_3b
    const/4 v4, -0x1

    .line 3076
    goto :goto_3c

    .line 3077
    :cond_8d
    add-int/lit8 v0, v0, 0x1

    .line 3078
    .line 3079
    const/16 v13, 0xae

    .line 3080
    .line 3081
    const/16 v14, 0xa0

    .line 3082
    .line 3083
    goto :goto_3a

    .line 3084
    :cond_8e
    const/4 v0, -0x1

    .line 3085
    goto :goto_3b

    .line 3086
    :goto_3c
    if-eq v0, v4, :cond_8f

    .line 3087
    .line 3088
    const/4 v4, 0x4

    .line 3089
    if-gt v0, v4, :cond_8f

    .line 3090
    .line 3091
    const/4 v4, 0x0

    .line 3092
    invoke-static {v5, v0, v4}, Lg9/e;->a([BIZ)J

    .line 3093
    .line 3094
    .line 3095
    move-result-wide v13

    .line 3096
    long-to-int v4, v13

    .line 3097
    iget-object v13, v7, Lg9/b;->d:La0/j;

    .line 3098
    .line 3099
    iget-object v13, v13, La0/j;->e:Ljava/lang/Object;

    .line 3100
    .line 3101
    if-eq v4, v15, :cond_90

    .line 3102
    .line 3103
    if-eq v4, v2, :cond_90

    .line 3104
    .line 3105
    if-eq v4, v3, :cond_90

    .line 3106
    .line 3107
    if-ne v4, v11, :cond_8f

    .line 3108
    .line 3109
    goto :goto_3d

    .line 3110
    :cond_8f
    const/4 v14, 0x1

    .line 3111
    goto :goto_3f

    .line 3112
    :cond_90
    :goto_3d
    invoke-interface {v1, v0}, Lo8/p;->n(I)V

    .line 3113
    .line 3114
    .line 3115
    int-to-long v4, v4

    .line 3116
    :goto_3e
    const/4 v14, 0x1

    .line 3117
    goto :goto_40

    .line 3118
    :goto_3f
    invoke-interface {v1, v14}, Lo8/p;->n(I)V

    .line 3119
    .line 3120
    .line 3121
    const/4 v0, 0x0

    .line 3122
    const/4 v4, 0x4

    .line 3123
    const/16 v13, 0xae

    .line 3124
    .line 3125
    const/16 v14, 0xa0

    .line 3126
    .line 3127
    goto :goto_39

    .line 3128
    :cond_91
    move-wide/from16 v4, v29

    .line 3129
    .line 3130
    goto :goto_3e

    .line 3131
    :goto_40
    cmp-long v0, v4, v20

    .line 3132
    .line 3133
    if-nez v0, :cond_92

    .line 3134
    .line 3135
    const/4 v4, 0x0

    .line 3136
    const/4 v5, 0x0

    .line 3137
    goto/16 :goto_4f

    .line 3138
    .line 3139
    :cond_92
    long-to-int v0, v4

    .line 3140
    iput v0, v7, Lg9/b;->f:I

    .line 3141
    .line 3142
    iput v14, v7, Lg9/b;->e:I

    .line 3143
    .line 3144
    goto :goto_41

    .line 3145
    :cond_93
    move-object/from16 v1, p1

    .line 3146
    .line 3147
    const/4 v14, 0x1

    .line 3148
    :goto_41
    iget v0, v7, Lg9/b;->e:I

    .line 3149
    .line 3150
    if-ne v0, v14, :cond_94

    .line 3151
    .line 3152
    const/4 v4, 0x0

    .line 3153
    const/16 v11, 0x8

    .line 3154
    .line 3155
    invoke-virtual {v8, v1, v4, v14, v11}, Lg9/e;->b(Lo8/p;ZZI)J

    .line 3156
    .line 3157
    .line 3158
    move-result-wide v12

    .line 3159
    iput-wide v12, v7, Lg9/b;->g:J

    .line 3160
    .line 3161
    const/4 v14, 0x2

    .line 3162
    iput v14, v7, Lg9/b;->e:I

    .line 3163
    .line 3164
    :cond_94
    iget-object v4, v7, Lg9/b;->d:La0/j;

    .line 3165
    .line 3166
    iget v5, v7, Lg9/b;->f:I

    .line 3167
    .line 3168
    iget-object v11, v4, La0/j;->e:Ljava/lang/Object;

    .line 3169
    .line 3170
    sparse-switch v5, :sswitch_data_2

    .line 3171
    .line 3172
    .line 3173
    const/4 v11, 0x0

    .line 3174
    goto :goto_42

    .line 3175
    :sswitch_44
    const/4 v11, 0x5

    .line 3176
    goto :goto_42

    .line 3177
    :sswitch_45
    const/4 v11, 0x4

    .line 3178
    goto :goto_42

    .line 3179
    :sswitch_46
    const/4 v11, 0x1

    .line 3180
    goto :goto_42

    .line 3181
    :sswitch_47
    const/4 v11, 0x3

    .line 3182
    goto :goto_42

    .line 3183
    :sswitch_48
    const/4 v11, 0x2

    .line 3184
    :goto_42
    if-eqz v11, :cond_b9

    .line 3185
    .line 3186
    const/4 v14, 0x1

    .line 3187
    if-eq v11, v14, :cond_a8

    .line 3188
    .line 3189
    const-wide/16 v2, 0x8

    .line 3190
    .line 3191
    const/4 v14, 0x2

    .line 3192
    if-eq v11, v14, :cond_a6

    .line 3193
    .line 3194
    const/4 v15, 0x3

    .line 3195
    if-eq v11, v15, :cond_9c

    .line 3196
    .line 3197
    const/4 v15, 0x4

    .line 3198
    if-eq v11, v15, :cond_9b

    .line 3199
    .line 3200
    const/4 v0, 0x5

    .line 3201
    if-ne v11, v0, :cond_9a

    .line 3202
    .line 3203
    iget-wide v8, v7, Lg9/b;->g:J

    .line 3204
    .line 3205
    const-wide/16 v10, 0x4

    .line 3206
    .line 3207
    cmp-long v0, v8, v10

    .line 3208
    .line 3209
    if-eqz v0, :cond_96

    .line 3210
    .line 3211
    cmp-long v0, v8, v2

    .line 3212
    .line 3213
    if-nez v0, :cond_95

    .line 3214
    .line 3215
    goto :goto_43

    .line 3216
    :cond_95
    new-instance v0, Ljava/lang/StringBuilder;

    .line 3217
    .line 3218
    const-string v1, "Invalid float size: "

    .line 3219
    .line 3220
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 3221
    .line 3222
    .line 3223
    iget-wide v1, v7, Lg9/b;->g:J

    .line 3224
    .line 3225
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 3226
    .line 3227
    .line 3228
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 3229
    .line 3230
    .line 3231
    move-result-object v0

    .line 3232
    const/4 v1, 0x0

    .line 3233
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 3234
    .line 3235
    .line 3236
    move-result-object v0

    .line 3237
    throw v0

    .line 3238
    :cond_96
    :goto_43
    long-to-int v0, v8

    .line 3239
    invoke-virtual {v7, v1, v0}, Lg9/b;->a(Lo8/p;I)J

    .line 3240
    .line 3241
    .line 3242
    move-result-wide v2

    .line 3243
    const/4 v15, 0x4

    .line 3244
    if-ne v0, v15, :cond_97

    .line 3245
    .line 3246
    long-to-int v0, v2

    .line 3247
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 3248
    .line 3249
    .line 3250
    move-result v0

    .line 3251
    float-to-double v2, v0

    .line 3252
    goto :goto_44

    .line 3253
    :cond_97
    invoke-static {v2, v3}, Ljava/lang/Double;->longBitsToDouble(J)D

    .line 3254
    .line 3255
    .line 3256
    move-result-wide v2

    .line 3257
    :goto_44
    iget-object v0, v4, La0/j;->e:Ljava/lang/Object;

    .line 3258
    .line 3259
    check-cast v0, Lg9/d;

    .line 3260
    .line 3261
    const/16 v4, 0xb5

    .line 3262
    .line 3263
    if-eq v5, v4, :cond_99

    .line 3264
    .line 3265
    const/16 v4, 0x4489

    .line 3266
    .line 3267
    if-eq v5, v4, :cond_98

    .line 3268
    .line 3269
    packed-switch v5, :pswitch_data_2

    .line 3270
    .line 3271
    .line 3272
    packed-switch v5, :pswitch_data_3

    .line 3273
    .line 3274
    .line 3275
    :goto_45
    const/4 v4, 0x0

    .line 3276
    goto/16 :goto_46

    .line 3277
    .line 3278
    :pswitch_1f
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3279
    .line 3280
    .line 3281
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3282
    .line 3283
    double-to-float v2, v2

    .line 3284
    iput v2, v0, Lg9/c;->w:F

    .line 3285
    .line 3286
    goto :goto_45

    .line 3287
    :pswitch_20
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3288
    .line 3289
    .line 3290
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3291
    .line 3292
    double-to-float v2, v2

    .line 3293
    iput v2, v0, Lg9/c;->v:F

    .line 3294
    .line 3295
    goto :goto_45

    .line 3296
    :pswitch_21
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3297
    .line 3298
    .line 3299
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3300
    .line 3301
    double-to-float v2, v2

    .line 3302
    iput v2, v0, Lg9/c;->u:F

    .line 3303
    .line 3304
    goto :goto_45

    .line 3305
    :pswitch_22
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3306
    .line 3307
    .line 3308
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3309
    .line 3310
    double-to-float v2, v2

    .line 3311
    iput v2, v0, Lg9/c;->O:F

    .line 3312
    .line 3313
    goto :goto_45

    .line 3314
    :pswitch_23
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3315
    .line 3316
    .line 3317
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3318
    .line 3319
    double-to-float v2, v2

    .line 3320
    iput v2, v0, Lg9/c;->N:F

    .line 3321
    .line 3322
    goto :goto_45

    .line 3323
    :pswitch_24
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3324
    .line 3325
    .line 3326
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3327
    .line 3328
    double-to-float v2, v2

    .line 3329
    iput v2, v0, Lg9/c;->M:F

    .line 3330
    .line 3331
    goto :goto_45

    .line 3332
    :pswitch_25
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3333
    .line 3334
    .line 3335
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3336
    .line 3337
    double-to-float v2, v2

    .line 3338
    iput v2, v0, Lg9/c;->L:F

    .line 3339
    .line 3340
    goto :goto_45

    .line 3341
    :pswitch_26
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3342
    .line 3343
    .line 3344
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3345
    .line 3346
    double-to-float v2, v2

    .line 3347
    iput v2, v0, Lg9/c;->K:F

    .line 3348
    .line 3349
    goto :goto_45

    .line 3350
    :pswitch_27
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3351
    .line 3352
    .line 3353
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3354
    .line 3355
    double-to-float v2, v2

    .line 3356
    iput v2, v0, Lg9/c;->J:F

    .line 3357
    .line 3358
    goto :goto_45

    .line 3359
    :pswitch_28
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3360
    .line 3361
    .line 3362
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3363
    .line 3364
    double-to-float v2, v2

    .line 3365
    iput v2, v0, Lg9/c;->I:F

    .line 3366
    .line 3367
    goto :goto_45

    .line 3368
    :pswitch_29
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3369
    .line 3370
    .line 3371
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3372
    .line 3373
    double-to-float v2, v2

    .line 3374
    iput v2, v0, Lg9/c;->H:F

    .line 3375
    .line 3376
    goto :goto_45

    .line 3377
    :pswitch_2a
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3378
    .line 3379
    .line 3380
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3381
    .line 3382
    double-to-float v2, v2

    .line 3383
    iput v2, v0, Lg9/c;->G:F

    .line 3384
    .line 3385
    goto :goto_45

    .line 3386
    :pswitch_2b
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3387
    .line 3388
    .line 3389
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3390
    .line 3391
    double-to-float v2, v2

    .line 3392
    iput v2, v0, Lg9/c;->F:F

    .line 3393
    .line 3394
    goto :goto_45

    .line 3395
    :cond_98
    double-to-long v2, v2

    .line 3396
    iput-wide v2, v0, Lg9/d;->u:J

    .line 3397
    .line 3398
    goto :goto_45

    .line 3399
    :cond_99
    invoke-virtual {v0, v5}, Lg9/d;->f(I)V

    .line 3400
    .line 3401
    .line 3402
    iget-object v0, v0, Lg9/d;->x:Lg9/c;

    .line 3403
    .line 3404
    double-to-int v2, v2

    .line 3405
    iput v2, v0, Lg9/c;->S:I

    .line 3406
    .line 3407
    goto/16 :goto_45

    .line 3408
    .line 3409
    :goto_46
    iput v4, v7, Lg9/b;->e:I

    .line 3410
    .line 3411
    goto/16 :goto_38

    .line 3412
    .line 3413
    :cond_9a
    new-instance v0, Ljava/lang/StringBuilder;

    .line 3414
    .line 3415
    const-string v1, "Invalid element type "

    .line 3416
    .line 3417
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 3418
    .line 3419
    .line 3420
    invoke-virtual {v0, v11}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 3421
    .line 3422
    .line 3423
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 3424
    .line 3425
    .line 3426
    move-result-object v0

    .line 3427
    const/4 v1, 0x0

    .line 3428
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 3429
    .line 3430
    .line 3431
    move-result-object v0

    .line 3432
    throw v0

    .line 3433
    :cond_9b
    iget-wide v2, v7, Lg9/b;->g:J

    .line 3434
    .line 3435
    long-to-int v0, v2

    .line 3436
    invoke-virtual {v4, v5, v0, v1}, La0/j;->T(IILo8/p;)V

    .line 3437
    .line 3438
    .line 3439
    const/4 v9, 0x0

    .line 3440
    iput v9, v7, Lg9/b;->e:I

    .line 3441
    .line 3442
    move v4, v9

    .line 3443
    goto/16 :goto_38

    .line 3444
    .line 3445
    :cond_9c
    const/4 v9, 0x0

    .line 3446
    iget-wide v2, v7, Lg9/b;->g:J

    .line 3447
    .line 3448
    const-wide/32 v10, 0x7fffffff

    .line 3449
    .line 3450
    .line 3451
    cmp-long v0, v2, v10

    .line 3452
    .line 3453
    if-gtz v0, :cond_a5

    .line 3454
    .line 3455
    long-to-int v0, v2

    .line 3456
    if-nez v0, :cond_9d

    .line 3457
    .line 3458
    const-string v0, ""

    .line 3459
    .line 3460
    goto :goto_48

    .line 3461
    :cond_9d
    new-array v2, v0, [B

    .line 3462
    .line 3463
    invoke-interface {v1, v2, v9, v0}, Lo8/p;->readFully([BII)V

    .line 3464
    .line 3465
    .line 3466
    :goto_47
    if-lez v0, :cond_9e

    .line 3467
    .line 3468
    add-int/lit8 v3, v0, -0x1

    .line 3469
    .line 3470
    aget-byte v3, v2, v3

    .line 3471
    .line 3472
    if-nez v3, :cond_9e

    .line 3473
    .line 3474
    add-int/lit8 v0, v0, -0x1

    .line 3475
    .line 3476
    goto :goto_47

    .line 3477
    :cond_9e
    new-instance v3, Ljava/lang/String;

    .line 3478
    .line 3479
    const/4 v9, 0x0

    .line 3480
    invoke-direct {v3, v2, v9, v0}, Ljava/lang/String;-><init>([BII)V

    .line 3481
    .line 3482
    .line 3483
    move-object v0, v3

    .line 3484
    :goto_48
    iget-object v2, v4, La0/j;->e:Ljava/lang/Object;

    .line 3485
    .line 3486
    check-cast v2, Lg9/d;

    .line 3487
    .line 3488
    const/16 v3, 0x86

    .line 3489
    .line 3490
    if-eq v5, v3, :cond_a4

    .line 3491
    .line 3492
    const/16 v3, 0x4282

    .line 3493
    .line 3494
    if-eq v5, v3, :cond_a1

    .line 3495
    .line 3496
    const/16 v3, 0x536e

    .line 3497
    .line 3498
    if-eq v5, v3, :cond_a0

    .line 3499
    .line 3500
    const v3, 0x22b59c

    .line 3501
    .line 3502
    .line 3503
    if-eq v5, v3, :cond_9f

    .line 3504
    .line 3505
    :goto_49
    const/4 v4, 0x0

    .line 3506
    goto :goto_4b

    .line 3507
    :cond_9f
    invoke-virtual {v2, v5}, Lg9/d;->f(I)V

    .line 3508
    .line 3509
    .line 3510
    iget-object v2, v2, Lg9/d;->x:Lg9/c;

    .line 3511
    .line 3512
    iput-object v0, v2, Lg9/c;->Y:Ljava/lang/String;

    .line 3513
    .line 3514
    goto :goto_49

    .line 3515
    :cond_a0
    invoke-virtual {v2, v5}, Lg9/d;->f(I)V

    .line 3516
    .line 3517
    .line 3518
    iget-object v2, v2, Lg9/d;->x:Lg9/c;

    .line 3519
    .line 3520
    iput-object v0, v2, Lg9/c;->b:Ljava/lang/String;

    .line 3521
    .line 3522
    goto :goto_49

    .line 3523
    :cond_a1
    const-string v3, "webm"

    .line 3524
    .line 3525
    invoke-virtual {v3, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 3526
    .line 3527
    .line 3528
    move-result v4

    .line 3529
    if-nez v4, :cond_a3

    .line 3530
    .line 3531
    const-string v4, "matroska"

    .line 3532
    .line 3533
    invoke-virtual {v4, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 3534
    .line 3535
    .line 3536
    move-result v4

    .line 3537
    if-eqz v4, :cond_a2

    .line 3538
    .line 3539
    goto :goto_4a

    .line 3540
    :cond_a2
    new-instance v1, Ljava/lang/StringBuilder;

    .line 3541
    .line 3542
    const-string v2, "DocType "

    .line 3543
    .line 3544
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 3545
    .line 3546
    .line 3547
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 3548
    .line 3549
    .line 3550
    const-string v0, " not supported"

    .line 3551
    .line 3552
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 3553
    .line 3554
    .line 3555
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 3556
    .line 3557
    .line 3558
    move-result-object v0

    .line 3559
    const/4 v1, 0x0

    .line 3560
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 3561
    .line 3562
    .line 3563
    move-result-object v0

    .line 3564
    throw v0

    .line 3565
    :cond_a3
    :goto_4a
    invoke-virtual {v0, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 3566
    .line 3567
    .line 3568
    move-result v0

    .line 3569
    iput-boolean v0, v2, Lg9/d;->w:Z

    .line 3570
    .line 3571
    goto :goto_49

    .line 3572
    :cond_a4
    invoke-virtual {v2, v5}, Lg9/d;->f(I)V

    .line 3573
    .line 3574
    .line 3575
    iget-object v2, v2, Lg9/d;->x:Lg9/c;

    .line 3576
    .line 3577
    iput-object v0, v2, Lg9/c;->c:Ljava/lang/String;

    .line 3578
    .line 3579
    goto :goto_49

    .line 3580
    :goto_4b
    iput v4, v7, Lg9/b;->e:I

    .line 3581
    .line 3582
    goto/16 :goto_38

    .line 3583
    .line 3584
    :cond_a5
    new-instance v0, Ljava/lang/StringBuilder;

    .line 3585
    .line 3586
    const-string v1, "String element size: "

    .line 3587
    .line 3588
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 3589
    .line 3590
    .line 3591
    iget-wide v1, v7, Lg9/b;->g:J

    .line 3592
    .line 3593
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 3594
    .line 3595
    .line 3596
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 3597
    .line 3598
    .line 3599
    move-result-object v0

    .line 3600
    const/4 v1, 0x0

    .line 3601
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 3602
    .line 3603
    .line 3604
    move-result-object v0

    .line 3605
    throw v0

    .line 3606
    :cond_a6
    iget-wide v8, v7, Lg9/b;->g:J

    .line 3607
    .line 3608
    cmp-long v0, v8, v2

    .line 3609
    .line 3610
    if-gtz v0, :cond_a7

    .line 3611
    .line 3612
    long-to-int v0, v8

    .line 3613
    invoke-virtual {v7, v1, v0}, Lg9/b;->a(Lo8/p;I)J

    .line 3614
    .line 3615
    .line 3616
    move-result-wide v2

    .line 3617
    invoke-virtual {v4, v5, v2, v3}, La0/j;->W(IJ)V

    .line 3618
    .line 3619
    .line 3620
    const/4 v4, 0x0

    .line 3621
    iput v4, v7, Lg9/b;->e:I

    .line 3622
    .line 3623
    goto/16 :goto_38

    .line 3624
    .line 3625
    :cond_a7
    new-instance v0, Ljava/lang/StringBuilder;

    .line 3626
    .line 3627
    const-string v1, "Invalid integer size: "

    .line 3628
    .line 3629
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 3630
    .line 3631
    .line 3632
    iget-wide v1, v7, Lg9/b;->g:J

    .line 3633
    .line 3634
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 3635
    .line 3636
    .line 3637
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 3638
    .line 3639
    .line 3640
    move-result-object v0

    .line 3641
    const/4 v1, 0x0

    .line 3642
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 3643
    .line 3644
    .line 3645
    move-result-object v0

    .line 3646
    throw v0

    .line 3647
    :cond_a8
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 3648
    .line 3649
    .line 3650
    move-result-wide v4

    .line 3651
    iget-wide v11, v7, Lg9/b;->g:J

    .line 3652
    .line 3653
    add-long/2addr v11, v4

    .line 3654
    new-instance v8, Lg9/a;

    .line 3655
    .line 3656
    iget v13, v7, Lg9/b;->f:I

    .line 3657
    .line 3658
    invoke-direct {v8, v13, v11, v12}, Lg9/a;-><init>(IJ)V

    .line 3659
    .line 3660
    .line 3661
    invoke-virtual {v9, v8}, Ljava/util/ArrayDeque;->push(Ljava/lang/Object;)V

    .line 3662
    .line 3663
    .line 3664
    iget-object v8, v7, Lg9/b;->d:La0/j;

    .line 3665
    .line 3666
    iget v9, v7, Lg9/b;->f:I

    .line 3667
    .line 3668
    iget-wide v11, v7, Lg9/b;->g:J

    .line 3669
    .line 3670
    iget-object v8, v8, La0/j;->e:Ljava/lang/Object;

    .line 3671
    .line 3672
    check-cast v8, Lg9/d;

    .line 3673
    .line 3674
    iget-object v13, v8, Lg9/d;->e0:Lo8/q;

    .line 3675
    .line 3676
    invoke-static {v13}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 3677
    .line 3678
    .line 3679
    const/16 v6, 0xa0

    .line 3680
    .line 3681
    if-eq v9, v6, :cond_b5

    .line 3682
    .line 3683
    const/16 v0, 0xae

    .line 3684
    .line 3685
    if-eq v9, v0, :cond_b4

    .line 3686
    .line 3687
    const/16 v0, 0xbb

    .line 3688
    .line 3689
    if-eq v9, v0, :cond_b3

    .line 3690
    .line 3691
    if-eq v9, v10, :cond_b2

    .line 3692
    .line 3693
    const/16 v0, 0x5035

    .line 3694
    .line 3695
    if-eq v9, v0, :cond_b1

    .line 3696
    .line 3697
    const/16 v0, 0x55d0

    .line 3698
    .line 3699
    if-eq v9, v0, :cond_b0

    .line 3700
    .line 3701
    const v0, 0x18538067

    .line 3702
    .line 3703
    .line 3704
    if-eq v9, v0, :cond_ad

    .line 3705
    .line 3706
    if-eq v9, v3, :cond_ac

    .line 3707
    .line 3708
    if-eq v9, v2, :cond_aa

    .line 3709
    .line 3710
    :cond_a9
    const/4 v14, 0x1

    .line 3711
    goto :goto_4c

    .line 3712
    :cond_aa
    iget-boolean v0, v8, Lg9/d;->y:Z

    .line 3713
    .line 3714
    if-nez v0, :cond_a9

    .line 3715
    .line 3716
    iget-boolean v0, v8, Lg9/d;->d:Z

    .line 3717
    .line 3718
    if-eqz v0, :cond_ab

    .line 3719
    .line 3720
    iget-wide v2, v8, Lg9/d;->C:J

    .line 3721
    .line 3722
    cmp-long v0, v2, v20

    .line 3723
    .line 3724
    if-eqz v0, :cond_ab

    .line 3725
    .line 3726
    const/4 v14, 0x1

    .line 3727
    iput-boolean v14, v8, Lg9/d;->B:Z

    .line 3728
    .line 3729
    :goto_4c
    const/4 v4, 0x0

    .line 3730
    goto/16 :goto_4e

    .line 3731
    .line 3732
    :cond_ab
    const/4 v14, 0x1

    .line 3733
    iget-object v0, v8, Lg9/d;->e0:Lo8/q;

    .line 3734
    .line 3735
    new-instance v2, Lo8/t;

    .line 3736
    .line 3737
    iget-wide v3, v8, Lg9/d;->v:J

    .line 3738
    .line 3739
    invoke-direct {v2, v3, v4}, Lo8/t;-><init>(J)V

    .line 3740
    .line 3741
    .line 3742
    invoke-interface {v0, v2}, Lo8/q;->c(Lo8/c0;)V

    .line 3743
    .line 3744
    .line 3745
    iput-boolean v14, v8, Lg9/d;->y:Z

    .line 3746
    .line 3747
    goto :goto_4c

    .line 3748
    :cond_ac
    const/4 v14, 0x1

    .line 3749
    new-instance v0, Lq3/b;

    .line 3750
    .line 3751
    const/4 v4, 0x0

    .line 3752
    invoke-direct {v0, v4, v14}, Lq3/b;-><init>(BI)V

    .line 3753
    .line 3754
    .line 3755
    iput-object v0, v8, Lg9/d;->F:Lq3/b;

    .line 3756
    .line 3757
    new-instance v0, Lq3/b;

    .line 3758
    .line 3759
    invoke-direct {v0, v4, v14}, Lq3/b;-><init>(BI)V

    .line 3760
    .line 3761
    .line 3762
    iput-object v0, v8, Lg9/d;->G:Lq3/b;

    .line 3763
    .line 3764
    goto :goto_4c

    .line 3765
    :cond_ad
    iget-wide v2, v8, Lg9/d;->s:J

    .line 3766
    .line 3767
    cmp-long v0, v2, v20

    .line 3768
    .line 3769
    if-eqz v0, :cond_af

    .line 3770
    .line 3771
    cmp-long v0, v2, v4

    .line 3772
    .line 3773
    if-nez v0, :cond_ae

    .line 3774
    .line 3775
    goto :goto_4d

    .line 3776
    :cond_ae
    const-string v0, "Multiple Segment elements not supported"

    .line 3777
    .line 3778
    const/4 v1, 0x0

    .line 3779
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 3780
    .line 3781
    .line 3782
    move-result-object v0

    .line 3783
    throw v0

    .line 3784
    :cond_af
    :goto_4d
    iput-wide v4, v8, Lg9/d;->s:J

    .line 3785
    .line 3786
    iput-wide v11, v8, Lg9/d;->r:J

    .line 3787
    .line 3788
    goto :goto_4c

    .line 3789
    :cond_b0
    invoke-virtual {v8, v9}, Lg9/d;->f(I)V

    .line 3790
    .line 3791
    .line 3792
    iget-object v0, v8, Lg9/d;->x:Lg9/c;

    .line 3793
    .line 3794
    const/4 v14, 0x1

    .line 3795
    iput-boolean v14, v0, Lg9/c;->z:Z

    .line 3796
    .line 3797
    goto :goto_4c

    .line 3798
    :cond_b1
    const/4 v14, 0x1

    .line 3799
    invoke-virtual {v8, v9}, Lg9/d;->f(I)V

    .line 3800
    .line 3801
    .line 3802
    iget-object v0, v8, Lg9/d;->x:Lg9/c;

    .line 3803
    .line 3804
    iput-boolean v14, v0, Lg9/c;->i:Z

    .line 3805
    .line 3806
    goto :goto_4c

    .line 3807
    :cond_b2
    const/4 v4, -0x1

    .line 3808
    iput v4, v8, Lg9/d;->z:I

    .line 3809
    .line 3810
    move-wide/from16 v2, v20

    .line 3811
    .line 3812
    iput-wide v2, v8, Lg9/d;->A:J

    .line 3813
    .line 3814
    goto :goto_4c

    .line 3815
    :cond_b3
    const/4 v9, 0x0

    .line 3816
    iput-boolean v9, v8, Lg9/d;->H:Z

    .line 3817
    .line 3818
    move v4, v9

    .line 3819
    goto :goto_4e

    .line 3820
    :cond_b4
    const/4 v4, -0x1

    .line 3821
    const/4 v9, 0x0

    .line 3822
    new-instance v0, Lg9/c;

    .line 3823
    .line 3824
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 3825
    .line 3826
    .line 3827
    iput v4, v0, Lg9/c;->n:I

    .line 3828
    .line 3829
    iput v4, v0, Lg9/c;->o:I

    .line 3830
    .line 3831
    iput v4, v0, Lg9/c;->p:I

    .line 3832
    .line 3833
    iput v4, v0, Lg9/c;->q:I

    .line 3834
    .line 3835
    iput v4, v0, Lg9/c;->r:I

    .line 3836
    .line 3837
    iput v9, v0, Lg9/c;->s:I

    .line 3838
    .line 3839
    iput v4, v0, Lg9/c;->t:I

    .line 3840
    .line 3841
    const/4 v10, 0x0

    .line 3842
    iput v10, v0, Lg9/c;->u:F

    .line 3843
    .line 3844
    iput v10, v0, Lg9/c;->v:F

    .line 3845
    .line 3846
    iput v10, v0, Lg9/c;->w:F

    .line 3847
    .line 3848
    const/4 v11, 0x0

    .line 3849
    iput-object v11, v0, Lg9/c;->x:[B

    .line 3850
    .line 3851
    iput v4, v0, Lg9/c;->y:I

    .line 3852
    .line 3853
    iput-boolean v9, v0, Lg9/c;->z:Z

    .line 3854
    .line 3855
    iput v4, v0, Lg9/c;->A:I

    .line 3856
    .line 3857
    iput v4, v0, Lg9/c;->B:I

    .line 3858
    .line 3859
    iput v4, v0, Lg9/c;->C:I

    .line 3860
    .line 3861
    const/16 v2, 0x3e8

    .line 3862
    .line 3863
    iput v2, v0, Lg9/c;->D:I

    .line 3864
    .line 3865
    const/16 v2, 0xc8

    .line 3866
    .line 3867
    iput v2, v0, Lg9/c;->E:I

    .line 3868
    .line 3869
    move/from16 v2, v25

    .line 3870
    .line 3871
    iput v2, v0, Lg9/c;->F:F

    .line 3872
    .line 3873
    iput v2, v0, Lg9/c;->G:F

    .line 3874
    .line 3875
    iput v2, v0, Lg9/c;->H:F

    .line 3876
    .line 3877
    iput v2, v0, Lg9/c;->I:F

    .line 3878
    .line 3879
    iput v2, v0, Lg9/c;->J:F

    .line 3880
    .line 3881
    iput v2, v0, Lg9/c;->K:F

    .line 3882
    .line 3883
    iput v2, v0, Lg9/c;->L:F

    .line 3884
    .line 3885
    iput v2, v0, Lg9/c;->M:F

    .line 3886
    .line 3887
    iput v2, v0, Lg9/c;->N:F

    .line 3888
    .line 3889
    iput v2, v0, Lg9/c;->O:F

    .line 3890
    .line 3891
    const/4 v14, 0x1

    .line 3892
    iput v14, v0, Lg9/c;->Q:I

    .line 3893
    .line 3894
    const/4 v4, -0x1

    .line 3895
    iput v4, v0, Lg9/c;->R:I

    .line 3896
    .line 3897
    const/16 v2, 0x1f40

    .line 3898
    .line 3899
    iput v2, v0, Lg9/c;->S:I

    .line 3900
    .line 3901
    move-wide/from16 v2, v17

    .line 3902
    .line 3903
    iput-wide v2, v0, Lg9/c;->T:J

    .line 3904
    .line 3905
    iput-wide v2, v0, Lg9/c;->U:J

    .line 3906
    .line 3907
    iput-boolean v14, v0, Lg9/c;->X:Z

    .line 3908
    .line 3909
    const-string v2, "eng"

    .line 3910
    .line 3911
    iput-object v2, v0, Lg9/c;->Y:Ljava/lang/String;

    .line 3912
    .line 3913
    iput-object v0, v8, Lg9/d;->x:Lg9/c;

    .line 3914
    .line 3915
    iget-boolean v2, v8, Lg9/d;->w:Z

    .line 3916
    .line 3917
    iput-boolean v2, v0, Lg9/c;->a:Z

    .line 3918
    .line 3919
    goto/16 :goto_4c

    .line 3920
    .line 3921
    :cond_b5
    move-wide/from16 v2, v17

    .line 3922
    .line 3923
    const/4 v4, 0x0

    .line 3924
    iput-boolean v4, v8, Lg9/d;->T:Z

    .line 3925
    .line 3926
    iput-wide v2, v8, Lg9/d;->U:J

    .line 3927
    .line 3928
    :goto_4e
    iput v4, v7, Lg9/b;->e:I

    .line 3929
    .line 3930
    goto/16 :goto_38

    .line 3931
    .line 3932
    :goto_4f
    if-eqz v5, :cond_b7

    .line 3933
    .line 3934
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 3935
    .line 3936
    .line 3937
    move-result-wide v2

    .line 3938
    move-object/from16 v0, p0

    .line 3939
    .line 3940
    iget-boolean v6, v0, Lg9/d;->B:Z

    .line 3941
    .line 3942
    if-eqz v6, :cond_b6

    .line 3943
    .line 3944
    iput-wide v2, v0, Lg9/d;->D:J

    .line 3945
    .line 3946
    iget-wide v1, v0, Lg9/d;->C:J

    .line 3947
    .line 3948
    move-object/from16 v3, p2

    .line 3949
    .line 3950
    iput-wide v1, v3, Lo8/s;->a:J

    .line 3951
    .line 3952
    iput-boolean v4, v0, Lg9/d;->B:Z

    .line 3953
    .line 3954
    const/16 v28, 0x1

    .line 3955
    .line 3956
    return v28

    .line 3957
    :cond_b6
    move-object/from16 v3, p2

    .line 3958
    .line 3959
    const/16 v28, 0x1

    .line 3960
    .line 3961
    iget-boolean v2, v0, Lg9/d;->y:Z

    .line 3962
    .line 3963
    if-eqz v2, :cond_b8

    .line 3964
    .line 3965
    iget-wide v6, v0, Lg9/d;->D:J

    .line 3966
    .line 3967
    const-wide/16 v8, -0x1

    .line 3968
    .line 3969
    cmp-long v2, v6, v8

    .line 3970
    .line 3971
    if-eqz v2, :cond_b8

    .line 3972
    .line 3973
    iput-wide v6, v3, Lo8/s;->a:J

    .line 3974
    .line 3975
    iput-wide v8, v0, Lg9/d;->D:J

    .line 3976
    .line 3977
    return v28

    .line 3978
    :cond_b7
    const/16 v28, 0x1

    .line 3979
    .line 3980
    move-object/from16 v0, p0

    .line 3981
    .line 3982
    move-object/from16 v3, p2

    .line 3983
    .line 3984
    :cond_b8
    const/4 v3, 0x0

    .line 3985
    goto/16 :goto_0

    .line 3986
    .line 3987
    :cond_b9
    move-object/from16 v0, p0

    .line 3988
    .line 3989
    move-object/from16 v3, p2

    .line 3990
    .line 3991
    const/16 v28, 0x1

    .line 3992
    .line 3993
    iget-wide v4, v7, Lg9/b;->g:J

    .line 3994
    .line 3995
    long-to-int v2, v4

    .line 3996
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 3997
    .line 3998
    .line 3999
    const/4 v4, 0x0

    .line 4000
    iput v4, v7, Lg9/b;->e:I

    .line 4001
    .line 4002
    move v3, v4

    .line 4003
    const/4 v6, -0x1

    .line 4004
    goto/16 :goto_1

    .line 4005
    .line 4006
    :cond_ba
    if-nez v5, :cond_bd

    .line 4007
    .line 4008
    const/4 v3, 0x0

    .line 4009
    :goto_50
    iget-object v1, v0, Lg9/d;->c:Landroid/util/SparseArray;

    .line 4010
    .line 4011
    invoke-virtual {v1}, Landroid/util/SparseArray;->size()I

    .line 4012
    .line 4013
    .line 4014
    move-result v2

    .line 4015
    if-ge v3, v2, :cond_bc

    .line 4016
    .line 4017
    invoke-virtual {v1, v3}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 4018
    .line 4019
    .line 4020
    move-result-object v1

    .line 4021
    check-cast v1, Lg9/c;

    .line 4022
    .line 4023
    iget-object v2, v1, Lg9/c;->Z:Lo8/i0;

    .line 4024
    .line 4025
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4026
    .line 4027
    .line 4028
    iget-object v2, v1, Lg9/c;->V:Lo8/j0;

    .line 4029
    .line 4030
    if-eqz v2, :cond_bb

    .line 4031
    .line 4032
    iget-object v4, v1, Lg9/c;->Z:Lo8/i0;

    .line 4033
    .line 4034
    iget-object v1, v1, Lg9/c;->k:Lo8/h0;

    .line 4035
    .line 4036
    invoke-virtual {v2, v4, v1}, Lo8/j0;->a(Lo8/i0;Lo8/h0;)V

    .line 4037
    .line 4038
    .line 4039
    :cond_bb
    add-int/lit8 v3, v3, 0x1

    .line 4040
    .line 4041
    goto :goto_50

    .line 4042
    :cond_bc
    const/16 v27, -0x1

    .line 4043
    .line 4044
    return v27

    .line 4045
    :cond_bd
    const/16 v24, 0x0

    .line 4046
    .line 4047
    return v24

    .line 4048
    nop

    :sswitch_data_0
    .sparse-switch
        -0x7ce7f5de -> :sswitch_21
        -0x7ce7f3b0 -> :sswitch_20
        -0x76567dc0 -> :sswitch_1f
        -0x6a615338 -> :sswitch_1e
        -0x672350af -> :sswitch_1d
        -0x585f4fce -> :sswitch_1c
        -0x585f4fcd -> :sswitch_1b
        -0x51dc40b2 -> :sswitch_1a
        -0x37a9c464 -> :sswitch_19
        -0x2016c535 -> :sswitch_18
        -0x2016c4e5 -> :sswitch_17
        -0x19552dbd -> :sswitch_16
        -0x1538b2ba -> :sswitch_15
        0x3c02325 -> :sswitch_14
        0x3c02353 -> :sswitch_13
        0x3c030c5 -> :sswitch_12
        0x4e81333 -> :sswitch_11
        0x4e86155 -> :sswitch_10
        0x4e86156 -> :sswitch_f
        0x5e8da3e -> :sswitch_e
        0x1a8350d6 -> :sswitch_d
        0x2056f406 -> :sswitch_c
        0x25e26ee2 -> :sswitch_b
        0x2b45174d -> :sswitch_a
        0x2b453ce4 -> :sswitch_9
        0x2c0618eb -> :sswitch_8
        0x2c065c6b -> :sswitch_7
        0x32fdf009 -> :sswitch_6
        0x3e4ca2d8 -> :sswitch_5
        0x54c61e47 -> :sswitch_4
        0x6bd6c624 -> :sswitch_3
        0x7446132a -> :sswitch_2
        0x7446b0a6 -> :sswitch_1
        0x744ad97d -> :sswitch_0
    .end sparse-switch

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch

    :sswitch_data_1
    .sparse-switch
        -0x7ce7f5de -> :sswitch_43
        -0x7ce7f3b0 -> :sswitch_42
        -0x76567dc0 -> :sswitch_41
        -0x6a615338 -> :sswitch_40
        -0x672350af -> :sswitch_3f
        -0x585f4fce -> :sswitch_3e
        -0x585f4fcd -> :sswitch_3d
        -0x51dc40b2 -> :sswitch_3c
        -0x37a9c464 -> :sswitch_3b
        -0x2016c535 -> :sswitch_3a
        -0x2016c4e5 -> :sswitch_39
        -0x19552dbd -> :sswitch_38
        -0x1538b2ba -> :sswitch_37
        0x3c02325 -> :sswitch_36
        0x3c02353 -> :sswitch_35
        0x3c030c5 -> :sswitch_34
        0x4e81333 -> :sswitch_33
        0x4e86155 -> :sswitch_32
        0x4e86156 -> :sswitch_31
        0x5e8da3e -> :sswitch_30
        0x1a8350d6 -> :sswitch_2f
        0x2056f406 -> :sswitch_2e
        0x25e26ee2 -> :sswitch_2d
        0x2b45174d -> :sswitch_2c
        0x2b453ce4 -> :sswitch_2b
        0x2c0618eb -> :sswitch_2a
        0x2c065c6b -> :sswitch_29
        0x32fdf009 -> :sswitch_28
        0x3e4ca2d8 -> :sswitch_27
        0x54c61e47 -> :sswitch_26
        0x6bd6c624 -> :sswitch_25
        0x7446132a -> :sswitch_24
        0x7446b0a6 -> :sswitch_23
        0x744ad97d -> :sswitch_22
    .end sparse-switch

    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_1e
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_1e
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_4
        :pswitch_11
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch

    :sswitch_data_2
    .sparse-switch
        0x83 -> :sswitch_48
        0x86 -> :sswitch_47
        0x88 -> :sswitch_48
        0x9b -> :sswitch_48
        0x9f -> :sswitch_48
        0xa0 -> :sswitch_46
        0xa1 -> :sswitch_45
        0xa3 -> :sswitch_45
        0xa5 -> :sswitch_45
        0xa6 -> :sswitch_46
        0xae -> :sswitch_46
        0xb0 -> :sswitch_48
        0xb3 -> :sswitch_48
        0xb5 -> :sswitch_44
        0xb7 -> :sswitch_46
        0xba -> :sswitch_48
        0xbb -> :sswitch_46
        0xd7 -> :sswitch_48
        0xe0 -> :sswitch_46
        0xe1 -> :sswitch_46
        0xe7 -> :sswitch_48
        0xee -> :sswitch_48
        0xf1 -> :sswitch_48
        0xfb -> :sswitch_48
        0x41e4 -> :sswitch_46
        0x41e7 -> :sswitch_48
        0x41ed -> :sswitch_45
        0x4254 -> :sswitch_48
        0x4255 -> :sswitch_45
        0x4282 -> :sswitch_47
        0x4285 -> :sswitch_48
        0x42f7 -> :sswitch_48
        0x4489 -> :sswitch_44
        0x47e1 -> :sswitch_48
        0x47e2 -> :sswitch_45
        0x47e7 -> :sswitch_46
        0x47e8 -> :sswitch_48
        0x4dbb -> :sswitch_46
        0x5031 -> :sswitch_48
        0x5032 -> :sswitch_48
        0x5034 -> :sswitch_46
        0x5035 -> :sswitch_46
        0x536e -> :sswitch_47
        0x53ab -> :sswitch_45
        0x53ac -> :sswitch_48
        0x53b8 -> :sswitch_48
        0x54b0 -> :sswitch_48
        0x54b2 -> :sswitch_48
        0x54ba -> :sswitch_48
        0x55aa -> :sswitch_48
        0x55b0 -> :sswitch_46
        0x55b2 -> :sswitch_48
        0x55b9 -> :sswitch_48
        0x55ba -> :sswitch_48
        0x55bb -> :sswitch_48
        0x55bc -> :sswitch_48
        0x55bd -> :sswitch_48
        0x55d0 -> :sswitch_46
        0x55d1 -> :sswitch_44
        0x55d2 -> :sswitch_44
        0x55d3 -> :sswitch_44
        0x55d4 -> :sswitch_44
        0x55d5 -> :sswitch_44
        0x55d6 -> :sswitch_44
        0x55d7 -> :sswitch_44
        0x55d8 -> :sswitch_44
        0x55d9 -> :sswitch_44
        0x55da -> :sswitch_44
        0x55ee -> :sswitch_48
        0x56aa -> :sswitch_48
        0x56bb -> :sswitch_48
        0x6240 -> :sswitch_46
        0x6264 -> :sswitch_48
        0x63a2 -> :sswitch_45
        0x6d80 -> :sswitch_46
        0x75a1 -> :sswitch_46
        0x75a2 -> :sswitch_48
        0x7670 -> :sswitch_46
        0x7671 -> :sswitch_48
        0x7672 -> :sswitch_45
        0x7673 -> :sswitch_44
        0x7674 -> :sswitch_44
        0x7675 -> :sswitch_44
        0x22b59c -> :sswitch_47
        0x23e383 -> :sswitch_48
        0x2ad7b1 -> :sswitch_48
        0x114d9b74 -> :sswitch_46
        0x1549a966 -> :sswitch_46
        0x1654ae6b -> :sswitch_46
        0x18538067 -> :sswitch_46
        0x1a45dfa3 -> :sswitch_46
        0x1c53bb6b -> :sswitch_46
        0x1f43b675 -> :sswitch_46
    .end sparse-switch

    :pswitch_data_2
    .packed-switch 0x55d1
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
    .end packed-switch

    :pswitch_data_3
    .packed-switch 0x7673
        :pswitch_21
        :pswitch_20
        :pswitch_1f
    .end packed-switch
.end method

.method public final k(Lo8/p;I)V
    .locals 3

    .line 1
    iget-object p0, p0, Lg9/d;->i:Lw7/p;

    .line 2
    .line 3
    iget v0, p0, Lw7/p;->c:I

    .line 4
    .line 5
    if-lt v0, p2, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget-object v0, p0, Lw7/p;->a:[B

    .line 9
    .line 10
    array-length v1, v0

    .line 11
    if-ge v1, p2, :cond_1

    .line 12
    .line 13
    array-length v0, v0

    .line 14
    mul-int/lit8 v0, v0, 0x2

    .line 15
    .line 16
    invoke-static {v0, p2}, Ljava/lang/Math;->max(II)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    invoke-virtual {p0, v0}, Lw7/p;->c(I)V

    .line 21
    .line 22
    .line 23
    :cond_1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 24
    .line 25
    iget v1, p0, Lw7/p;->c:I

    .line 26
    .line 27
    sub-int v2, p2, v1

    .line 28
    .line 29
    invoke-interface {p1, v0, v1, v2}, Lo8/p;->readFully([BII)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, p2}, Lw7/p;->H(I)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public final l()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lg9/d;->V:I

    .line 3
    .line 4
    iput v0, p0, Lg9/d;->W:I

    .line 5
    .line 6
    iput v0, p0, Lg9/d;->X:I

    .line 7
    .line 8
    iput-boolean v0, p0, Lg9/d;->Y:Z

    .line 9
    .line 10
    iput-boolean v0, p0, Lg9/d;->Z:Z

    .line 11
    .line 12
    iput-boolean v0, p0, Lg9/d;->a0:Z

    .line 13
    .line 14
    iput v0, p0, Lg9/d;->b0:I

    .line 15
    .line 16
    iput-byte v0, p0, Lg9/d;->c0:B

    .line 17
    .line 18
    iput-boolean v0, p0, Lg9/d;->d0:Z

    .line 19
    .line 20
    iget-object p0, p0, Lg9/d;->l:Lw7/p;

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Lw7/p;->F(I)V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public final m(J)J
    .locals 7

    .line 1
    iget-wide v2, p0, Lg9/d;->t:J

    .line 2
    .line 3
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    cmp-long p0, v2, v0

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    sget-object p0, Lw7/w;->a:Ljava/lang/String;

    .line 13
    .line 14
    sget-object v6, Ljava/math/RoundingMode;->DOWN:Ljava/math/RoundingMode;

    .line 15
    .line 16
    const-wide/16 v4, 0x3e8

    .line 17
    .line 18
    move-wide v0, p1

    .line 19
    invoke-static/range {v0 .. v6}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 20
    .line 21
    .line 22
    move-result-wide p0

    .line 23
    return-wide p0

    .line 24
    :cond_0
    const-string p0, "Can\'t scale timecode prior to timecodeScale being set."

    .line 25
    .line 26
    const/4 p1, 0x0

    .line 27
    invoke-static {p1, p0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    throw p0
.end method

.method public final n(Lo8/p;Lg9/c;IZ)I
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move/from16 v3, p3

    .line 8
    .line 9
    const-string v4, "S_TEXT/UTF8"

    .line 10
    .line 11
    iget-object v5, v2, Lg9/c;->c:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    if-eqz v4, :cond_0

    .line 18
    .line 19
    sget-object v2, Lg9/d;->f0:[B

    .line 20
    .line 21
    invoke-virtual {v0, v1, v2, v3}, Lg9/d;->o(Lo8/p;[BI)V

    .line 22
    .line 23
    .line 24
    iget v1, v0, Lg9/d;->W:I

    .line 25
    .line 26
    invoke-virtual {v0}, Lg9/d;->l()V

    .line 27
    .line 28
    .line 29
    return v1

    .line 30
    :cond_0
    const-string v4, "S_TEXT/ASS"

    .line 31
    .line 32
    iget-object v5, v2, Lg9/c;->c:Ljava/lang/String;

    .line 33
    .line 34
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    if-nez v4, :cond_1e

    .line 39
    .line 40
    const-string v4, "S_TEXT/SSA"

    .line 41
    .line 42
    iget-object v5, v2, Lg9/c;->c:Ljava/lang/String;

    .line 43
    .line 44
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    if-eqz v4, :cond_1

    .line 49
    .line 50
    goto/16 :goto_e

    .line 51
    .line 52
    :cond_1
    const-string v4, "S_TEXT/WEBVTT"

    .line 53
    .line 54
    iget-object v5, v2, Lg9/c;->c:Ljava/lang/String;

    .line 55
    .line 56
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    if-eqz v4, :cond_2

    .line 61
    .line 62
    sget-object v2, Lg9/d;->i0:[B

    .line 63
    .line 64
    invoke-virtual {v0, v1, v2, v3}, Lg9/d;->o(Lo8/p;[BI)V

    .line 65
    .line 66
    .line 67
    iget v1, v0, Lg9/d;->W:I

    .line 68
    .line 69
    invoke-virtual {v0}, Lg9/d;->l()V

    .line 70
    .line 71
    .line 72
    return v1

    .line 73
    :cond_2
    iget-object v4, v2, Lg9/c;->Z:Lo8/i0;

    .line 74
    .line 75
    iget-boolean v5, v0, Lg9/d;->Y:Z

    .line 76
    .line 77
    iget-object v6, v0, Lg9/d;->l:Lw7/p;

    .line 78
    .line 79
    const/4 v7, 0x4

    .line 80
    const/4 v8, 0x2

    .line 81
    const/4 v9, 0x1

    .line 82
    const/4 v10, 0x0

    .line 83
    if-nez v5, :cond_13

    .line 84
    .line 85
    iget-boolean v5, v2, Lg9/c;->i:Z

    .line 86
    .line 87
    iget-object v11, v0, Lg9/d;->i:Lw7/p;

    .line 88
    .line 89
    if-eqz v5, :cond_e

    .line 90
    .line 91
    iget v5, v0, Lg9/d;->R:I

    .line 92
    .line 93
    const v12, -0x40000001    # -1.9999999f

    .line 94
    .line 95
    .line 96
    and-int/2addr v5, v12

    .line 97
    iput v5, v0, Lg9/d;->R:I

    .line 98
    .line 99
    iget-boolean v5, v0, Lg9/d;->Z:Z

    .line 100
    .line 101
    const/16 v12, 0x80

    .line 102
    .line 103
    if-nez v5, :cond_4

    .line 104
    .line 105
    iget-object v5, v11, Lw7/p;->a:[B

    .line 106
    .line 107
    invoke-interface {v1, v5, v10, v9}, Lo8/p;->readFully([BII)V

    .line 108
    .line 109
    .line 110
    iget v5, v0, Lg9/d;->V:I

    .line 111
    .line 112
    add-int/2addr v5, v9

    .line 113
    iput v5, v0, Lg9/d;->V:I

    .line 114
    .line 115
    iget-object v5, v11, Lw7/p;->a:[B

    .line 116
    .line 117
    aget-byte v5, v5, v10

    .line 118
    .line 119
    and-int/lit16 v13, v5, 0x80

    .line 120
    .line 121
    if-eq v13, v12, :cond_3

    .line 122
    .line 123
    iput-byte v5, v0, Lg9/d;->c0:B

    .line 124
    .line 125
    iput-boolean v9, v0, Lg9/d;->Z:Z

    .line 126
    .line 127
    goto :goto_0

    .line 128
    :cond_3
    const-string v0, "Extension bit is set in signal byte"

    .line 129
    .line 130
    const/4 v1, 0x0

    .line 131
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    throw v0

    .line 136
    :cond_4
    :goto_0
    iget-byte v5, v0, Lg9/d;->c0:B

    .line 137
    .line 138
    and-int/lit8 v13, v5, 0x1

    .line 139
    .line 140
    if-ne v13, v9, :cond_f

    .line 141
    .line 142
    and-int/2addr v5, v8

    .line 143
    if-ne v5, v8, :cond_5

    .line 144
    .line 145
    move v5, v9

    .line 146
    goto :goto_1

    .line 147
    :cond_5
    move v5, v10

    .line 148
    :goto_1
    iget v13, v0, Lg9/d;->R:I

    .line 149
    .line 150
    const/high16 v14, 0x40000000    # 2.0f

    .line 151
    .line 152
    or-int/2addr v13, v14

    .line 153
    iput v13, v0, Lg9/d;->R:I

    .line 154
    .line 155
    iget-boolean v13, v0, Lg9/d;->d0:Z

    .line 156
    .line 157
    if-nez v13, :cond_7

    .line 158
    .line 159
    iget-object v13, v0, Lg9/d;->n:Lw7/p;

    .line 160
    .line 161
    iget-object v14, v13, Lw7/p;->a:[B

    .line 162
    .line 163
    const/16 v15, 0x8

    .line 164
    .line 165
    invoke-interface {v1, v14, v10, v15}, Lo8/p;->readFully([BII)V

    .line 166
    .line 167
    .line 168
    iget v14, v0, Lg9/d;->V:I

    .line 169
    .line 170
    add-int/2addr v14, v15

    .line 171
    iput v14, v0, Lg9/d;->V:I

    .line 172
    .line 173
    iput-boolean v9, v0, Lg9/d;->d0:Z

    .line 174
    .line 175
    iget-object v14, v11, Lw7/p;->a:[B

    .line 176
    .line 177
    if-eqz v5, :cond_6

    .line 178
    .line 179
    goto :goto_2

    .line 180
    :cond_6
    move v12, v10

    .line 181
    :goto_2
    or-int/2addr v12, v15

    .line 182
    int-to-byte v12, v12

    .line 183
    aput-byte v12, v14, v10

    .line 184
    .line 185
    invoke-virtual {v11, v10}, Lw7/p;->I(I)V

    .line 186
    .line 187
    .line 188
    invoke-interface {v4, v11, v9, v9}, Lo8/i0;->a(Lw7/p;II)V

    .line 189
    .line 190
    .line 191
    iget v12, v0, Lg9/d;->W:I

    .line 192
    .line 193
    add-int/2addr v12, v9

    .line 194
    iput v12, v0, Lg9/d;->W:I

    .line 195
    .line 196
    invoke-virtual {v13, v10}, Lw7/p;->I(I)V

    .line 197
    .line 198
    .line 199
    invoke-interface {v4, v13, v15, v9}, Lo8/i0;->a(Lw7/p;II)V

    .line 200
    .line 201
    .line 202
    iget v12, v0, Lg9/d;->W:I

    .line 203
    .line 204
    add-int/2addr v12, v15

    .line 205
    iput v12, v0, Lg9/d;->W:I

    .line 206
    .line 207
    :cond_7
    if-eqz v5, :cond_f

    .line 208
    .line 209
    iget-boolean v5, v0, Lg9/d;->a0:Z

    .line 210
    .line 211
    if-nez v5, :cond_8

    .line 212
    .line 213
    iget-object v5, v11, Lw7/p;->a:[B

    .line 214
    .line 215
    invoke-interface {v1, v5, v10, v9}, Lo8/p;->readFully([BII)V

    .line 216
    .line 217
    .line 218
    iget v5, v0, Lg9/d;->V:I

    .line 219
    .line 220
    add-int/2addr v5, v9

    .line 221
    iput v5, v0, Lg9/d;->V:I

    .line 222
    .line 223
    invoke-virtual {v11, v10}, Lw7/p;->I(I)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {v11}, Lw7/p;->w()I

    .line 227
    .line 228
    .line 229
    move-result v5

    .line 230
    iput v5, v0, Lg9/d;->b0:I

    .line 231
    .line 232
    iput-boolean v9, v0, Lg9/d;->a0:Z

    .line 233
    .line 234
    :cond_8
    iget v5, v0, Lg9/d;->b0:I

    .line 235
    .line 236
    mul-int/2addr v5, v7

    .line 237
    invoke-virtual {v11, v5}, Lw7/p;->F(I)V

    .line 238
    .line 239
    .line 240
    iget-object v12, v11, Lw7/p;->a:[B

    .line 241
    .line 242
    invoke-interface {v1, v12, v10, v5}, Lo8/p;->readFully([BII)V

    .line 243
    .line 244
    .line 245
    iget v12, v0, Lg9/d;->V:I

    .line 246
    .line 247
    add-int/2addr v12, v5

    .line 248
    iput v12, v0, Lg9/d;->V:I

    .line 249
    .line 250
    iget v5, v0, Lg9/d;->b0:I

    .line 251
    .line 252
    div-int/2addr v5, v8

    .line 253
    add-int/2addr v5, v9

    .line 254
    int-to-short v5, v5

    .line 255
    mul-int/lit8 v12, v5, 0x6

    .line 256
    .line 257
    add-int/2addr v12, v8

    .line 258
    iget-object v13, v0, Lg9/d;->q:Ljava/nio/ByteBuffer;

    .line 259
    .line 260
    if-eqz v13, :cond_9

    .line 261
    .line 262
    invoke-virtual {v13}, Ljava/nio/Buffer;->capacity()I

    .line 263
    .line 264
    .line 265
    move-result v13

    .line 266
    if-ge v13, v12, :cond_a

    .line 267
    .line 268
    :cond_9
    invoke-static {v12}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 269
    .line 270
    .line 271
    move-result-object v13

    .line 272
    iput-object v13, v0, Lg9/d;->q:Ljava/nio/ByteBuffer;

    .line 273
    .line 274
    :cond_a
    iget-object v13, v0, Lg9/d;->q:Ljava/nio/ByteBuffer;

    .line 275
    .line 276
    invoke-virtual {v13, v10}, Ljava/nio/ByteBuffer;->position(I)Ljava/nio/Buffer;

    .line 277
    .line 278
    .line 279
    iget-object v13, v0, Lg9/d;->q:Ljava/nio/ByteBuffer;

    .line 280
    .line 281
    invoke-virtual {v13, v5}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 282
    .line 283
    .line 284
    move v5, v10

    .line 285
    move v13, v5

    .line 286
    :goto_3
    iget v14, v0, Lg9/d;->b0:I

    .line 287
    .line 288
    if-ge v5, v14, :cond_c

    .line 289
    .line 290
    invoke-virtual {v11}, Lw7/p;->A()I

    .line 291
    .line 292
    .line 293
    move-result v14

    .line 294
    rem-int/lit8 v15, v5, 0x2

    .line 295
    .line 296
    if-nez v15, :cond_b

    .line 297
    .line 298
    iget-object v15, v0, Lg9/d;->q:Ljava/nio/ByteBuffer;

    .line 299
    .line 300
    sub-int v13, v14, v13

    .line 301
    .line 302
    int-to-short v13, v13

    .line 303
    invoke-virtual {v15, v13}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 304
    .line 305
    .line 306
    goto :goto_4

    .line 307
    :cond_b
    iget-object v15, v0, Lg9/d;->q:Ljava/nio/ByteBuffer;

    .line 308
    .line 309
    sub-int v13, v14, v13

    .line 310
    .line 311
    invoke-virtual {v15, v13}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 312
    .line 313
    .line 314
    :goto_4
    add-int/lit8 v5, v5, 0x1

    .line 315
    .line 316
    move v13, v14

    .line 317
    goto :goto_3

    .line 318
    :cond_c
    iget v5, v0, Lg9/d;->V:I

    .line 319
    .line 320
    sub-int v5, v3, v5

    .line 321
    .line 322
    sub-int/2addr v5, v13

    .line 323
    rem-int/2addr v14, v8

    .line 324
    if-ne v14, v9, :cond_d

    .line 325
    .line 326
    iget-object v13, v0, Lg9/d;->q:Ljava/nio/ByteBuffer;

    .line 327
    .line 328
    invoke-virtual {v13, v5}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 329
    .line 330
    .line 331
    goto :goto_5

    .line 332
    :cond_d
    iget-object v13, v0, Lg9/d;->q:Ljava/nio/ByteBuffer;

    .line 333
    .line 334
    int-to-short v5, v5

    .line 335
    invoke-virtual {v13, v5}, Ljava/nio/ByteBuffer;->putShort(S)Ljava/nio/ByteBuffer;

    .line 336
    .line 337
    .line 338
    iget-object v5, v0, Lg9/d;->q:Ljava/nio/ByteBuffer;

    .line 339
    .line 340
    invoke-virtual {v5, v10}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 341
    .line 342
    .line 343
    :goto_5
    iget-object v5, v0, Lg9/d;->q:Ljava/nio/ByteBuffer;

    .line 344
    .line 345
    invoke-virtual {v5}, Ljava/nio/ByteBuffer;->array()[B

    .line 346
    .line 347
    .line 348
    move-result-object v5

    .line 349
    iget-object v13, v0, Lg9/d;->o:Lw7/p;

    .line 350
    .line 351
    invoke-virtual {v13, v12, v5}, Lw7/p;->G(I[B)V

    .line 352
    .line 353
    .line 354
    invoke-interface {v4, v13, v12, v9}, Lo8/i0;->a(Lw7/p;II)V

    .line 355
    .line 356
    .line 357
    iget v5, v0, Lg9/d;->W:I

    .line 358
    .line 359
    add-int/2addr v5, v12

    .line 360
    iput v5, v0, Lg9/d;->W:I

    .line 361
    .line 362
    goto :goto_6

    .line 363
    :cond_e
    iget-object v5, v2, Lg9/c;->j:[B

    .line 364
    .line 365
    if-eqz v5, :cond_f

    .line 366
    .line 367
    array-length v12, v5

    .line 368
    invoke-virtual {v6, v12, v5}, Lw7/p;->G(I[B)V

    .line 369
    .line 370
    .line 371
    :cond_f
    :goto_6
    const-string v5, "A_OPUS"

    .line 372
    .line 373
    iget-object v12, v2, Lg9/c;->c:Ljava/lang/String;

    .line 374
    .line 375
    invoke-virtual {v5, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 376
    .line 377
    .line 378
    move-result v5

    .line 379
    if-eqz v5, :cond_10

    .line 380
    .line 381
    move/from16 v5, p4

    .line 382
    .line 383
    goto :goto_7

    .line 384
    :cond_10
    iget v5, v2, Lg9/c;->g:I

    .line 385
    .line 386
    if-lez v5, :cond_11

    .line 387
    .line 388
    move v5, v9

    .line 389
    goto :goto_7

    .line 390
    :cond_11
    move v5, v10

    .line 391
    :goto_7
    if-eqz v5, :cond_12

    .line 392
    .line 393
    iget v5, v0, Lg9/d;->R:I

    .line 394
    .line 395
    const/high16 v12, 0x10000000

    .line 396
    .line 397
    or-int/2addr v5, v12

    .line 398
    iput v5, v0, Lg9/d;->R:I

    .line 399
    .line 400
    iget-object v5, v0, Lg9/d;->p:Lw7/p;

    .line 401
    .line 402
    invoke-virtual {v5, v10}, Lw7/p;->F(I)V

    .line 403
    .line 404
    .line 405
    iget v5, v6, Lw7/p;->c:I

    .line 406
    .line 407
    add-int/2addr v5, v3

    .line 408
    iget v12, v0, Lg9/d;->V:I

    .line 409
    .line 410
    sub-int/2addr v5, v12

    .line 411
    invoke-virtual {v11, v7}, Lw7/p;->F(I)V

    .line 412
    .line 413
    .line 414
    iget-object v12, v11, Lw7/p;->a:[B

    .line 415
    .line 416
    shr-int/lit8 v13, v5, 0x18

    .line 417
    .line 418
    and-int/lit16 v13, v13, 0xff

    .line 419
    .line 420
    int-to-byte v13, v13

    .line 421
    aput-byte v13, v12, v10

    .line 422
    .line 423
    shr-int/lit8 v13, v5, 0x10

    .line 424
    .line 425
    and-int/lit16 v13, v13, 0xff

    .line 426
    .line 427
    int-to-byte v13, v13

    .line 428
    aput-byte v13, v12, v9

    .line 429
    .line 430
    shr-int/lit8 v13, v5, 0x8

    .line 431
    .line 432
    and-int/lit16 v13, v13, 0xff

    .line 433
    .line 434
    int-to-byte v13, v13

    .line 435
    aput-byte v13, v12, v8

    .line 436
    .line 437
    and-int/lit16 v5, v5, 0xff

    .line 438
    .line 439
    int-to-byte v5, v5

    .line 440
    const/4 v13, 0x3

    .line 441
    aput-byte v5, v12, v13

    .line 442
    .line 443
    invoke-interface {v4, v11, v7, v8}, Lo8/i0;->a(Lw7/p;II)V

    .line 444
    .line 445
    .line 446
    iget v5, v0, Lg9/d;->W:I

    .line 447
    .line 448
    add-int/2addr v5, v7

    .line 449
    iput v5, v0, Lg9/d;->W:I

    .line 450
    .line 451
    :cond_12
    iput-boolean v9, v0, Lg9/d;->Y:Z

    .line 452
    .line 453
    :cond_13
    iget v5, v6, Lw7/p;->c:I

    .line 454
    .line 455
    add-int/2addr v3, v5

    .line 456
    const-string v5, "V_MPEG4/ISO/AVC"

    .line 457
    .line 458
    iget-object v11, v2, Lg9/c;->c:Ljava/lang/String;

    .line 459
    .line 460
    invoke-virtual {v5, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 461
    .line 462
    .line 463
    move-result v5

    .line 464
    if-nez v5, :cond_18

    .line 465
    .line 466
    const-string v5, "V_MPEGH/ISO/HEVC"

    .line 467
    .line 468
    iget-object v11, v2, Lg9/c;->c:Ljava/lang/String;

    .line 469
    .line 470
    invoke-virtual {v5, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 471
    .line 472
    .line 473
    move-result v5

    .line 474
    if-eqz v5, :cond_14

    .line 475
    .line 476
    goto :goto_b

    .line 477
    :cond_14
    iget-object v5, v2, Lg9/c;->V:Lo8/j0;

    .line 478
    .line 479
    if-eqz v5, :cond_16

    .line 480
    .line 481
    iget v5, v6, Lw7/p;->c:I

    .line 482
    .line 483
    if-nez v5, :cond_15

    .line 484
    .line 485
    goto :goto_8

    .line 486
    :cond_15
    move v9, v10

    .line 487
    :goto_8
    invoke-static {v9}, Lw7/a;->j(Z)V

    .line 488
    .line 489
    .line 490
    iget-object v5, v2, Lg9/c;->V:Lo8/j0;

    .line 491
    .line 492
    invoke-virtual {v5, v1}, Lo8/j0;->c(Lo8/p;)V

    .line 493
    .line 494
    .line 495
    :cond_16
    :goto_9
    iget v5, v0, Lg9/d;->V:I

    .line 496
    .line 497
    if-ge v5, v3, :cond_1c

    .line 498
    .line 499
    sub-int v5, v3, v5

    .line 500
    .line 501
    invoke-virtual {v6}, Lw7/p;->a()I

    .line 502
    .line 503
    .line 504
    move-result v8

    .line 505
    if-lez v8, :cond_17

    .line 506
    .line 507
    invoke-static {v5, v8}, Ljava/lang/Math;->min(II)I

    .line 508
    .line 509
    .line 510
    move-result v5

    .line 511
    invoke-interface {v4, v6, v5, v10}, Lo8/i0;->a(Lw7/p;II)V

    .line 512
    .line 513
    .line 514
    goto :goto_a

    .line 515
    :cond_17
    invoke-interface {v4, v1, v5, v10}, Lo8/i0;->d(Lt7/g;IZ)I

    .line 516
    .line 517
    .line 518
    move-result v5

    .line 519
    :goto_a
    iget v8, v0, Lg9/d;->V:I

    .line 520
    .line 521
    add-int/2addr v8, v5

    .line 522
    iput v8, v0, Lg9/d;->V:I

    .line 523
    .line 524
    iget v8, v0, Lg9/d;->W:I

    .line 525
    .line 526
    add-int/2addr v8, v5

    .line 527
    iput v8, v0, Lg9/d;->W:I

    .line 528
    .line 529
    goto :goto_9

    .line 530
    :cond_18
    :goto_b
    iget-object v5, v0, Lg9/d;->h:Lw7/p;

    .line 531
    .line 532
    iget-object v11, v5, Lw7/p;->a:[B

    .line 533
    .line 534
    aput-byte v10, v11, v10

    .line 535
    .line 536
    aput-byte v10, v11, v9

    .line 537
    .line 538
    aput-byte v10, v11, v8

    .line 539
    .line 540
    iget v8, v2, Lg9/c;->a0:I

    .line 541
    .line 542
    rsub-int/lit8 v9, v8, 0x4

    .line 543
    .line 544
    :goto_c
    iget v12, v0, Lg9/d;->V:I

    .line 545
    .line 546
    if-ge v12, v3, :cond_1c

    .line 547
    .line 548
    iget v12, v0, Lg9/d;->X:I

    .line 549
    .line 550
    if-nez v12, :cond_1a

    .line 551
    .line 552
    invoke-virtual {v6}, Lw7/p;->a()I

    .line 553
    .line 554
    .line 555
    move-result v12

    .line 556
    invoke-static {v8, v12}, Ljava/lang/Math;->min(II)I

    .line 557
    .line 558
    .line 559
    move-result v12

    .line 560
    add-int v13, v9, v12

    .line 561
    .line 562
    sub-int v14, v8, v12

    .line 563
    .line 564
    invoke-interface {v1, v11, v13, v14}, Lo8/p;->readFully([BII)V

    .line 565
    .line 566
    .line 567
    if-lez v12, :cond_19

    .line 568
    .line 569
    invoke-virtual {v6, v11, v9, v12}, Lw7/p;->h([BII)V

    .line 570
    .line 571
    .line 572
    :cond_19
    iget v12, v0, Lg9/d;->V:I

    .line 573
    .line 574
    add-int/2addr v12, v8

    .line 575
    iput v12, v0, Lg9/d;->V:I

    .line 576
    .line 577
    invoke-virtual {v5, v10}, Lw7/p;->I(I)V

    .line 578
    .line 579
    .line 580
    invoke-virtual {v5}, Lw7/p;->A()I

    .line 581
    .line 582
    .line 583
    move-result v12

    .line 584
    iput v12, v0, Lg9/d;->X:I

    .line 585
    .line 586
    iget-object v12, v0, Lg9/d;->g:Lw7/p;

    .line 587
    .line 588
    invoke-virtual {v12, v10}, Lw7/p;->I(I)V

    .line 589
    .line 590
    .line 591
    invoke-interface {v4, v12, v7, v10}, Lo8/i0;->a(Lw7/p;II)V

    .line 592
    .line 593
    .line 594
    iget v12, v0, Lg9/d;->W:I

    .line 595
    .line 596
    add-int/2addr v12, v7

    .line 597
    iput v12, v0, Lg9/d;->W:I

    .line 598
    .line 599
    goto :goto_c

    .line 600
    :cond_1a
    invoke-virtual {v6}, Lw7/p;->a()I

    .line 601
    .line 602
    .line 603
    move-result v13

    .line 604
    if-lez v13, :cond_1b

    .line 605
    .line 606
    invoke-static {v12, v13}, Ljava/lang/Math;->min(II)I

    .line 607
    .line 608
    .line 609
    move-result v12

    .line 610
    invoke-interface {v4, v6, v12, v10}, Lo8/i0;->a(Lw7/p;II)V

    .line 611
    .line 612
    .line 613
    goto :goto_d

    .line 614
    :cond_1b
    invoke-interface {v4, v1, v12, v10}, Lo8/i0;->d(Lt7/g;IZ)I

    .line 615
    .line 616
    .line 617
    move-result v12

    .line 618
    :goto_d
    iget v13, v0, Lg9/d;->V:I

    .line 619
    .line 620
    add-int/2addr v13, v12

    .line 621
    iput v13, v0, Lg9/d;->V:I

    .line 622
    .line 623
    iget v13, v0, Lg9/d;->W:I

    .line 624
    .line 625
    add-int/2addr v13, v12

    .line 626
    iput v13, v0, Lg9/d;->W:I

    .line 627
    .line 628
    iget v13, v0, Lg9/d;->X:I

    .line 629
    .line 630
    sub-int/2addr v13, v12

    .line 631
    iput v13, v0, Lg9/d;->X:I

    .line 632
    .line 633
    goto :goto_c

    .line 634
    :cond_1c
    const-string v1, "A_VORBIS"

    .line 635
    .line 636
    iget-object v2, v2, Lg9/c;->c:Ljava/lang/String;

    .line 637
    .line 638
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 639
    .line 640
    .line 641
    move-result v1

    .line 642
    if-eqz v1, :cond_1d

    .line 643
    .line 644
    iget-object v1, v0, Lg9/d;->j:Lw7/p;

    .line 645
    .line 646
    invoke-virtual {v1, v10}, Lw7/p;->I(I)V

    .line 647
    .line 648
    .line 649
    invoke-interface {v4, v1, v7, v10}, Lo8/i0;->a(Lw7/p;II)V

    .line 650
    .line 651
    .line 652
    iget v1, v0, Lg9/d;->W:I

    .line 653
    .line 654
    add-int/2addr v1, v7

    .line 655
    iput v1, v0, Lg9/d;->W:I

    .line 656
    .line 657
    :cond_1d
    iget v1, v0, Lg9/d;->W:I

    .line 658
    .line 659
    invoke-virtual {v0}, Lg9/d;->l()V

    .line 660
    .line 661
    .line 662
    return v1

    .line 663
    :cond_1e
    :goto_e
    sget-object v2, Lg9/d;->h0:[B

    .line 664
    .line 665
    invoke-virtual {v0, v1, v2, v3}, Lg9/d;->o(Lo8/p;[BI)V

    .line 666
    .line 667
    .line 668
    iget v1, v0, Lg9/d;->W:I

    .line 669
    .line 670
    invoke-virtual {v0}, Lg9/d;->l()V

    .line 671
    .line 672
    .line 673
    return v1
.end method

.method public final o(Lo8/p;[BI)V
    .locals 4

    .line 1
    array-length v0, p2

    .line 2
    add-int/2addr v0, p3

    .line 3
    iget-object p0, p0, Lg9/d;->m:Lw7/p;

    .line 4
    .line 5
    iget-object v1, p0, Lw7/p;->a:[B

    .line 6
    .line 7
    array-length v2, v1

    .line 8
    const/4 v3, 0x0

    .line 9
    if-ge v2, v0, :cond_0

    .line 10
    .line 11
    add-int v1, v0, p3

    .line 12
    .line 13
    invoke-static {p2, v1}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    array-length v2, v1

    .line 21
    invoke-virtual {p0, v2, v1}, Lw7/p;->G(I[B)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    array-length v2, p2

    .line 26
    invoke-static {p2, v3, v1, v3, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, p0, Lw7/p;->a:[B

    .line 30
    .line 31
    array-length p2, p2

    .line 32
    invoke-interface {p1, v1, p2, p3}, Lo8/p;->readFully([BII)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, v3}, Lw7/p;->I(I)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, v0}, Lw7/p;->H(I)V

    .line 39
    .line 40
    .line 41
    return-void
.end method
