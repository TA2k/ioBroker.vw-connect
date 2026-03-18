.class public final Landroidx/glance/appwidget/protobuf/j;
.super Ljp/h1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Ljava/util/logging/Logger;

.field public static final g:Z


# instance fields
.field public a:Landroidx/glance/appwidget/protobuf/h0;

.field public final b:[B

.field public final c:I

.field public d:I

.field public final e:Lm6/b1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Landroidx/glance/appwidget/protobuf/j;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Landroidx/glance/appwidget/protobuf/j;->f:Ljava/util/logging/Logger;

    .line 12
    .line 13
    sget-boolean v0, Landroidx/glance/appwidget/protobuf/e1;->e:Z

    .line 14
    .line 15
    sput-boolean v0, Landroidx/glance/appwidget/protobuf/j;->g:Z

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Lm6/b1;I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-ltz p2, :cond_0

    .line 5
    .line 6
    const/16 v0, 0x14

    .line 7
    .line 8
    invoke-static {p2, v0}, Ljava/lang/Math;->max(II)I

    .line 9
    .line 10
    .line 11
    move-result p2

    .line 12
    new-array v0, p2, [B

    .line 13
    .line 14
    iput-object v0, p0, Landroidx/glance/appwidget/protobuf/j;->b:[B

    .line 15
    .line 16
    iput p2, p0, Landroidx/glance/appwidget/protobuf/j;->c:I

    .line 17
    .line 18
    iput-object p1, p0, Landroidx/glance/appwidget/protobuf/j;->e:Lm6/b1;

    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 22
    .line 23
    const-string p1, "bufferSize must be >= 0"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0
.end method

.method public static h(ILandroidx/glance/appwidget/protobuf/g;)I
    .locals 1

    .line 1
    invoke-static {p0}, Landroidx/glance/appwidget/protobuf/j;->j(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-virtual {p1}, Landroidx/glance/appwidget/protobuf/g;->size()I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    invoke-static {p1}, Landroidx/glance/appwidget/protobuf/j;->k(I)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    add-int/2addr v0, p1

    .line 14
    add-int/2addr v0, p0

    .line 15
    return v0
.end method

.method public static i(Ljava/lang/String;)I
    .locals 1

    .line 1
    :try_start_0
    invoke-static {p0}, Landroidx/glance/appwidget/protobuf/h1;->a(Ljava/lang/String;)I

    .line 2
    .line 3
    .line 4
    move-result p0
    :try_end_0
    .catch Landroidx/glance/appwidget/protobuf/g1; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    goto :goto_0

    .line 6
    :catch_0
    sget-object v0, Landroidx/glance/appwidget/protobuf/y;->a:Ljava/nio/charset/Charset;

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    array-length p0, p0

    .line 13
    :goto_0
    invoke-static {p0}, Landroidx/glance/appwidget/protobuf/j;->k(I)I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    add-int/2addr v0, p0

    .line 18
    return v0
.end method

.method public static j(I)I
    .locals 0

    .line 1
    shl-int/lit8 p0, p0, 0x3

    .line 2
    .line 3
    invoke-static {p0}, Landroidx/glance/appwidget/protobuf/j;->k(I)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public static k(I)I
    .locals 0

    .line 1
    invoke-static {p0}, Ljava/lang/Integer;->numberOfLeadingZeros(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    mul-int/lit8 p0, p0, 0x9

    .line 6
    .line 7
    rsub-int p0, p0, 0x160

    .line 8
    .line 9
    ushr-int/lit8 p0, p0, 0x6

    .line 10
    .line 11
    return p0
.end method

.method public static l(J)I
    .locals 0

    .line 1
    invoke-static {p0, p1}, Ljava/lang/Long;->numberOfLeadingZeros(J)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    mul-int/lit8 p0, p0, 0x9

    .line 6
    .line 7
    rsub-int p0, p0, 0x280

    .line 8
    .line 9
    ushr-int/lit8 p0, p0, 0x6

    .line 10
    .line 11
    return p0
.end method


# virtual methods
.method public final A(II)V
    .locals 1

    .line 1
    const/16 v0, 0x14

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroidx/glance/appwidget/protobuf/j;->n(I)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-virtual {p0, p1, v0}, Landroidx/glance/appwidget/protobuf/j;->e(II)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p2}, Landroidx/glance/appwidget/protobuf/j;->f(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final B(I)V
    .locals 1

    .line 1
    const/4 v0, 0x5

    .line 2
    invoke-virtual {p0, v0}, Landroidx/glance/appwidget/protobuf/j;->n(I)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroidx/glance/appwidget/protobuf/j;->f(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final C(IJ)V
    .locals 1

    .line 1
    const/16 v0, 0x14

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroidx/glance/appwidget/protobuf/j;->n(I)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-virtual {p0, p1, v0}, Landroidx/glance/appwidget/protobuf/j;->e(II)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p2, p3}, Landroidx/glance/appwidget/protobuf/j;->g(J)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final D(J)V
    .locals 1

    .line 1
    const/16 v0, 0xa

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroidx/glance/appwidget/protobuf/j;->n(I)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Landroidx/glance/appwidget/protobuf/j;->g(J)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final b([BII)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2, p3}, Landroidx/glance/appwidget/protobuf/j;->o([BII)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final c(I)V
    .locals 5

    .line 1
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 2
    .line 3
    add-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    iput v1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 6
    .line 7
    and-int/lit16 v2, p1, 0xff

    .line 8
    .line 9
    int-to-byte v2, v2

    .line 10
    iget-object v3, p0, Landroidx/glance/appwidget/protobuf/j;->b:[B

    .line 11
    .line 12
    aput-byte v2, v3, v0

    .line 13
    .line 14
    add-int/lit8 v2, v0, 0x2

    .line 15
    .line 16
    iput v2, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 17
    .line 18
    shr-int/lit8 v4, p1, 0x8

    .line 19
    .line 20
    and-int/lit16 v4, v4, 0xff

    .line 21
    .line 22
    int-to-byte v4, v4

    .line 23
    aput-byte v4, v3, v1

    .line 24
    .line 25
    add-int/lit8 v1, v0, 0x3

    .line 26
    .line 27
    iput v1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 28
    .line 29
    shr-int/lit8 v4, p1, 0x10

    .line 30
    .line 31
    and-int/lit16 v4, v4, 0xff

    .line 32
    .line 33
    int-to-byte v4, v4

    .line 34
    aput-byte v4, v3, v2

    .line 35
    .line 36
    add-int/lit8 v0, v0, 0x4

    .line 37
    .line 38
    iput v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 39
    .line 40
    shr-int/lit8 p0, p1, 0x18

    .line 41
    .line 42
    and-int/lit16 p0, p0, 0xff

    .line 43
    .line 44
    int-to-byte p0, p0

    .line 45
    aput-byte p0, v3, v1

    .line 46
    .line 47
    return-void
.end method

.method public final d(J)V
    .locals 9

    .line 1
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 2
    .line 3
    add-int/lit8 v1, v0, 0x1

    .line 4
    .line 5
    iput v1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 6
    .line 7
    const-wide/16 v2, 0xff

    .line 8
    .line 9
    and-long v4, p1, v2

    .line 10
    .line 11
    long-to-int v4, v4

    .line 12
    int-to-byte v4, v4

    .line 13
    iget-object v5, p0, Landroidx/glance/appwidget/protobuf/j;->b:[B

    .line 14
    .line 15
    aput-byte v4, v5, v0

    .line 16
    .line 17
    add-int/lit8 v4, v0, 0x2

    .line 18
    .line 19
    iput v4, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 20
    .line 21
    const/16 v6, 0x8

    .line 22
    .line 23
    shr-long v7, p1, v6

    .line 24
    .line 25
    and-long/2addr v7, v2

    .line 26
    long-to-int v7, v7

    .line 27
    int-to-byte v7, v7

    .line 28
    aput-byte v7, v5, v1

    .line 29
    .line 30
    add-int/lit8 v1, v0, 0x3

    .line 31
    .line 32
    iput v1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 33
    .line 34
    const/16 v7, 0x10

    .line 35
    .line 36
    shr-long v7, p1, v7

    .line 37
    .line 38
    and-long/2addr v7, v2

    .line 39
    long-to-int v7, v7

    .line 40
    int-to-byte v7, v7

    .line 41
    aput-byte v7, v5, v4

    .line 42
    .line 43
    add-int/lit8 v4, v0, 0x4

    .line 44
    .line 45
    iput v4, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 46
    .line 47
    const/16 v7, 0x18

    .line 48
    .line 49
    shr-long v7, p1, v7

    .line 50
    .line 51
    and-long/2addr v2, v7

    .line 52
    long-to-int v2, v2

    .line 53
    int-to-byte v2, v2

    .line 54
    aput-byte v2, v5, v1

    .line 55
    .line 56
    add-int/lit8 v1, v0, 0x5

    .line 57
    .line 58
    iput v1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 59
    .line 60
    const/16 v2, 0x20

    .line 61
    .line 62
    shr-long v2, p1, v2

    .line 63
    .line 64
    long-to-int v2, v2

    .line 65
    and-int/lit16 v2, v2, 0xff

    .line 66
    .line 67
    int-to-byte v2, v2

    .line 68
    aput-byte v2, v5, v4

    .line 69
    .line 70
    add-int/lit8 v2, v0, 0x6

    .line 71
    .line 72
    iput v2, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 73
    .line 74
    const/16 v3, 0x28

    .line 75
    .line 76
    shr-long v3, p1, v3

    .line 77
    .line 78
    long-to-int v3, v3

    .line 79
    and-int/lit16 v3, v3, 0xff

    .line 80
    .line 81
    int-to-byte v3, v3

    .line 82
    aput-byte v3, v5, v1

    .line 83
    .line 84
    add-int/lit8 v1, v0, 0x7

    .line 85
    .line 86
    iput v1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 87
    .line 88
    const/16 v3, 0x30

    .line 89
    .line 90
    shr-long v3, p1, v3

    .line 91
    .line 92
    long-to-int v3, v3

    .line 93
    and-int/lit16 v3, v3, 0xff

    .line 94
    .line 95
    int-to-byte v3, v3

    .line 96
    aput-byte v3, v5, v2

    .line 97
    .line 98
    add-int/2addr v0, v6

    .line 99
    iput v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 100
    .line 101
    const/16 p0, 0x38

    .line 102
    .line 103
    shr-long p0, p1, p0

    .line 104
    .line 105
    long-to-int p0, p0

    .line 106
    and-int/lit16 p0, p0, 0xff

    .line 107
    .line 108
    int-to-byte p0, p0

    .line 109
    aput-byte p0, v5, v1

    .line 110
    .line 111
    return-void
.end method

.method public final e(II)V
    .locals 0

    .line 1
    shl-int/lit8 p1, p1, 0x3

    .line 2
    .line 3
    or-int/2addr p1, p2

    .line 4
    invoke-virtual {p0, p1}, Landroidx/glance/appwidget/protobuf/j;->f(I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final f(I)V
    .locals 4

    .line 1
    sget-boolean v0, Landroidx/glance/appwidget/protobuf/j;->g:Z

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/glance/appwidget/protobuf/j;->b:[B

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    :goto_0
    and-int/lit8 v0, p1, -0x80

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 12
    .line 13
    add-int/lit8 v2, v0, 0x1

    .line 14
    .line 15
    iput v2, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 16
    .line 17
    int-to-long v2, v0

    .line 18
    int-to-byte p0, p1

    .line 19
    invoke-static {v1, v2, v3, p0}, Landroidx/glance/appwidget/protobuf/e1;->j([BJB)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 24
    .line 25
    add-int/lit8 v2, v0, 0x1

    .line 26
    .line 27
    iput v2, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 28
    .line 29
    int-to-long v2, v0

    .line 30
    or-int/lit16 v0, p1, 0x80

    .line 31
    .line 32
    and-int/lit16 v0, v0, 0xff

    .line 33
    .line 34
    int-to-byte v0, v0

    .line 35
    invoke-static {v1, v2, v3, v0}, Landroidx/glance/appwidget/protobuf/e1;->j([BJB)V

    .line 36
    .line 37
    .line 38
    ushr-int/lit8 p1, p1, 0x7

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    :goto_1
    and-int/lit8 v0, p1, -0x80

    .line 42
    .line 43
    if-nez v0, :cond_2

    .line 44
    .line 45
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 46
    .line 47
    add-int/lit8 v2, v0, 0x1

    .line 48
    .line 49
    iput v2, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 50
    .line 51
    int-to-byte p0, p1

    .line 52
    aput-byte p0, v1, v0

    .line 53
    .line 54
    return-void

    .line 55
    :cond_2
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 56
    .line 57
    add-int/lit8 v2, v0, 0x1

    .line 58
    .line 59
    iput v2, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 60
    .line 61
    or-int/lit16 v2, p1, 0x80

    .line 62
    .line 63
    and-int/lit16 v2, v2, 0xff

    .line 64
    .line 65
    int-to-byte v2, v2

    .line 66
    aput-byte v2, v1, v0

    .line 67
    .line 68
    ushr-int/lit8 p1, p1, 0x7

    .line 69
    .line 70
    goto :goto_1
.end method

.method public final g(J)V
    .locals 9

    .line 1
    sget-boolean v0, Landroidx/glance/appwidget/protobuf/j;->g:Z

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    const-wide/16 v2, 0x0

    .line 5
    .line 6
    const-wide/16 v4, -0x80

    .line 7
    .line 8
    iget-object v6, p0, Landroidx/glance/appwidget/protobuf/j;->b:[B

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    :goto_0
    and-long v7, p1, v4

    .line 13
    .line 14
    cmp-long v0, v7, v2

    .line 15
    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 19
    .line 20
    add-int/lit8 v1, v0, 0x1

    .line 21
    .line 22
    iput v1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 23
    .line 24
    int-to-long v0, v0

    .line 25
    long-to-int p0, p1

    .line 26
    int-to-byte p0, p0

    .line 27
    invoke-static {v6, v0, v1, p0}, Landroidx/glance/appwidget/protobuf/e1;->j([BJB)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_0
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 32
    .line 33
    add-int/lit8 v7, v0, 0x1

    .line 34
    .line 35
    iput v7, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 36
    .line 37
    int-to-long v7, v0

    .line 38
    long-to-int v0, p1

    .line 39
    or-int/lit16 v0, v0, 0x80

    .line 40
    .line 41
    and-int/lit16 v0, v0, 0xff

    .line 42
    .line 43
    int-to-byte v0, v0

    .line 44
    invoke-static {v6, v7, v8, v0}, Landroidx/glance/appwidget/protobuf/e1;->j([BJB)V

    .line 45
    .line 46
    .line 47
    ushr-long/2addr p1, v1

    .line 48
    goto :goto_0

    .line 49
    :cond_1
    :goto_1
    and-long v7, p1, v4

    .line 50
    .line 51
    cmp-long v0, v7, v2

    .line 52
    .line 53
    if-nez v0, :cond_2

    .line 54
    .line 55
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 56
    .line 57
    add-int/lit8 v1, v0, 0x1

    .line 58
    .line 59
    iput v1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 60
    .line 61
    long-to-int p0, p1

    .line 62
    int-to-byte p0, p0

    .line 63
    aput-byte p0, v6, v0

    .line 64
    .line 65
    return-void

    .line 66
    :cond_2
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 67
    .line 68
    add-int/lit8 v7, v0, 0x1

    .line 69
    .line 70
    iput v7, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 71
    .line 72
    long-to-int v7, p1

    .line 73
    or-int/lit16 v7, v7, 0x80

    .line 74
    .line 75
    and-int/lit16 v7, v7, 0xff

    .line 76
    .line 77
    int-to-byte v7, v7

    .line 78
    aput-byte v7, v6, v0

    .line 79
    .line 80
    ushr-long/2addr p1, v1

    .line 81
    goto :goto_1
.end method

.method public final m()V
    .locals 4

    .line 1
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/glance/appwidget/protobuf/j;->e:Lm6/b1;

    .line 4
    .line 5
    iget-object v2, p0, Landroidx/glance/appwidget/protobuf/j;->b:[B

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-virtual {v1, v2, v3, v0}, Lm6/b1;->write([BII)V

    .line 9
    .line 10
    .line 11
    iput v3, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 12
    .line 13
    return-void
.end method

.method public final n(I)V
    .locals 2

    .line 1
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->c:I

    .line 2
    .line 3
    iget v1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 4
    .line 5
    sub-int/2addr v0, v1

    .line 6
    if-ge v0, p1, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0}, Landroidx/glance/appwidget/protobuf/j;->m()V

    .line 9
    .line 10
    .line 11
    :cond_0
    return-void
.end method

.method public final o([BII)V
    .locals 4

    .line 1
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 2
    .line 3
    iget v1, p0, Landroidx/glance/appwidget/protobuf/j;->c:I

    .line 4
    .line 5
    sub-int v2, v1, v0

    .line 6
    .line 7
    iget-object v3, p0, Landroidx/glance/appwidget/protobuf/j;->b:[B

    .line 8
    .line 9
    if-lt v2, p3, :cond_0

    .line 10
    .line 11
    invoke-static {p1, p2, v3, v0, p3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 12
    .line 13
    .line 14
    iget p1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 15
    .line 16
    add-int/2addr p1, p3

    .line 17
    iput p1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    invoke-static {p1, p2, v3, v0, v2}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 21
    .line 22
    .line 23
    add-int/2addr p2, v2

    .line 24
    sub-int/2addr p3, v2

    .line 25
    iput v1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 26
    .line 27
    invoke-virtual {p0}, Landroidx/glance/appwidget/protobuf/j;->m()V

    .line 28
    .line 29
    .line 30
    if-gt p3, v1, :cond_1

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    invoke-static {p1, p2, v3, v0, p3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 34
    .line 35
    .line 36
    iput p3, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    iget-object p0, p0, Landroidx/glance/appwidget/protobuf/j;->e:Lm6/b1;

    .line 40
    .line 41
    invoke-virtual {p0, p1, p2, p3}, Lm6/b1;->write([BII)V

    .line 42
    .line 43
    .line 44
    :goto_0
    return-void
.end method

.method public final p(IZ)V
    .locals 1

    .line 1
    const/16 v0, 0xb

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroidx/glance/appwidget/protobuf/j;->n(I)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-virtual {p0, p1, v0}, Landroidx/glance/appwidget/protobuf/j;->e(II)V

    .line 8
    .line 9
    .line 10
    int-to-byte p1, p2

    .line 11
    iget p2, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 12
    .line 13
    add-int/lit8 v0, p2, 0x1

    .line 14
    .line 15
    iput v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 16
    .line 17
    iget-object p0, p0, Landroidx/glance/appwidget/protobuf/j;->b:[B

    .line 18
    .line 19
    aput-byte p1, p0, p2

    .line 20
    .line 21
    return-void
.end method

.method public final q(ILandroidx/glance/appwidget/protobuf/g;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-virtual {p0, p1, v0}, Landroidx/glance/appwidget/protobuf/j;->z(II)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p2}, Landroidx/glance/appwidget/protobuf/g;->size()I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    invoke-virtual {p0, p1}, Landroidx/glance/appwidget/protobuf/j;->B(I)V

    .line 10
    .line 11
    .line 12
    iget-object p1, p2, Landroidx/glance/appwidget/protobuf/g;->e:[B

    .line 13
    .line 14
    invoke-virtual {p2}, Landroidx/glance/appwidget/protobuf/g;->i()I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    invoke-virtual {p2}, Landroidx/glance/appwidget/protobuf/g;->size()I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    invoke-virtual {p0, p1, v0, p2}, Landroidx/glance/appwidget/protobuf/j;->b([BII)V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public final r(II)V
    .locals 1

    .line 1
    const/16 v0, 0xe

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroidx/glance/appwidget/protobuf/j;->n(I)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x5

    .line 7
    invoke-virtual {p0, p1, v0}, Landroidx/glance/appwidget/protobuf/j;->e(II)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p2}, Landroidx/glance/appwidget/protobuf/j;->c(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final s(I)V
    .locals 1

    .line 1
    const/4 v0, 0x4

    .line 2
    invoke-virtual {p0, v0}, Landroidx/glance/appwidget/protobuf/j;->n(I)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroidx/glance/appwidget/protobuf/j;->c(I)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final t(IJ)V
    .locals 1

    .line 1
    const/16 v0, 0x12

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroidx/glance/appwidget/protobuf/j;->n(I)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    invoke-virtual {p0, p1, v0}, Landroidx/glance/appwidget/protobuf/j;->e(II)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p2, p3}, Landroidx/glance/appwidget/protobuf/j;->d(J)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final u(J)V
    .locals 1

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroidx/glance/appwidget/protobuf/j;->n(I)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Landroidx/glance/appwidget/protobuf/j;->d(J)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public final v(II)V
    .locals 1

    .line 1
    const/16 v0, 0x14

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroidx/glance/appwidget/protobuf/j;->n(I)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-virtual {p0, p1, v0}, Landroidx/glance/appwidget/protobuf/j;->e(II)V

    .line 8
    .line 9
    .line 10
    if-ltz p2, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0, p2}, Landroidx/glance/appwidget/protobuf/j;->f(I)V

    .line 13
    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    int-to-long p1, p2

    .line 17
    invoke-virtual {p0, p1, p2}, Landroidx/glance/appwidget/protobuf/j;->g(J)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final w(I)V
    .locals 2

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroidx/glance/appwidget/protobuf/j;->B(I)V

    .line 4
    .line 5
    .line 6
    return-void

    .line 7
    :cond_0
    int-to-long v0, p1

    .line 8
    invoke-virtual {p0, v0, v1}, Landroidx/glance/appwidget/protobuf/j;->D(J)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final x(ILandroidx/glance/appwidget/protobuf/a;Landroidx/glance/appwidget/protobuf/v0;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-virtual {p0, p1, v0}, Landroidx/glance/appwidget/protobuf/j;->z(II)V

    .line 3
    .line 4
    .line 5
    invoke-virtual {p2, p3}, Landroidx/glance/appwidget/protobuf/a;->a(Landroidx/glance/appwidget/protobuf/v0;)I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    invoke-virtual {p0, p1}, Landroidx/glance/appwidget/protobuf/j;->B(I)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Landroidx/glance/appwidget/protobuf/j;->a:Landroidx/glance/appwidget/protobuf/h0;

    .line 13
    .line 14
    invoke-interface {p3, p2, p0}, Landroidx/glance/appwidget/protobuf/v0;->g(Ljava/lang/Object;Landroidx/glance/appwidget/protobuf/h0;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public final y(ILjava/lang/String;)V
    .locals 5

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-virtual {p0, p1, v0}, Landroidx/glance/appwidget/protobuf/j;->z(II)V

    .line 3
    .line 4
    .line 5
    :try_start_0
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    mul-int/lit8 p1, p1, 0x3

    .line 10
    .line 11
    invoke-static {p1}, Landroidx/glance/appwidget/protobuf/j;->k(I)I

    .line 12
    .line 13
    .line 14
    move-result v0
    :try_end_0
    .catch Landroidx/glance/appwidget/protobuf/g1; {:try_start_0 .. :try_end_0} :catch_0

    .line 15
    add-int v1, v0, p1

    .line 16
    .line 17
    iget v2, p0, Landroidx/glance/appwidget/protobuf/j;->c:I

    .line 18
    .line 19
    if-le v1, v2, :cond_0

    .line 20
    .line 21
    :try_start_1
    new-array v0, p1, [B

    .line 22
    .line 23
    sget-object v1, Landroidx/glance/appwidget/protobuf/h1;->a:Landroidx/glance/appwidget/protobuf/f1;

    .line 24
    .line 25
    const/4 v2, 0x0

    .line 26
    invoke-virtual {v1, v2, p1, p2, v0}, Landroidx/glance/appwidget/protobuf/f1;->d(IILjava/lang/String;[B)I

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    invoke-virtual {p0, p1}, Landroidx/glance/appwidget/protobuf/j;->B(I)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0, v0, v2, p1}, Landroidx/glance/appwidget/protobuf/j;->o([BII)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :catch_0
    move-exception p1

    .line 38
    goto :goto_2

    .line 39
    :cond_0
    iget p1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 40
    .line 41
    sub-int p1, v2, p1

    .line 42
    .line 43
    if-le v1, p1, :cond_1

    .line 44
    .line 45
    invoke-virtual {p0}, Landroidx/glance/appwidget/protobuf/j;->m()V

    .line 46
    .line 47
    .line 48
    :cond_1
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    invoke-static {p1}, Landroidx/glance/appwidget/protobuf/j;->k(I)I

    .line 53
    .line 54
    .line 55
    move-result p1

    .line 56
    iget v1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I
    :try_end_1
    .catch Landroidx/glance/appwidget/protobuf/g1; {:try_start_1 .. :try_end_1} :catch_0

    .line 57
    .line 58
    iget-object v3, p0, Landroidx/glance/appwidget/protobuf/j;->b:[B

    .line 59
    .line 60
    if-ne p1, v0, :cond_2

    .line 61
    .line 62
    add-int v0, v1, p1

    .line 63
    .line 64
    :try_start_2
    iput v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 65
    .line 66
    sub-int/2addr v2, v0

    .line 67
    sget-object v4, Landroidx/glance/appwidget/protobuf/h1;->a:Landroidx/glance/appwidget/protobuf/f1;

    .line 68
    .line 69
    invoke-virtual {v4, v0, v2, p2, v3}, Landroidx/glance/appwidget/protobuf/f1;->d(IILjava/lang/String;[B)I

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    iput v1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 74
    .line 75
    sub-int v2, v0, v1

    .line 76
    .line 77
    sub-int/2addr v2, p1

    .line 78
    invoke-virtual {p0, v2}, Landroidx/glance/appwidget/protobuf/j;->f(I)V

    .line 79
    .line 80
    .line 81
    iput v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 82
    .line 83
    return-void

    .line 84
    :catch_1
    move-exception p1

    .line 85
    goto :goto_0

    .line 86
    :catch_2
    move-exception p1

    .line 87
    goto :goto_1

    .line 88
    :cond_2
    invoke-static {p2}, Landroidx/glance/appwidget/protobuf/h1;->a(Ljava/lang/String;)I

    .line 89
    .line 90
    .line 91
    move-result p1

    .line 92
    invoke-virtual {p0, p1}, Landroidx/glance/appwidget/protobuf/j;->f(I)V

    .line 93
    .line 94
    .line 95
    iget v0, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 96
    .line 97
    sget-object v2, Landroidx/glance/appwidget/protobuf/h1;->a:Landroidx/glance/appwidget/protobuf/f1;

    .line 98
    .line 99
    invoke-virtual {v2, v0, p1, p2, v3}, Landroidx/glance/appwidget/protobuf/f1;->d(IILjava/lang/String;[B)I

    .line 100
    .line 101
    .line 102
    move-result p1

    .line 103
    iput p1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I
    :try_end_2
    .catch Landroidx/glance/appwidget/protobuf/g1; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_2 .. :try_end_2} :catch_1

    .line 104
    .line 105
    return-void

    .line 106
    :goto_0
    :try_start_3
    new-instance v0, Lio/ktor/utils/io/k0;

    .line 107
    .line 108
    invoke-direct {v0, p1}, Lio/ktor/utils/io/k0;-><init>(Ljava/lang/IndexOutOfBoundsException;)V

    .line 109
    .line 110
    .line 111
    throw v0

    .line 112
    :goto_1
    iput v1, p0, Landroidx/glance/appwidget/protobuf/j;->d:I

    .line 113
    .line 114
    throw p1
    :try_end_3
    .catch Landroidx/glance/appwidget/protobuf/g1; {:try_start_3 .. :try_end_3} :catch_0

    .line 115
    :goto_2
    sget-object v0, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 116
    .line 117
    const-string v1, "Converting ill-formed UTF-16. Your Protocol Buffer will not round trip correctly!"

    .line 118
    .line 119
    sget-object v2, Landroidx/glance/appwidget/protobuf/j;->f:Ljava/util/logging/Logger;

    .line 120
    .line 121
    invoke-virtual {v2, v0, v1, p1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 122
    .line 123
    .line 124
    sget-object p1, Landroidx/glance/appwidget/protobuf/y;->a:Ljava/nio/charset/Charset;

    .line 125
    .line 126
    invoke-virtual {p2, p1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    :try_start_4
    array-length p2, p1

    .line 131
    invoke-virtual {p0, p2}, Landroidx/glance/appwidget/protobuf/j;->B(I)V

    .line 132
    .line 133
    .line 134
    array-length p2, p1

    .line 135
    const/4 v0, 0x0

    .line 136
    invoke-virtual {p0, p1, v0, p2}, Ljp/h1;->b([BII)V
    :try_end_4
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_4 .. :try_end_4} :catch_3

    .line 137
    .line 138
    .line 139
    return-void

    .line 140
    :catch_3
    move-exception p0

    .line 141
    new-instance p1, Lio/ktor/utils/io/k0;

    .line 142
    .line 143
    invoke-direct {p1, p0}, Lio/ktor/utils/io/k0;-><init>(Ljava/lang/IndexOutOfBoundsException;)V

    .line 144
    .line 145
    .line 146
    throw p1
.end method

.method public final z(II)V
    .locals 0

    .line 1
    shl-int/lit8 p1, p1, 0x3

    .line 2
    .line 3
    or-int/2addr p1, p2

    .line 4
    invoke-virtual {p0, p1}, Landroidx/glance/appwidget/protobuf/j;->B(I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method
