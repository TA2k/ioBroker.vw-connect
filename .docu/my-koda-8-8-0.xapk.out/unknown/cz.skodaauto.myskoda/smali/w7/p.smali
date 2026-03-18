.class public final Lw7/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:[C

.field public static final e:[C

.field public static final f:Lhr/k0;


# instance fields
.field public a:[B

.field public b:I

.field public c:I


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    const/4 v0, 0x2

    .line 2
    new-array v0, v0, [C

    .line 3
    .line 4
    fill-array-data v0, :array_0

    .line 5
    .line 6
    .line 7
    sput-object v0, Lw7/p;->d:[C

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    new-array v0, v0, [C

    .line 11
    .line 12
    const/16 v1, 0xa

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    aput-char v1, v0, v2

    .line 16
    .line 17
    sput-object v0, Lw7/p;->e:[C

    .line 18
    .line 19
    sget-object v0, Ljava/nio/charset/StandardCharsets;->US_ASCII:Ljava/nio/charset/Charset;

    .line 20
    .line 21
    sget-object v1, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 22
    .line 23
    sget-object v2, Ljava/nio/charset/StandardCharsets;->UTF_16:Ljava/nio/charset/Charset;

    .line 24
    .line 25
    sget-object v3, Ljava/nio/charset/StandardCharsets;->UTF_16BE:Ljava/nio/charset/Charset;

    .line 26
    .line 27
    sget-object v4, Ljava/nio/charset/StandardCharsets;->UTF_16LE:Ljava/nio/charset/Charset;

    .line 28
    .line 29
    const/4 v5, 0x5

    .line 30
    filled-new-array {v0, v1, v2, v3, v4}, [Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-static {v5, v0}, Lhr/k0;->o(I[Ljava/lang/Object;)Lhr/k0;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    sput-object v0, Lw7/p;->f:Lhr/k0;

    .line 39
    .line 40
    return-void

    .line 41
    :array_0
    .array-data 2
        0xds
        0xas
    .end array-data
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Lw7/w;->b:[B

    iput-object v0, p0, Lw7/p;->a:[B

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    new-array v0, p1, [B

    iput-object v0, p0, Lw7/p;->a:[B

    .line 5
    iput p1, p0, Lw7/p;->c:I

    return-void
.end method

.method public constructor <init>(I[B)V
    .locals 0

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    iput-object p2, p0, Lw7/p;->a:[B

    .line 11
    iput p1, p0, Lw7/p;->c:I

    return-void
.end method

.method public constructor <init>([B)V
    .locals 0

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    iput-object p1, p0, Lw7/p;->a:[B

    .line 8
    array-length p1, p1

    iput p1, p0, Lw7/p;->c:I

    return-void
.end method

.method public static b(IIII)I
    .locals 2

    .line 1
    and-int/lit8 p0, p0, 0x7

    .line 2
    .line 3
    shl-int/lit8 p0, p0, 0x2

    .line 4
    .line 5
    and-int/lit8 v0, p1, 0x30

    .line 6
    .line 7
    shr-int/lit8 v0, v0, 0x4

    .line 8
    .line 9
    or-int/2addr p0, v0

    .line 10
    int-to-long v0, p0

    .line 11
    invoke-static {v0, v1}, Llp/fe;->b(J)B

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    int-to-byte p1, p1

    .line 16
    and-int/lit8 p1, p1, 0xf

    .line 17
    .line 18
    shl-int/lit8 p1, p1, 0x4

    .line 19
    .line 20
    int-to-byte p2, p2

    .line 21
    and-int/lit8 v0, p2, 0x3c

    .line 22
    .line 23
    shr-int/lit8 v0, v0, 0x2

    .line 24
    .line 25
    or-int/2addr p1, v0

    .line 26
    int-to-long v0, p1

    .line 27
    invoke-static {v0, v1}, Llp/fe;->b(J)B

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    and-int/lit8 p2, p2, 0x3

    .line 32
    .line 33
    shl-int/lit8 p2, p2, 0x6

    .line 34
    .line 35
    int-to-byte p3, p3

    .line 36
    and-int/lit8 p3, p3, 0x3f

    .line 37
    .line 38
    or-int/2addr p2, p3

    .line 39
    int-to-long p2, p2

    .line 40
    invoke-static {p2, p3}, Llp/fe;->b(J)B

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    const/4 p3, 0x0

    .line 45
    invoke-static {p3, p0, p1, p2}, Llp/de;->d(BBBB)I

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    return p0
.end method

.method public static d(Ljava/nio/charset/Charset;)I
    .locals 3

    .line 1
    sget-object v0, Lw7/p;->f:Lhr/k0;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lhr/c0;->contains(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-instance v1, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v2, "Unsupported charset: "

    .line 10
    .line 11
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-static {v0, v1}, Lw7/a;->d(ZLjava/lang/String;)V

    .line 22
    .line 23
    .line 24
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 25
    .line 26
    invoke-virtual {p0, v0}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-nez v0, :cond_1

    .line 31
    .line 32
    sget-object v0, Ljava/nio/charset/StandardCharsets;->US_ASCII:Ljava/nio/charset/Charset;

    .line 33
    .line 34
    invoke-virtual {p0, v0}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    if-eqz p0, :cond_0

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 p0, 0x2

    .line 42
    return p0

    .line 43
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 44
    return p0
.end method

.method public static e(B)Z
    .locals 1

    .line 1
    and-int/lit16 p0, p0, 0xc0

    .line 2
    .line 3
    const/16 v0, 0x80

    .line 4
    .line 5
    if-ne p0, v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method


# virtual methods
.method public final A()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lw7/p;->j()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-ltz p0, :cond_0

    .line 6
    .line 7
    return p0

    .line 8
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 9
    .line 10
    const-string v1, "Top bit not zero: "

    .line 11
    .line 12
    invoke-static {p0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw v0
.end method

.method public final B()J
    .locals 4

    .line 1
    invoke-virtual {p0}, Lw7/p;->q()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-wide/16 v2, 0x0

    .line 6
    .line 7
    cmp-long p0, v0, v2

    .line 8
    .line 9
    if-ltz p0, :cond_0

    .line 10
    .line 11
    return-wide v0

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 13
    .line 14
    const-string v2, "Top bit not zero: "

    .line 15
    .line 16
    invoke-static {v0, v1, v2}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0
.end method

.method public final C()I
    .locals 4

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lw7/p;->b:I

    .line 8
    .line 9
    aget-byte v3, v0, v1

    .line 10
    .line 11
    and-int/lit16 v3, v3, 0xff

    .line 12
    .line 13
    shl-int/lit8 v3, v3, 0x8

    .line 14
    .line 15
    add-int/lit8 v1, v1, 0x2

    .line 16
    .line 17
    iput v1, p0, Lw7/p;->b:I

    .line 18
    .line 19
    aget-byte p0, v0, v2

    .line 20
    .line 21
    and-int/lit16 p0, p0, 0xff

    .line 22
    .line 23
    or-int/2addr p0, v3

    .line 24
    return p0
.end method

.method public final D()J
    .locals 11

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    aget-byte v0, v0, v1

    .line 6
    .line 7
    int-to-long v0, v0

    .line 8
    const/4 v2, 0x7

    .line 9
    move v3, v2

    .line 10
    :goto_0
    const/4 v4, 0x6

    .line 11
    const/4 v5, 0x1

    .line 12
    if-ltz v3, :cond_2

    .line 13
    .line 14
    shl-int v6, v5, v3

    .line 15
    .line 16
    int-to-long v7, v6

    .line 17
    and-long/2addr v7, v0

    .line 18
    const-wide/16 v9, 0x0

    .line 19
    .line 20
    cmp-long v7, v7, v9

    .line 21
    .line 22
    if-nez v7, :cond_1

    .line 23
    .line 24
    if-ge v3, v4, :cond_0

    .line 25
    .line 26
    sub-int/2addr v6, v5

    .line 27
    int-to-long v6, v6

    .line 28
    and-long/2addr v0, v6

    .line 29
    sub-int/2addr v2, v3

    .line 30
    goto :goto_1

    .line 31
    :cond_0
    if-ne v3, v2, :cond_2

    .line 32
    .line 33
    move v2, v5

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    add-int/lit8 v3, v3, -0x1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_2
    const/4 v2, 0x0

    .line 39
    :goto_1
    if-eqz v2, :cond_5

    .line 40
    .line 41
    :goto_2
    if-ge v5, v2, :cond_4

    .line 42
    .line 43
    iget-object v3, p0, Lw7/p;->a:[B

    .line 44
    .line 45
    iget v6, p0, Lw7/p;->b:I

    .line 46
    .line 47
    add-int/2addr v6, v5

    .line 48
    aget-byte v3, v3, v6

    .line 49
    .line 50
    and-int/lit16 v6, v3, 0xc0

    .line 51
    .line 52
    const/16 v7, 0x80

    .line 53
    .line 54
    if-ne v6, v7, :cond_3

    .line 55
    .line 56
    shl-long/2addr v0, v4

    .line 57
    and-int/lit8 v3, v3, 0x3f

    .line 58
    .line 59
    int-to-long v6, v3

    .line 60
    or-long/2addr v0, v6

    .line 61
    add-int/lit8 v5, v5, 0x1

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_3
    new-instance p0, Ljava/lang/NumberFormatException;

    .line 65
    .line 66
    const-string v2, "Invalid UTF-8 sequence continuation byte: "

    .line 67
    .line 68
    invoke-static {v0, v1, v2}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    invoke-direct {p0, v0}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw p0

    .line 76
    :cond_4
    iget v3, p0, Lw7/p;->b:I

    .line 77
    .line 78
    add-int/2addr v3, v2

    .line 79
    iput v3, p0, Lw7/p;->b:I

    .line 80
    .line 81
    return-wide v0

    .line 82
    :cond_5
    new-instance p0, Ljava/lang/NumberFormatException;

    .line 83
    .line 84
    const-string v2, "Invalid UTF-8 sequence first byte: "

    .line 85
    .line 86
    invoke-static {v0, v1, v2}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    invoke-direct {p0, v0}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw p0
.end method

.method public final E()Ljava/nio/charset/Charset;
    .locals 7

    .line 1
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x3

    .line 6
    if-lt v0, v1, :cond_0

    .line 7
    .line 8
    iget-object v0, p0, Lw7/p;->a:[B

    .line 9
    .line 10
    iget v2, p0, Lw7/p;->b:I

    .line 11
    .line 12
    aget-byte v3, v0, v2

    .line 13
    .line 14
    const/16 v4, -0x11

    .line 15
    .line 16
    if-ne v3, v4, :cond_0

    .line 17
    .line 18
    add-int/lit8 v3, v2, 0x1

    .line 19
    .line 20
    aget-byte v3, v0, v3

    .line 21
    .line 22
    const/16 v4, -0x45

    .line 23
    .line 24
    if-ne v3, v4, :cond_0

    .line 25
    .line 26
    add-int/lit8 v3, v2, 0x2

    .line 27
    .line 28
    aget-byte v0, v0, v3

    .line 29
    .line 30
    const/16 v3, -0x41

    .line 31
    .line 32
    if-ne v0, v3, :cond_0

    .line 33
    .line 34
    add-int/2addr v2, v1

    .line 35
    iput v2, p0, Lw7/p;->b:I

    .line 36
    .line 37
    sget-object p0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_0
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    const/4 v1, 0x2

    .line 45
    if-lt v0, v1, :cond_2

    .line 46
    .line 47
    iget-object v0, p0, Lw7/p;->a:[B

    .line 48
    .line 49
    iget v2, p0, Lw7/p;->b:I

    .line 50
    .line 51
    aget-byte v3, v0, v2

    .line 52
    .line 53
    const/4 v4, -0x1

    .line 54
    const/4 v5, -0x2

    .line 55
    if-ne v3, v5, :cond_1

    .line 56
    .line 57
    add-int/lit8 v6, v2, 0x1

    .line 58
    .line 59
    aget-byte v6, v0, v6

    .line 60
    .line 61
    if-ne v6, v4, :cond_1

    .line 62
    .line 63
    add-int/2addr v2, v1

    .line 64
    iput v2, p0, Lw7/p;->b:I

    .line 65
    .line 66
    sget-object p0, Ljava/nio/charset/StandardCharsets;->UTF_16BE:Ljava/nio/charset/Charset;

    .line 67
    .line 68
    return-object p0

    .line 69
    :cond_1
    if-ne v3, v4, :cond_2

    .line 70
    .line 71
    add-int/lit8 v3, v2, 0x1

    .line 72
    .line 73
    aget-byte v0, v0, v3

    .line 74
    .line 75
    if-ne v0, v5, :cond_2

    .line 76
    .line 77
    add-int/2addr v2, v1

    .line 78
    iput v2, p0, Lw7/p;->b:I

    .line 79
    .line 80
    sget-object p0, Ljava/nio/charset/StandardCharsets;->UTF_16LE:Ljava/nio/charset/Charset;

    .line 81
    .line 82
    return-object p0

    .line 83
    :cond_2
    const/4 p0, 0x0

    .line 84
    return-object p0
.end method

.method public final F(I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    if-ge v1, p1, :cond_0

    .line 5
    .line 6
    new-array v0, p1, [B

    .line 7
    .line 8
    :cond_0
    invoke-virtual {p0, p1, v0}, Lw7/p;->G(I[B)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final G(I[B)V
    .locals 0

    .line 1
    iput-object p2, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iput p1, p0, Lw7/p;->c:I

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    iput p1, p0, Lw7/p;->b:I

    .line 7
    .line 8
    return-void
.end method

.method public final H(I)V
    .locals 1

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    iget-object v0, p0, Lw7/p;->a:[B

    .line 4
    .line 5
    array-length v0, v0

    .line 6
    if-gt p1, v0, :cond_0

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 v0, 0x0

    .line 11
    :goto_0
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 12
    .line 13
    .line 14
    iput p1, p0, Lw7/p;->c:I

    .line 15
    .line 16
    return-void
.end method

.method public final I(I)V
    .locals 1

    .line 1
    if-ltz p1, :cond_0

    .line 2
    .line 3
    iget v0, p0, Lw7/p;->c:I

    .line 4
    .line 5
    if-gt p1, v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const/4 v0, 0x0

    .line 10
    :goto_0
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 11
    .line 12
    .line 13
    iput p1, p0, Lw7/p;->b:I

    .line 14
    .line 15
    return-void
.end method

.method public final J(I)V
    .locals 1

    .line 1
    iget v0, p0, Lw7/p;->b:I

    .line 2
    .line 3
    add-int/2addr v0, p1

    .line 4
    invoke-virtual {p0, v0}, Lw7/p;->I(I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final a()I
    .locals 1

    .line 1
    iget v0, p0, Lw7/p;->c:I

    .line 2
    .line 3
    iget p0, p0, Lw7/p;->b:I

    .line 4
    .line 5
    sub-int/2addr v0, p0

    .line 6
    const/4 p0, 0x0

    .line 7
    invoke-static {v0, p0}, Ljava/lang/Math;->max(II)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public final c(I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    if-le p1, v1, :cond_0

    .line 5
    .line 6
    invoke-static {v0, p1}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lw7/p;->a:[B

    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final f(ILjava/nio/ByteOrder;)C
    .locals 1

    .line 1
    sget-object v0, Ljava/nio/ByteOrder;->BIG_ENDIAN:Ljava/nio/ByteOrder;

    .line 2
    .line 3
    if-ne p2, v0, :cond_0

    .line 4
    .line 5
    iget-object p2, p0, Lw7/p;->a:[B

    .line 6
    .line 7
    iget p0, p0, Lw7/p;->b:I

    .line 8
    .line 9
    add-int/2addr p0, p1

    .line 10
    aget-byte p1, p2, p0

    .line 11
    .line 12
    add-int/lit8 p0, p0, 0x1

    .line 13
    .line 14
    aget-byte p0, p2, p0

    .line 15
    .line 16
    :goto_0
    shl-int/lit8 p1, p1, 0x8

    .line 17
    .line 18
    and-int/lit16 p0, p0, 0xff

    .line 19
    .line 20
    or-int/2addr p0, p1

    .line 21
    int-to-char p0, p0

    .line 22
    return p0

    .line 23
    :cond_0
    iget-object p2, p0, Lw7/p;->a:[B

    .line 24
    .line 25
    iget p0, p0, Lw7/p;->b:I

    .line 26
    .line 27
    add-int/2addr p0, p1

    .line 28
    add-int/lit8 p1, p0, 0x1

    .line 29
    .line 30
    aget-byte p1, p2, p1

    .line 31
    .line 32
    aget-byte p0, p2, p0

    .line 33
    .line 34
    goto :goto_0
.end method

.method public final g(Ljava/nio/charset/Charset;)I
    .locals 7

    .line 1
    sget-object v0, Lw7/p;->f:Lhr/k0;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lhr/c0;->contains(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-instance v1, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v2, "Unsupported charset: "

    .line 10
    .line 11
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-static {v0, v1}, Lw7/a;->d(ZLjava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    invoke-static {p1}, Lw7/p;->d(Ljava/nio/charset/Charset;)I

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-lt v0, v1, :cond_d

    .line 33
    .line 34
    sget-object v0, Ljava/nio/charset/StandardCharsets;->US_ASCII:Ljava/nio/charset/Charset;

    .line 35
    .line 36
    invoke-virtual {p1, v0}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    const/4 v1, 0x1

    .line 41
    const/4 v2, 0x0

    .line 42
    if-eqz v0, :cond_1

    .line 43
    .line 44
    iget-object p1, p0, Lw7/p;->a:[B

    .line 45
    .line 46
    iget p0, p0, Lw7/p;->b:I

    .line 47
    .line 48
    aget-byte p0, p1, p0

    .line 49
    .line 50
    and-int/lit16 p1, p0, 0x80

    .line 51
    .line 52
    if-eqz p1, :cond_0

    .line 53
    .line 54
    goto/16 :goto_1

    .line 55
    .line 56
    :cond_0
    and-int/lit16 p0, p0, 0xff

    .line 57
    .line 58
    goto/16 :goto_4

    .line 59
    .line 60
    :cond_1
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 61
    .line 62
    invoke-virtual {p1, v0}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    const/4 v3, 0x4

    .line 67
    const/4 v4, 0x2

    .line 68
    if-eqz v0, :cond_a

    .line 69
    .line 70
    iget-object p1, p0, Lw7/p;->a:[B

    .line 71
    .line 72
    iget v0, p0, Lw7/p;->b:I

    .line 73
    .line 74
    aget-byte p1, p1, v0

    .line 75
    .line 76
    and-int/lit16 v0, p1, 0x80

    .line 77
    .line 78
    const/4 v5, 0x3

    .line 79
    if-nez v0, :cond_2

    .line 80
    .line 81
    move p1, v1

    .line 82
    goto/16 :goto_0

    .line 83
    .line 84
    :cond_2
    const/16 v0, 0xe0

    .line 85
    .line 86
    and-int/2addr p1, v0

    .line 87
    const/16 v6, 0xc0

    .line 88
    .line 89
    if-ne p1, v6, :cond_3

    .line 90
    .line 91
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    if-lt p1, v4, :cond_3

    .line 96
    .line 97
    iget-object p1, p0, Lw7/p;->a:[B

    .line 98
    .line 99
    iget v6, p0, Lw7/p;->b:I

    .line 100
    .line 101
    add-int/2addr v6, v1

    .line 102
    aget-byte p1, p1, v6

    .line 103
    .line 104
    invoke-static {p1}, Lw7/p;->e(B)Z

    .line 105
    .line 106
    .line 107
    move-result p1

    .line 108
    if-eqz p1, :cond_3

    .line 109
    .line 110
    move p1, v4

    .line 111
    goto :goto_0

    .line 112
    :cond_3
    iget-object p1, p0, Lw7/p;->a:[B

    .line 113
    .line 114
    iget v6, p0, Lw7/p;->b:I

    .line 115
    .line 116
    aget-byte p1, p1, v6

    .line 117
    .line 118
    const/16 v6, 0xf0

    .line 119
    .line 120
    and-int/2addr p1, v6

    .line 121
    if-ne p1, v0, :cond_4

    .line 122
    .line 123
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 124
    .line 125
    .line 126
    move-result p1

    .line 127
    if-lt p1, v5, :cond_4

    .line 128
    .line 129
    iget-object p1, p0, Lw7/p;->a:[B

    .line 130
    .line 131
    iget v0, p0, Lw7/p;->b:I

    .line 132
    .line 133
    add-int/2addr v0, v1

    .line 134
    aget-byte p1, p1, v0

    .line 135
    .line 136
    invoke-static {p1}, Lw7/p;->e(B)Z

    .line 137
    .line 138
    .line 139
    move-result p1

    .line 140
    if-eqz p1, :cond_4

    .line 141
    .line 142
    iget-object p1, p0, Lw7/p;->a:[B

    .line 143
    .line 144
    iget v0, p0, Lw7/p;->b:I

    .line 145
    .line 146
    add-int/2addr v0, v4

    .line 147
    aget-byte p1, p1, v0

    .line 148
    .line 149
    invoke-static {p1}, Lw7/p;->e(B)Z

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    if-eqz p1, :cond_4

    .line 154
    .line 155
    move p1, v5

    .line 156
    goto :goto_0

    .line 157
    :cond_4
    iget-object p1, p0, Lw7/p;->a:[B

    .line 158
    .line 159
    iget v0, p0, Lw7/p;->b:I

    .line 160
    .line 161
    aget-byte p1, p1, v0

    .line 162
    .line 163
    and-int/lit16 p1, p1, 0xf8

    .line 164
    .line 165
    if-ne p1, v6, :cond_5

    .line 166
    .line 167
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 168
    .line 169
    .line 170
    move-result p1

    .line 171
    if-lt p1, v3, :cond_5

    .line 172
    .line 173
    iget-object p1, p0, Lw7/p;->a:[B

    .line 174
    .line 175
    iget v0, p0, Lw7/p;->b:I

    .line 176
    .line 177
    add-int/2addr v0, v1

    .line 178
    aget-byte p1, p1, v0

    .line 179
    .line 180
    invoke-static {p1}, Lw7/p;->e(B)Z

    .line 181
    .line 182
    .line 183
    move-result p1

    .line 184
    if-eqz p1, :cond_5

    .line 185
    .line 186
    iget-object p1, p0, Lw7/p;->a:[B

    .line 187
    .line 188
    iget v0, p0, Lw7/p;->b:I

    .line 189
    .line 190
    add-int/2addr v0, v4

    .line 191
    aget-byte p1, p1, v0

    .line 192
    .line 193
    invoke-static {p1}, Lw7/p;->e(B)Z

    .line 194
    .line 195
    .line 196
    move-result p1

    .line 197
    if-eqz p1, :cond_5

    .line 198
    .line 199
    iget-object p1, p0, Lw7/p;->a:[B

    .line 200
    .line 201
    iget v0, p0, Lw7/p;->b:I

    .line 202
    .line 203
    add-int/2addr v0, v5

    .line 204
    aget-byte p1, p1, v0

    .line 205
    .line 206
    invoke-static {p1}, Lw7/p;->e(B)Z

    .line 207
    .line 208
    .line 209
    move-result p1

    .line 210
    if-eqz p1, :cond_5

    .line 211
    .line 212
    move p1, v3

    .line 213
    goto :goto_0

    .line 214
    :cond_5
    move p1, v2

    .line 215
    :goto_0
    if-eq p1, v1, :cond_9

    .line 216
    .line 217
    if-eq p1, v4, :cond_8

    .line 218
    .line 219
    if-eq p1, v5, :cond_7

    .line 220
    .line 221
    if-eq p1, v3, :cond_6

    .line 222
    .line 223
    :goto_1
    return v2

    .line 224
    :cond_6
    iget-object v0, p0, Lw7/p;->a:[B

    .line 225
    .line 226
    iget p0, p0, Lw7/p;->b:I

    .line 227
    .line 228
    aget-byte v1, v0, p0

    .line 229
    .line 230
    add-int/lit8 v2, p0, 0x1

    .line 231
    .line 232
    aget-byte v2, v0, v2

    .line 233
    .line 234
    add-int/lit8 v3, p0, 0x2

    .line 235
    .line 236
    aget-byte v3, v0, v3

    .line 237
    .line 238
    add-int/2addr p0, v5

    .line 239
    aget-byte p0, v0, p0

    .line 240
    .line 241
    invoke-static {v1, v2, v3, p0}, Lw7/p;->b(IIII)I

    .line 242
    .line 243
    .line 244
    move-result p0

    .line 245
    :goto_2
    move v1, p1

    .line 246
    goto :goto_4

    .line 247
    :cond_7
    iget-object v0, p0, Lw7/p;->a:[B

    .line 248
    .line 249
    iget p0, p0, Lw7/p;->b:I

    .line 250
    .line 251
    aget-byte v1, v0, p0

    .line 252
    .line 253
    and-int/lit8 v1, v1, 0xf

    .line 254
    .line 255
    add-int/lit8 v3, p0, 0x1

    .line 256
    .line 257
    aget-byte v3, v0, v3

    .line 258
    .line 259
    add-int/2addr p0, v4

    .line 260
    aget-byte p0, v0, p0

    .line 261
    .line 262
    invoke-static {v2, v1, v3, p0}, Lw7/p;->b(IIII)I

    .line 263
    .line 264
    .line 265
    move-result p0

    .line 266
    goto :goto_2

    .line 267
    :cond_8
    iget-object v0, p0, Lw7/p;->a:[B

    .line 268
    .line 269
    iget p0, p0, Lw7/p;->b:I

    .line 270
    .line 271
    aget-byte v3, v0, p0

    .line 272
    .line 273
    add-int/2addr p0, v1

    .line 274
    aget-byte p0, v0, p0

    .line 275
    .line 276
    invoke-static {v2, v2, v3, p0}, Lw7/p;->b(IIII)I

    .line 277
    .line 278
    .line 279
    move-result p0

    .line 280
    goto :goto_2

    .line 281
    :cond_9
    iget-object v0, p0, Lw7/p;->a:[B

    .line 282
    .line 283
    iget p0, p0, Lw7/p;->b:I

    .line 284
    .line 285
    aget-byte p0, v0, p0

    .line 286
    .line 287
    and-int/lit16 p0, p0, 0xff

    .line 288
    .line 289
    goto :goto_2

    .line 290
    :cond_a
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_16LE:Ljava/nio/charset/Charset;

    .line 291
    .line 292
    invoke-virtual {p1, v0}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 293
    .line 294
    .line 295
    move-result p1

    .line 296
    if-eqz p1, :cond_b

    .line 297
    .line 298
    sget-object p1, Ljava/nio/ByteOrder;->LITTLE_ENDIAN:Ljava/nio/ByteOrder;

    .line 299
    .line 300
    goto :goto_3

    .line 301
    :cond_b
    sget-object p1, Ljava/nio/ByteOrder;->BIG_ENDIAN:Ljava/nio/ByteOrder;

    .line 302
    .line 303
    :goto_3
    invoke-virtual {p0, v2, p1}, Lw7/p;->f(ILjava/nio/ByteOrder;)C

    .line 304
    .line 305
    .line 306
    move-result v0

    .line 307
    invoke-static {v0}, Ljava/lang/Character;->isHighSurrogate(C)Z

    .line 308
    .line 309
    .line 310
    move-result v1

    .line 311
    if-eqz v1, :cond_c

    .line 312
    .line 313
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 314
    .line 315
    .line 316
    move-result v1

    .line 317
    if-lt v1, v3, :cond_c

    .line 318
    .line 319
    invoke-virtual {p0, v4, p1}, Lw7/p;->f(ILjava/nio/ByteOrder;)C

    .line 320
    .line 321
    .line 322
    move-result p0

    .line 323
    invoke-static {v0, p0}, Ljava/lang/Character;->toCodePoint(CC)I

    .line 324
    .line 325
    .line 326
    move-result p0

    .line 327
    move v1, v3

    .line 328
    goto :goto_4

    .line 329
    :cond_c
    move p0, v0

    .line 330
    move v1, v4

    .line 331
    :goto_4
    shl-int/lit8 p0, p0, 0x8

    .line 332
    .line 333
    or-int/2addr p0, v1

    .line 334
    return p0

    .line 335
    :cond_d
    new-instance p1, Ljava/lang/IndexOutOfBoundsException;

    .line 336
    .line 337
    new-instance v0, Ljava/lang/StringBuilder;

    .line 338
    .line 339
    const-string v1, "position="

    .line 340
    .line 341
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 342
    .line 343
    .line 344
    iget v1, p0, Lw7/p;->b:I

    .line 345
    .line 346
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 347
    .line 348
    .line 349
    const-string v1, ", limit="

    .line 350
    .line 351
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 352
    .line 353
    .line 354
    iget p0, p0, Lw7/p;->c:I

    .line 355
    .line 356
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 357
    .line 358
    .line 359
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 360
    .line 361
    .line 362
    move-result-object p0

    .line 363
    invoke-direct {p1, p0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 364
    .line 365
    .line 366
    throw p1
.end method

.method public final h([BII)V
    .locals 2

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    invoke-static {v0, v1, p1, p2, p3}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 6
    .line 7
    .line 8
    iget p1, p0, Lw7/p;->b:I

    .line 9
    .line 10
    add-int/2addr p1, p3

    .line 11
    iput p1, p0, Lw7/p;->b:I

    .line 12
    .line 13
    return-void
.end method

.method public final i(Ljava/nio/charset/Charset;[C)C
    .locals 7

    .line 1
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p1}, Lw7/p;->d(Ljava/nio/charset/Charset;)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x0

    .line 10
    if-ge v0, v1, :cond_0

    .line 11
    .line 12
    goto :goto_3

    .line 13
    :cond_0
    invoke-virtual {p0, p1}, Lw7/p;->g(Ljava/nio/charset/Charset;)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    if-nez p1, :cond_1

    .line 18
    .line 19
    goto :goto_3

    .line 20
    :cond_1
    ushr-int/lit8 v0, p1, 0x8

    .line 21
    .line 22
    int-to-long v0, v0

    .line 23
    const/16 v3, 0x20

    .line 24
    .line 25
    shr-long v3, v0, v3

    .line 26
    .line 27
    const-wide/16 v5, 0x0

    .line 28
    .line 29
    cmp-long v3, v3, v5

    .line 30
    .line 31
    const/4 v4, 0x1

    .line 32
    if-nez v3, :cond_2

    .line 33
    .line 34
    move v3, v4

    .line 35
    goto :goto_0

    .line 36
    :cond_2
    move v3, v2

    .line 37
    :goto_0
    const-string v5, "out of range: %s"

    .line 38
    .line 39
    invoke-static {v0, v1, v5, v3}, Lkp/i9;->b(JLjava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    long-to-int v0, v0

    .line 43
    invoke-static {v0}, Ljava/lang/Character;->isSupplementaryCodePoint(I)Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_3

    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_3
    int-to-long v0, v0

    .line 51
    long-to-int v3, v0

    .line 52
    int-to-char v3, v3

    .line 53
    int-to-long v5, v3

    .line 54
    cmp-long v5, v5, v0

    .line 55
    .line 56
    if-nez v5, :cond_4

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_4
    move v4, v2

    .line 60
    :goto_1
    const-string v5, "Out of range: %s"

    .line 61
    .line 62
    invoke-static {v0, v1, v5, v4}, Lkp/i9;->b(JLjava/lang/String;Z)V

    .line 63
    .line 64
    .line 65
    array-length v0, p2

    .line 66
    move v1, v2

    .line 67
    :goto_2
    if-ge v1, v0, :cond_6

    .line 68
    .line 69
    aget-char v4, p2, v1

    .line 70
    .line 71
    if-ne v4, v3, :cond_5

    .line 72
    .line 73
    iget p2, p0, Lw7/p;->b:I

    .line 74
    .line 75
    and-int/lit16 p1, p1, 0xff

    .line 76
    .line 77
    int-to-long v0, p1

    .line 78
    invoke-static {v0, v1}, Llp/de;->c(J)I

    .line 79
    .line 80
    .line 81
    move-result p1

    .line 82
    add-int/2addr p1, p2

    .line 83
    iput p1, p0, Lw7/p;->b:I

    .line 84
    .line 85
    return v3

    .line 86
    :cond_5
    add-int/lit8 v1, v1, 0x1

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_6
    :goto_3
    return v2
.end method

.method public final j()I
    .locals 5

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lw7/p;->b:I

    .line 8
    .line 9
    aget-byte v3, v0, v1

    .line 10
    .line 11
    and-int/lit16 v3, v3, 0xff

    .line 12
    .line 13
    shl-int/lit8 v3, v3, 0x18

    .line 14
    .line 15
    add-int/lit8 v4, v1, 0x2

    .line 16
    .line 17
    iput v4, p0, Lw7/p;->b:I

    .line 18
    .line 19
    aget-byte v2, v0, v2

    .line 20
    .line 21
    and-int/lit16 v2, v2, 0xff

    .line 22
    .line 23
    shl-int/lit8 v2, v2, 0x10

    .line 24
    .line 25
    or-int/2addr v2, v3

    .line 26
    add-int/lit8 v3, v1, 0x3

    .line 27
    .line 28
    iput v3, p0, Lw7/p;->b:I

    .line 29
    .line 30
    aget-byte v4, v0, v4

    .line 31
    .line 32
    and-int/lit16 v4, v4, 0xff

    .line 33
    .line 34
    shl-int/lit8 v4, v4, 0x8

    .line 35
    .line 36
    or-int/2addr v2, v4

    .line 37
    add-int/lit8 v1, v1, 0x4

    .line 38
    .line 39
    iput v1, p0, Lw7/p;->b:I

    .line 40
    .line 41
    aget-byte p0, v0, v3

    .line 42
    .line 43
    and-int/lit16 p0, p0, 0xff

    .line 44
    .line 45
    or-int/2addr p0, v2

    .line 46
    return p0
.end method

.method public final k(Ljava/nio/charset/Charset;)Ljava/lang/String;
    .locals 6

    .line 1
    sget-object v0, Lw7/p;->f:Lhr/k0;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lhr/c0;->contains(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-instance v1, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const-string v2, "Unsupported charset: "

    .line 10
    .line 11
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-static {v0, v1}, Lw7/a;->d(ZLjava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-nez v0, :cond_0

    .line 29
    .line 30
    const/4 p0, 0x0

    .line 31
    return-object p0

    .line 32
    :cond_0
    sget-object v0, Ljava/nio/charset/StandardCharsets;->US_ASCII:Ljava/nio/charset/Charset;

    .line 33
    .line 34
    invoke-virtual {p1, v0}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-nez v1, :cond_1

    .line 39
    .line 40
    invoke-virtual {p0}, Lw7/p;->E()Ljava/nio/charset/Charset;

    .line 41
    .line 42
    .line 43
    :cond_1
    sget-object v1, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 44
    .line 45
    invoke-virtual {p1, v1}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-nez v1, :cond_5

    .line 50
    .line 51
    invoke-virtual {p1, v0}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-eqz v0, :cond_2

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_2
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_16:Ljava/nio/charset/Charset;

    .line 59
    .line 60
    invoke-virtual {p1, v0}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    if-nez v0, :cond_4

    .line 65
    .line 66
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_16LE:Ljava/nio/charset/Charset;

    .line 67
    .line 68
    invoke-virtual {p1, v0}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    if-nez v0, :cond_4

    .line 73
    .line 74
    sget-object v0, Ljava/nio/charset/StandardCharsets;->UTF_16BE:Ljava/nio/charset/Charset;

    .line 75
    .line 76
    invoke-virtual {p1, v0}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    if-eqz v0, :cond_3

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 84
    .line 85
    new-instance v0, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    throw p0

    .line 101
    :cond_4
    :goto_0
    const/4 v0, 0x2

    .line 102
    goto :goto_2

    .line 103
    :cond_5
    :goto_1
    const/4 v0, 0x1

    .line 104
    :goto_2
    iget v1, p0, Lw7/p;->b:I

    .line 105
    .line 106
    :goto_3
    iget v2, p0, Lw7/p;->c:I

    .line 107
    .line 108
    add-int/lit8 v3, v0, -0x1

    .line 109
    .line 110
    sub-int v3, v2, v3

    .line 111
    .line 112
    const/16 v4, 0xd

    .line 113
    .line 114
    if-ge v1, v3, :cond_b

    .line 115
    .line 116
    sget-object v2, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 117
    .line 118
    invoke-virtual {p1, v2}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v2

    .line 122
    const/16 v3, 0xa

    .line 123
    .line 124
    if-nez v2, :cond_6

    .line 125
    .line 126
    sget-object v2, Ljava/nio/charset/StandardCharsets;->US_ASCII:Ljava/nio/charset/Charset;

    .line 127
    .line 128
    invoke-virtual {p1, v2}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v2

    .line 132
    if-eqz v2, :cond_7

    .line 133
    .line 134
    :cond_6
    iget-object v2, p0, Lw7/p;->a:[B

    .line 135
    .line 136
    aget-byte v2, v2, v1

    .line 137
    .line 138
    sget-object v5, Lw7/w;->a:Ljava/lang/String;

    .line 139
    .line 140
    if-eq v2, v3, :cond_c

    .line 141
    .line 142
    if-ne v2, v4, :cond_7

    .line 143
    .line 144
    goto :goto_4

    .line 145
    :cond_7
    sget-object v2, Ljava/nio/charset/StandardCharsets;->UTF_16:Ljava/nio/charset/Charset;

    .line 146
    .line 147
    invoke-virtual {p1, v2}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v2

    .line 151
    if-nez v2, :cond_8

    .line 152
    .line 153
    sget-object v2, Ljava/nio/charset/StandardCharsets;->UTF_16BE:Ljava/nio/charset/Charset;

    .line 154
    .line 155
    invoke-virtual {p1, v2}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v2

    .line 159
    if-eqz v2, :cond_9

    .line 160
    .line 161
    :cond_8
    iget-object v2, p0, Lw7/p;->a:[B

    .line 162
    .line 163
    aget-byte v5, v2, v1

    .line 164
    .line 165
    if-nez v5, :cond_9

    .line 166
    .line 167
    add-int/lit8 v5, v1, 0x1

    .line 168
    .line 169
    aget-byte v2, v2, v5

    .line 170
    .line 171
    sget-object v5, Lw7/w;->a:Ljava/lang/String;

    .line 172
    .line 173
    if-eq v2, v3, :cond_c

    .line 174
    .line 175
    if-ne v2, v4, :cond_9

    .line 176
    .line 177
    goto :goto_4

    .line 178
    :cond_9
    sget-object v2, Ljava/nio/charset/StandardCharsets;->UTF_16LE:Ljava/nio/charset/Charset;

    .line 179
    .line 180
    invoke-virtual {p1, v2}, Ljava/nio/charset/Charset;->equals(Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v2

    .line 184
    if-eqz v2, :cond_a

    .line 185
    .line 186
    iget-object v2, p0, Lw7/p;->a:[B

    .line 187
    .line 188
    add-int/lit8 v5, v1, 0x1

    .line 189
    .line 190
    aget-byte v5, v2, v5

    .line 191
    .line 192
    if-nez v5, :cond_a

    .line 193
    .line 194
    aget-byte v2, v2, v1

    .line 195
    .line 196
    sget-object v5, Lw7/w;->a:Ljava/lang/String;

    .line 197
    .line 198
    if-eq v2, v3, :cond_c

    .line 199
    .line 200
    if-ne v2, v4, :cond_a

    .line 201
    .line 202
    goto :goto_4

    .line 203
    :cond_a
    add-int/2addr v1, v0

    .line 204
    goto :goto_3

    .line 205
    :cond_b
    move v1, v2

    .line 206
    :cond_c
    :goto_4
    iget v0, p0, Lw7/p;->b:I

    .line 207
    .line 208
    sub-int/2addr v1, v0

    .line 209
    invoke-virtual {p0, v1, p1}, Lw7/p;->u(ILjava/nio/charset/Charset;)Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v0

    .line 213
    iget v1, p0, Lw7/p;->b:I

    .line 214
    .line 215
    iget v2, p0, Lw7/p;->c:I

    .line 216
    .line 217
    if-ne v1, v2, :cond_d

    .line 218
    .line 219
    goto :goto_5

    .line 220
    :cond_d
    sget-object v1, Lw7/p;->d:[C

    .line 221
    .line 222
    invoke-virtual {p0, p1, v1}, Lw7/p;->i(Ljava/nio/charset/Charset;[C)C

    .line 223
    .line 224
    .line 225
    move-result v1

    .line 226
    if-ne v1, v4, :cond_e

    .line 227
    .line 228
    sget-object v1, Lw7/p;->e:[C

    .line 229
    .line 230
    invoke-virtual {p0, p1, v1}, Lw7/p;->i(Ljava/nio/charset/Charset;[C)C

    .line 231
    .line 232
    .line 233
    :cond_e
    :goto_5
    return-object v0
.end method

.method public final l()I
    .locals 5

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lw7/p;->b:I

    .line 8
    .line 9
    aget-byte v3, v0, v1

    .line 10
    .line 11
    and-int/lit16 v3, v3, 0xff

    .line 12
    .line 13
    add-int/lit8 v4, v1, 0x2

    .line 14
    .line 15
    iput v4, p0, Lw7/p;->b:I

    .line 16
    .line 17
    aget-byte v2, v0, v2

    .line 18
    .line 19
    and-int/lit16 v2, v2, 0xff

    .line 20
    .line 21
    shl-int/lit8 v2, v2, 0x8

    .line 22
    .line 23
    or-int/2addr v2, v3

    .line 24
    add-int/lit8 v3, v1, 0x3

    .line 25
    .line 26
    iput v3, p0, Lw7/p;->b:I

    .line 27
    .line 28
    aget-byte v4, v0, v4

    .line 29
    .line 30
    and-int/lit16 v4, v4, 0xff

    .line 31
    .line 32
    shl-int/lit8 v4, v4, 0x10

    .line 33
    .line 34
    or-int/2addr v2, v4

    .line 35
    add-int/lit8 v1, v1, 0x4

    .line 36
    .line 37
    iput v1, p0, Lw7/p;->b:I

    .line 38
    .line 39
    aget-byte p0, v0, v3

    .line 40
    .line 41
    and-int/lit16 p0, p0, 0xff

    .line 42
    .line 43
    shl-int/lit8 p0, p0, 0x18

    .line 44
    .line 45
    or-int/2addr p0, v2

    .line 46
    return p0
.end method

.method public final m()J
    .locals 11

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lw7/p;->b:I

    .line 8
    .line 9
    aget-byte v3, v0, v1

    .line 10
    .line 11
    int-to-long v3, v3

    .line 12
    const-wide/16 v5, 0xff

    .line 13
    .line 14
    and-long/2addr v3, v5

    .line 15
    add-int/lit8 v7, v1, 0x2

    .line 16
    .line 17
    iput v7, p0, Lw7/p;->b:I

    .line 18
    .line 19
    aget-byte v2, v0, v2

    .line 20
    .line 21
    int-to-long v8, v2

    .line 22
    and-long/2addr v8, v5

    .line 23
    const/16 v2, 0x8

    .line 24
    .line 25
    shl-long/2addr v8, v2

    .line 26
    or-long/2addr v3, v8

    .line 27
    add-int/lit8 v8, v1, 0x3

    .line 28
    .line 29
    iput v8, p0, Lw7/p;->b:I

    .line 30
    .line 31
    aget-byte v7, v0, v7

    .line 32
    .line 33
    int-to-long v9, v7

    .line 34
    and-long/2addr v9, v5

    .line 35
    const/16 v7, 0x10

    .line 36
    .line 37
    shl-long/2addr v9, v7

    .line 38
    or-long/2addr v3, v9

    .line 39
    add-int/lit8 v7, v1, 0x4

    .line 40
    .line 41
    iput v7, p0, Lw7/p;->b:I

    .line 42
    .line 43
    aget-byte v8, v0, v8

    .line 44
    .line 45
    int-to-long v8, v8

    .line 46
    and-long/2addr v8, v5

    .line 47
    const/16 v10, 0x18

    .line 48
    .line 49
    shl-long/2addr v8, v10

    .line 50
    or-long/2addr v3, v8

    .line 51
    add-int/lit8 v8, v1, 0x5

    .line 52
    .line 53
    iput v8, p0, Lw7/p;->b:I

    .line 54
    .line 55
    aget-byte v7, v0, v7

    .line 56
    .line 57
    int-to-long v9, v7

    .line 58
    and-long/2addr v9, v5

    .line 59
    const/16 v7, 0x20

    .line 60
    .line 61
    shl-long/2addr v9, v7

    .line 62
    or-long/2addr v3, v9

    .line 63
    add-int/lit8 v7, v1, 0x6

    .line 64
    .line 65
    iput v7, p0, Lw7/p;->b:I

    .line 66
    .line 67
    aget-byte v8, v0, v8

    .line 68
    .line 69
    int-to-long v8, v8

    .line 70
    and-long/2addr v8, v5

    .line 71
    const/16 v10, 0x28

    .line 72
    .line 73
    shl-long/2addr v8, v10

    .line 74
    or-long/2addr v3, v8

    .line 75
    add-int/lit8 v8, v1, 0x7

    .line 76
    .line 77
    iput v8, p0, Lw7/p;->b:I

    .line 78
    .line 79
    aget-byte v7, v0, v7

    .line 80
    .line 81
    int-to-long v9, v7

    .line 82
    and-long/2addr v9, v5

    .line 83
    const/16 v7, 0x30

    .line 84
    .line 85
    shl-long/2addr v9, v7

    .line 86
    or-long/2addr v3, v9

    .line 87
    add-int/2addr v1, v2

    .line 88
    iput v1, p0, Lw7/p;->b:I

    .line 89
    .line 90
    aget-byte p0, v0, v8

    .line 91
    .line 92
    int-to-long v0, p0

    .line 93
    and-long/2addr v0, v5

    .line 94
    const/16 p0, 0x38

    .line 95
    .line 96
    shl-long/2addr v0, p0

    .line 97
    or-long/2addr v0, v3

    .line 98
    return-wide v0
.end method

.method public final n()J
    .locals 10

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lw7/p;->b:I

    .line 8
    .line 9
    aget-byte v3, v0, v1

    .line 10
    .line 11
    int-to-long v3, v3

    .line 12
    const-wide/16 v5, 0xff

    .line 13
    .line 14
    and-long/2addr v3, v5

    .line 15
    add-int/lit8 v7, v1, 0x2

    .line 16
    .line 17
    iput v7, p0, Lw7/p;->b:I

    .line 18
    .line 19
    aget-byte v2, v0, v2

    .line 20
    .line 21
    int-to-long v8, v2

    .line 22
    and-long/2addr v8, v5

    .line 23
    const/16 v2, 0x8

    .line 24
    .line 25
    shl-long/2addr v8, v2

    .line 26
    or-long v2, v3, v8

    .line 27
    .line 28
    add-int/lit8 v4, v1, 0x3

    .line 29
    .line 30
    iput v4, p0, Lw7/p;->b:I

    .line 31
    .line 32
    aget-byte v7, v0, v7

    .line 33
    .line 34
    int-to-long v7, v7

    .line 35
    and-long/2addr v7, v5

    .line 36
    const/16 v9, 0x10

    .line 37
    .line 38
    shl-long/2addr v7, v9

    .line 39
    or-long/2addr v2, v7

    .line 40
    add-int/lit8 v1, v1, 0x4

    .line 41
    .line 42
    iput v1, p0, Lw7/p;->b:I

    .line 43
    .line 44
    aget-byte p0, v0, v4

    .line 45
    .line 46
    int-to-long v0, p0

    .line 47
    and-long/2addr v0, v5

    .line 48
    const/16 p0, 0x18

    .line 49
    .line 50
    shl-long/2addr v0, p0

    .line 51
    or-long/2addr v0, v2

    .line 52
    return-wide v0
.end method

.method public final o()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lw7/p;->l()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-ltz p0, :cond_0

    .line 6
    .line 7
    return p0

    .line 8
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 9
    .line 10
    const-string v1, "Top bit not zero: "

    .line 11
    .line 12
    invoke-static {p0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw v0
.end method

.method public final p()I
    .locals 4

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lw7/p;->b:I

    .line 8
    .line 9
    aget-byte v3, v0, v1

    .line 10
    .line 11
    and-int/lit16 v3, v3, 0xff

    .line 12
    .line 13
    add-int/lit8 v1, v1, 0x2

    .line 14
    .line 15
    iput v1, p0, Lw7/p;->b:I

    .line 16
    .line 17
    aget-byte p0, v0, v2

    .line 18
    .line 19
    and-int/lit16 p0, p0, 0xff

    .line 20
    .line 21
    shl-int/lit8 p0, p0, 0x8

    .line 22
    .line 23
    or-int/2addr p0, v3

    .line 24
    return p0
.end method

.method public final q()J
    .locals 10

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lw7/p;->b:I

    .line 8
    .line 9
    aget-byte v3, v0, v1

    .line 10
    .line 11
    int-to-long v3, v3

    .line 12
    const-wide/16 v5, 0xff

    .line 13
    .line 14
    and-long/2addr v3, v5

    .line 15
    const/16 v7, 0x38

    .line 16
    .line 17
    shl-long/2addr v3, v7

    .line 18
    add-int/lit8 v7, v1, 0x2

    .line 19
    .line 20
    iput v7, p0, Lw7/p;->b:I

    .line 21
    .line 22
    aget-byte v2, v0, v2

    .line 23
    .line 24
    int-to-long v8, v2

    .line 25
    and-long/2addr v8, v5

    .line 26
    const/16 v2, 0x30

    .line 27
    .line 28
    shl-long/2addr v8, v2

    .line 29
    or-long v2, v3, v8

    .line 30
    .line 31
    add-int/lit8 v4, v1, 0x3

    .line 32
    .line 33
    iput v4, p0, Lw7/p;->b:I

    .line 34
    .line 35
    aget-byte v7, v0, v7

    .line 36
    .line 37
    int-to-long v7, v7

    .line 38
    and-long/2addr v7, v5

    .line 39
    const/16 v9, 0x28

    .line 40
    .line 41
    shl-long/2addr v7, v9

    .line 42
    or-long/2addr v2, v7

    .line 43
    add-int/lit8 v7, v1, 0x4

    .line 44
    .line 45
    iput v7, p0, Lw7/p;->b:I

    .line 46
    .line 47
    aget-byte v4, v0, v4

    .line 48
    .line 49
    int-to-long v8, v4

    .line 50
    and-long/2addr v8, v5

    .line 51
    const/16 v4, 0x20

    .line 52
    .line 53
    shl-long/2addr v8, v4

    .line 54
    or-long/2addr v2, v8

    .line 55
    add-int/lit8 v4, v1, 0x5

    .line 56
    .line 57
    iput v4, p0, Lw7/p;->b:I

    .line 58
    .line 59
    aget-byte v7, v0, v7

    .line 60
    .line 61
    int-to-long v7, v7

    .line 62
    and-long/2addr v7, v5

    .line 63
    const/16 v9, 0x18

    .line 64
    .line 65
    shl-long/2addr v7, v9

    .line 66
    or-long/2addr v2, v7

    .line 67
    add-int/lit8 v7, v1, 0x6

    .line 68
    .line 69
    iput v7, p0, Lw7/p;->b:I

    .line 70
    .line 71
    aget-byte v4, v0, v4

    .line 72
    .line 73
    int-to-long v8, v4

    .line 74
    and-long/2addr v8, v5

    .line 75
    const/16 v4, 0x10

    .line 76
    .line 77
    shl-long/2addr v8, v4

    .line 78
    or-long/2addr v2, v8

    .line 79
    add-int/lit8 v4, v1, 0x7

    .line 80
    .line 81
    iput v4, p0, Lw7/p;->b:I

    .line 82
    .line 83
    aget-byte v7, v0, v7

    .line 84
    .line 85
    int-to-long v7, v7

    .line 86
    and-long/2addr v7, v5

    .line 87
    const/16 v9, 0x8

    .line 88
    .line 89
    shl-long/2addr v7, v9

    .line 90
    or-long/2addr v2, v7

    .line 91
    add-int/2addr v1, v9

    .line 92
    iput v1, p0, Lw7/p;->b:I

    .line 93
    .line 94
    aget-byte p0, v0, v4

    .line 95
    .line 96
    int-to-long v0, p0

    .line 97
    and-long/2addr v0, v5

    .line 98
    or-long/2addr v0, v2

    .line 99
    return-wide v0
.end method

.method public final r()Ljava/lang/String;
    .locals 6

    .line 1
    invoke-virtual {p0}, Lw7/p;->a()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    iget v0, p0, Lw7/p;->b:I

    .line 10
    .line 11
    :goto_0
    iget v1, p0, Lw7/p;->c:I

    .line 12
    .line 13
    if-ge v0, v1, :cond_1

    .line 14
    .line 15
    iget-object v1, p0, Lw7/p;->a:[B

    .line 16
    .line 17
    aget-byte v1, v1, v0

    .line 18
    .line 19
    if-eqz v1, :cond_1

    .line 20
    .line 21
    add-int/lit8 v0, v0, 0x1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_1
    iget-object v1, p0, Lw7/p;->a:[B

    .line 25
    .line 26
    iget v2, p0, Lw7/p;->b:I

    .line 27
    .line 28
    sub-int v3, v0, v2

    .line 29
    .line 30
    sget-object v4, Lw7/w;->a:Ljava/lang/String;

    .line 31
    .line 32
    new-instance v4, Ljava/lang/String;

    .line 33
    .line 34
    sget-object v5, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 35
    .line 36
    invoke-direct {v4, v1, v2, v3, v5}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 37
    .line 38
    .line 39
    iput v0, p0, Lw7/p;->b:I

    .line 40
    .line 41
    iget v1, p0, Lw7/p;->c:I

    .line 42
    .line 43
    if-ge v0, v1, :cond_2

    .line 44
    .line 45
    add-int/lit8 v0, v0, 0x1

    .line 46
    .line 47
    iput v0, p0, Lw7/p;->b:I

    .line 48
    .line 49
    :cond_2
    return-object v4
.end method

.method public final s(I)Ljava/lang/String;
    .locals 5

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const-string p0, ""

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    iget v0, p0, Lw7/p;->b:I

    .line 7
    .line 8
    add-int v1, v0, p1

    .line 9
    .line 10
    add-int/lit8 v1, v1, -0x1

    .line 11
    .line 12
    iget v2, p0, Lw7/p;->c:I

    .line 13
    .line 14
    if-ge v1, v2, :cond_1

    .line 15
    .line 16
    iget-object v2, p0, Lw7/p;->a:[B

    .line 17
    .line 18
    aget-byte v1, v2, v1

    .line 19
    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    add-int/lit8 v1, p1, -0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    move v1, p1

    .line 26
    :goto_0
    iget-object v2, p0, Lw7/p;->a:[B

    .line 27
    .line 28
    sget-object v3, Lw7/w;->a:Ljava/lang/String;

    .line 29
    .line 30
    new-instance v3, Ljava/lang/String;

    .line 31
    .line 32
    sget-object v4, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 33
    .line 34
    invoke-direct {v3, v2, v0, v1, v4}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 35
    .line 36
    .line 37
    iget v0, p0, Lw7/p;->b:I

    .line 38
    .line 39
    add-int/2addr v0, p1

    .line 40
    iput v0, p0, Lw7/p;->b:I

    .line 41
    .line 42
    return-object v3
.end method

.method public final t()S
    .locals 4

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lw7/p;->b:I

    .line 8
    .line 9
    aget-byte v3, v0, v1

    .line 10
    .line 11
    and-int/lit16 v3, v3, 0xff

    .line 12
    .line 13
    shl-int/lit8 v3, v3, 0x8

    .line 14
    .line 15
    add-int/lit8 v1, v1, 0x2

    .line 16
    .line 17
    iput v1, p0, Lw7/p;->b:I

    .line 18
    .line 19
    aget-byte p0, v0, v2

    .line 20
    .line 21
    and-int/lit16 p0, p0, 0xff

    .line 22
    .line 23
    or-int/2addr p0, v3

    .line 24
    int-to-short p0, p0

    .line 25
    return p0
.end method

.method public final u(ILjava/nio/charset/Charset;)Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/String;

    .line 2
    .line 3
    iget-object v1, p0, Lw7/p;->a:[B

    .line 4
    .line 5
    iget v2, p0, Lw7/p;->b:I

    .line 6
    .line 7
    invoke-direct {v0, v1, v2, p1, p2}, Ljava/lang/String;-><init>([BIILjava/nio/charset/Charset;)V

    .line 8
    .line 9
    .line 10
    iget p2, p0, Lw7/p;->b:I

    .line 11
    .line 12
    add-int/2addr p2, p1

    .line 13
    iput p2, p0, Lw7/p;->b:I

    .line 14
    .line 15
    return-object v0
.end method

.method public final v()I
    .locals 3

    .line 1
    invoke-virtual {p0}, Lw7/p;->w()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Lw7/p;->w()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {p0}, Lw7/p;->w()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    invoke-virtual {p0}, Lw7/p;->w()I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    shl-int/lit8 v0, v0, 0x15

    .line 18
    .line 19
    shl-int/lit8 v1, v1, 0xe

    .line 20
    .line 21
    or-int/2addr v0, v1

    .line 22
    shl-int/lit8 v1, v2, 0x7

    .line 23
    .line 24
    or-int/2addr v0, v1

    .line 25
    or-int/2addr p0, v0

    .line 26
    return p0
.end method

.method public final w()I
    .locals 3

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lw7/p;->b:I

    .line 8
    .line 9
    aget-byte p0, v0, v1

    .line 10
    .line 11
    and-int/lit16 p0, p0, 0xff

    .line 12
    .line 13
    return p0
.end method

.method public final x()I
    .locals 5

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lw7/p;->b:I

    .line 8
    .line 9
    aget-byte v3, v0, v1

    .line 10
    .line 11
    and-int/lit16 v3, v3, 0xff

    .line 12
    .line 13
    shl-int/lit8 v3, v3, 0x8

    .line 14
    .line 15
    add-int/lit8 v4, v1, 0x2

    .line 16
    .line 17
    iput v4, p0, Lw7/p;->b:I

    .line 18
    .line 19
    aget-byte v0, v0, v2

    .line 20
    .line 21
    and-int/lit16 v0, v0, 0xff

    .line 22
    .line 23
    or-int/2addr v0, v3

    .line 24
    add-int/lit8 v1, v1, 0x4

    .line 25
    .line 26
    iput v1, p0, Lw7/p;->b:I

    .line 27
    .line 28
    return v0
.end method

.method public final y()J
    .locals 10

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lw7/p;->b:I

    .line 8
    .line 9
    aget-byte v3, v0, v1

    .line 10
    .line 11
    int-to-long v3, v3

    .line 12
    const-wide/16 v5, 0xff

    .line 13
    .line 14
    and-long/2addr v3, v5

    .line 15
    const/16 v7, 0x18

    .line 16
    .line 17
    shl-long/2addr v3, v7

    .line 18
    add-int/lit8 v7, v1, 0x2

    .line 19
    .line 20
    iput v7, p0, Lw7/p;->b:I

    .line 21
    .line 22
    aget-byte v2, v0, v2

    .line 23
    .line 24
    int-to-long v8, v2

    .line 25
    and-long/2addr v8, v5

    .line 26
    const/16 v2, 0x10

    .line 27
    .line 28
    shl-long/2addr v8, v2

    .line 29
    or-long v2, v3, v8

    .line 30
    .line 31
    add-int/lit8 v4, v1, 0x3

    .line 32
    .line 33
    iput v4, p0, Lw7/p;->b:I

    .line 34
    .line 35
    aget-byte v7, v0, v7

    .line 36
    .line 37
    int-to-long v7, v7

    .line 38
    and-long/2addr v7, v5

    .line 39
    const/16 v9, 0x8

    .line 40
    .line 41
    shl-long/2addr v7, v9

    .line 42
    or-long/2addr v2, v7

    .line 43
    add-int/lit8 v1, v1, 0x4

    .line 44
    .line 45
    iput v1, p0, Lw7/p;->b:I

    .line 46
    .line 47
    aget-byte p0, v0, v4

    .line 48
    .line 49
    int-to-long v0, p0

    .line 50
    and-long/2addr v0, v5

    .line 51
    or-long/2addr v0, v2

    .line 52
    return-wide v0
.end method

.method public final z()I
    .locals 5

    .line 1
    iget-object v0, p0, Lw7/p;->a:[B

    .line 2
    .line 3
    iget v1, p0, Lw7/p;->b:I

    .line 4
    .line 5
    add-int/lit8 v2, v1, 0x1

    .line 6
    .line 7
    iput v2, p0, Lw7/p;->b:I

    .line 8
    .line 9
    aget-byte v3, v0, v1

    .line 10
    .line 11
    and-int/lit16 v3, v3, 0xff

    .line 12
    .line 13
    shl-int/lit8 v3, v3, 0x10

    .line 14
    .line 15
    add-int/lit8 v4, v1, 0x2

    .line 16
    .line 17
    iput v4, p0, Lw7/p;->b:I

    .line 18
    .line 19
    aget-byte v2, v0, v2

    .line 20
    .line 21
    and-int/lit16 v2, v2, 0xff

    .line 22
    .line 23
    shl-int/lit8 v2, v2, 0x8

    .line 24
    .line 25
    or-int/2addr v2, v3

    .line 26
    add-int/lit8 v1, v1, 0x3

    .line 27
    .line 28
    iput v1, p0, Lw7/p;->b:I

    .line 29
    .line 30
    aget-byte p0, v0, v4

    .line 31
    .line 32
    and-int/lit16 p0, p0, 0xff

    .line 33
    .line 34
    or-int/2addr p0, v2

    .line 35
    return p0
.end method
