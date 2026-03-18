.class public final Lv6/a;
.super Landroid/media/MediaDataSource;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public d:J

.field public final synthetic e:Lv6/f;


# direct methods
.method public constructor <init>(Lv6/f;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lv6/a;->e:Lv6/f;

    .line 2
    .line 3
    invoke-direct {p0}, Landroid/media/MediaDataSource;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final close()V
    .locals 0

    .line 1
    return-void
.end method

.method public final getSize()J
    .locals 2

    .line 1
    const-wide/16 v0, -0x1

    .line 2
    .line 3
    return-wide v0
.end method

.method public final readAt(J[BII)I
    .locals 7

    .line 1
    if-nez p5, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    const-wide/16 v0, 0x0

    .line 6
    .line 7
    cmp-long v2, p1, v0

    .line 8
    .line 9
    const/4 v3, -0x1

    .line 10
    if-gez v2, :cond_1

    .line 11
    .line 12
    return v3

    .line 13
    :cond_1
    :try_start_0
    iget-wide v4, p0, Lv6/a;->d:J
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    cmp-long v2, v4, p1

    .line 16
    .line 17
    iget-object v6, p0, Lv6/a;->e:Lv6/f;

    .line 18
    .line 19
    if-eqz v2, :cond_3

    .line 20
    .line 21
    cmp-long v0, v4, v0

    .line 22
    .line 23
    if-ltz v0, :cond_2

    .line 24
    .line 25
    :try_start_1
    iget-object v0, v6, Lv6/b;->d:Ljava/io/DataInputStream;

    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/io/InputStream;->available()I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    int-to-long v0, v0

    .line 32
    add-long/2addr v4, v0

    .line 33
    cmp-long v0, p1, v4

    .line 34
    .line 35
    if-ltz v0, :cond_2

    .line 36
    .line 37
    return v3

    .line 38
    :cond_2
    invoke-virtual {v6, p1, p2}, Lv6/f;->b(J)V

    .line 39
    .line 40
    .line 41
    iput-wide p1, p0, Lv6/a;->d:J

    .line 42
    .line 43
    :cond_3
    iget-object p1, v6, Lv6/b;->d:Ljava/io/DataInputStream;

    .line 44
    .line 45
    invoke-virtual {p1}, Ljava/io/InputStream;->available()I

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    if-le p5, p1, :cond_4

    .line 50
    .line 51
    iget-object p1, v6, Lv6/b;->d:Ljava/io/DataInputStream;

    .line 52
    .line 53
    invoke-virtual {p1}, Ljava/io/InputStream;->available()I

    .line 54
    .line 55
    .line 56
    move-result p5

    .line 57
    :cond_4
    invoke-virtual {v6, p3, p4, p5}, Lv6/b;->read([BII)I

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    if-ltz p1, :cond_5

    .line 62
    .line 63
    iget-wide p2, p0, Lv6/a;->d:J

    .line 64
    .line 65
    int-to-long p4, p1

    .line 66
    add-long/2addr p2, p4

    .line 67
    iput-wide p2, p0, Lv6/a;->d:J
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    .line 68
    .line 69
    return p1

    .line 70
    :catch_0
    :cond_5
    const-wide/16 p1, -0x1

    .line 71
    .line 72
    iput-wide p1, p0, Lv6/a;->d:J

    .line 73
    .line 74
    return v3
.end method
