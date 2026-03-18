.class public final Lj01/d;
.super Lj01/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public h:J

.field public final synthetic i:Lj01/f;


# direct methods
.method public constructor <init>(Lj01/f;Ld01/a0;J)V
    .locals 1

    .line 1
    const-string v0, "url"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lj01/d;->i:Lj01/f;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2}, Lj01/a;-><init>(Lj01/f;Ld01/a0;)V

    .line 9
    .line 10
    .line 11
    iput-wide p3, p0, Lj01/d;->h:J

    .line 12
    .line 13
    const-wide/16 p1, 0x0

    .line 14
    .line 15
    cmp-long p1, p3, p1

    .line 16
    .line 17
    if-nez p1, :cond_0

    .line 18
    .line 19
    sget-object p1, Ld01/y;->e:Ld01/y;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lj01/a;->a(Ld01/y;)V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 7

    .line 1
    const-string v0, "sink"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-wide/16 v0, 0x0

    .line 7
    .line 8
    cmp-long v2, p2, v0

    .line 9
    .line 10
    if-ltz v2, :cond_4

    .line 11
    .line 12
    iget-boolean v2, p0, Lj01/a;->f:Z

    .line 13
    .line 14
    if-nez v2, :cond_3

    .line 15
    .line 16
    iget-wide v2, p0, Lj01/d;->h:J

    .line 17
    .line 18
    cmp-long v4, v2, v0

    .line 19
    .line 20
    const-wide/16 v5, -0x1

    .line 21
    .line 22
    if-nez v4, :cond_0

    .line 23
    .line 24
    return-wide v5

    .line 25
    :cond_0
    invoke-static {v2, v3, p2, p3}, Ljava/lang/Math;->min(JJ)J

    .line 26
    .line 27
    .line 28
    move-result-wide p2

    .line 29
    invoke-super {p0, p1, p2, p3}, Lj01/a;->A(Lu01/f;J)J

    .line 30
    .line 31
    .line 32
    move-result-wide p1

    .line 33
    cmp-long p3, p1, v5

    .line 34
    .line 35
    if-eqz p3, :cond_2

    .line 36
    .line 37
    iget-wide v2, p0, Lj01/d;->h:J

    .line 38
    .line 39
    sub-long/2addr v2, p1

    .line 40
    iput-wide v2, p0, Lj01/d;->h:J

    .line 41
    .line 42
    cmp-long p3, v2, v0

    .line 43
    .line 44
    if-nez p3, :cond_1

    .line 45
    .line 46
    sget-object p3, Ld01/y;->e:Ld01/y;

    .line 47
    .line 48
    invoke-virtual {p0, p3}, Lj01/a;->a(Ld01/y;)V

    .line 49
    .line 50
    .line 51
    :cond_1
    return-wide p1

    .line 52
    :cond_2
    iget-object p1, p0, Lj01/d;->i:Lj01/f;

    .line 53
    .line 54
    iget-object p1, p1, Lj01/f;->b:Li01/c;

    .line 55
    .line 56
    invoke-interface {p1}, Li01/c;->c()V

    .line 57
    .line 58
    .line 59
    new-instance p1, Ljava/net/ProtocolException;

    .line 60
    .line 61
    const-string p2, "unexpected end of stream"

    .line 62
    .line 63
    invoke-direct {p1, p2}, Ljava/net/ProtocolException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    sget-object p2, Lj01/f;->g:Ld01/y;

    .line 67
    .line 68
    invoke-virtual {p0, p2}, Lj01/a;->a(Ld01/y;)V

    .line 69
    .line 70
    .line 71
    throw p1

    .line 72
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 73
    .line 74
    const-string p1, "closed"

    .line 75
    .line 76
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw p0

    .line 80
    :cond_4
    const-string p0, "byteCount < 0: "

    .line 81
    .line 82
    invoke-static {p2, p3, p0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 87
    .line 88
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw p1
.end method

.method public final close()V
    .locals 4

    .line 1
    iget-boolean v0, p0, Lj01/a;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-wide v0, p0, Lj01/d;->h:J

    .line 7
    .line 8
    const-wide/16 v2, 0x0

    .line 9
    .line 10
    cmp-long v0, v0, v2

    .line 11
    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 15
    .line 16
    sget-object v1, Le01/g;->a:Ljava/util/TimeZone;

    .line 17
    .line 18
    const-string v1, "timeUnit"

    .line 19
    .line 20
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const/16 v0, 0x64

    .line 24
    .line 25
    :try_start_0
    invoke-static {p0, v0}, Le01/g;->g(Lu01/h0;I)Z

    .line 26
    .line 27
    .line 28
    move-result v0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 29
    goto :goto_0

    .line 30
    :catch_0
    const/4 v0, 0x0

    .line 31
    :goto_0
    if-nez v0, :cond_1

    .line 32
    .line 33
    iget-object v0, p0, Lj01/d;->i:Lj01/f;

    .line 34
    .line 35
    iget-object v0, v0, Lj01/f;->b:Li01/c;

    .line 36
    .line 37
    invoke-interface {v0}, Li01/c;->c()V

    .line 38
    .line 39
    .line 40
    sget-object v0, Lj01/f;->g:Ld01/y;

    .line 41
    .line 42
    invoke-virtual {p0, v0}, Lj01/a;->a(Ld01/y;)V

    .line 43
    .line 44
    .line 45
    :cond_1
    const/4 v0, 0x1

    .line 46
    iput-boolean v0, p0, Lj01/a;->f:Z

    .line 47
    .line 48
    return-void
.end method
