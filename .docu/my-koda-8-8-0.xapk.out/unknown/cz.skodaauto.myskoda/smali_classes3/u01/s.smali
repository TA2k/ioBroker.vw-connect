.class public final Lu01/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/h0;


# instance fields
.field public final d:Ljava/io/InputStream;

.field public final e:Lu01/j0;


# direct methods
.method public constructor <init>(Ljava/io/InputStream;Lu01/j0;)V
    .locals 1

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lu01/s;->d:Ljava/io/InputStream;

    .line 10
    .line 11
    iput-object p2, p0, Lu01/s;->e:Lu01/j0;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 3

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
    if-nez v2, :cond_0

    .line 11
    .line 12
    return-wide v0

    .line 13
    :cond_0
    if-ltz v2, :cond_4

    .line 14
    .line 15
    :try_start_0
    iget-object v0, p0, Lu01/s;->e:Lu01/j0;

    .line 16
    .line 17
    invoke-virtual {v0}, Lu01/j0;->f()V

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    invoke-virtual {p1, v0}, Lu01/f;->W(I)Lu01/c0;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    iget v1, v0, Lu01/c0;->c:I

    .line 26
    .line 27
    rsub-int v1, v1, 0x2000

    .line 28
    .line 29
    int-to-long v1, v1

    .line 30
    invoke-static {p2, p3, v1, v2}, Ljava/lang/Math;->min(JJ)J

    .line 31
    .line 32
    .line 33
    move-result-wide p2

    .line 34
    long-to-int p2, p2

    .line 35
    iget-object p0, p0, Lu01/s;->d:Ljava/io/InputStream;

    .line 36
    .line 37
    iget-object p3, v0, Lu01/c0;->a:[B

    .line 38
    .line 39
    iget v1, v0, Lu01/c0;->c:I

    .line 40
    .line 41
    invoke-virtual {p0, p3, v1, p2}, Ljava/io/InputStream;->read([BII)I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    const/4 p2, -0x1

    .line 46
    if-ne p0, p2, :cond_2

    .line 47
    .line 48
    iget p0, v0, Lu01/c0;->b:I

    .line 49
    .line 50
    iget p2, v0, Lu01/c0;->c:I

    .line 51
    .line 52
    if-ne p0, p2, :cond_1

    .line 53
    .line 54
    invoke-virtual {v0}, Lu01/c0;->a()Lu01/c0;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    iput-object p0, p1, Lu01/f;->d:Lu01/c0;

    .line 59
    .line 60
    invoke-static {v0}, Lu01/d0;->a(Lu01/c0;)V

    .line 61
    .line 62
    .line 63
    :cond_1
    const-wide/16 p0, -0x1

    .line 64
    .line 65
    return-wide p0

    .line 66
    :cond_2
    iget p2, v0, Lu01/c0;->c:I

    .line 67
    .line 68
    add-int/2addr p2, p0

    .line 69
    iput p2, v0, Lu01/c0;->c:I

    .line 70
    .line 71
    iget-wide p2, p1, Lu01/f;->e:J

    .line 72
    .line 73
    int-to-long v0, p0

    .line 74
    add-long/2addr p2, v0

    .line 75
    iput-wide p2, p1, Lu01/f;->e:J
    :try_end_0
    .catch Ljava/lang/AssertionError; {:try_start_0 .. :try_end_0} :catch_0

    .line 76
    .line 77
    return-wide v0

    .line 78
    :catch_0
    move-exception p0

    .line 79
    invoke-static {p0}, Lv01/k;->a(Ljava/lang/AssertionError;)Z

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    if-eqz p1, :cond_3

    .line 84
    .line 85
    new-instance p1, Ljava/io/IOException;

    .line 86
    .line 87
    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/Throwable;)V

    .line 88
    .line 89
    .line 90
    throw p1

    .line 91
    :cond_3
    throw p0

    .line 92
    :cond_4
    const-string p0, "byteCount < 0: "

    .line 93
    .line 94
    invoke-static {p2, p3, p0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 99
    .line 100
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    throw p1
.end method

.method public final close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lu01/s;->d:Ljava/io/InputStream;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/io/InputStream;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final timeout()Lu01/j0;
    .locals 0

    .line 1
    iget-object p0, p0, Lu01/s;->e:Lu01/j0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "source("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lu01/s;->d:Ljava/io/InputStream;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const/16 p0, 0x29

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method
