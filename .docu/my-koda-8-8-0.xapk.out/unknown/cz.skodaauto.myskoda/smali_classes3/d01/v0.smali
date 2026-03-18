.class public abstract Ld01/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# static fields
.field public static final d:Ld01/u0;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    sget-object v0, Lu01/i;->g:Lu01/i;

    .line 2
    .line 3
    const-string v1, "<this>"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lu01/f;

    .line 9
    .line 10
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v1, v0}, Lu01/f;->e0(Lu01/i;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, v0, Lu01/i;->d:[B

    .line 17
    .line 18
    array-length v0, v0

    .line 19
    int-to-long v2, v0

    .line 20
    new-instance v0, Ld01/u0;

    .line 21
    .line 22
    const/4 v4, 0x0

    .line 23
    invoke-direct {v0, v4, v2, v3, v1}, Ld01/u0;-><init>(Ld01/d0;JLu01/f;)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Ld01/v0;->d:Ld01/u0;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final a()[B
    .locals 6

    .line 1
    invoke-virtual {p0}, Ld01/v0;->b()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-wide/32 v2, 0x7fffffff

    .line 6
    .line 7
    .line 8
    cmp-long v2, v0, v2

    .line 9
    .line 10
    if-gtz v2, :cond_4

    .line 11
    .line 12
    invoke-virtual {p0}, Ld01/v0;->p0()Lu01/h;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const/4 v2, 0x0

    .line 17
    :try_start_0
    invoke-interface {p0}, Lu01/h;->Y()[B

    .line 18
    .line 19
    .line 20
    move-result-object v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 21
    :try_start_1
    invoke-interface {p0}, Ljava/io/Closeable;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :catchall_0
    move-exception v2

    .line 26
    :goto_0
    move-object v5, v3

    .line 27
    move-object v3, v2

    .line 28
    move-object v2, v5

    .line 29
    goto :goto_1

    .line 30
    :catchall_1
    move-exception v3

    .line 31
    if-eqz p0, :cond_0

    .line 32
    .line 33
    :try_start_2
    invoke-interface {p0}, Ljava/io/Closeable;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 34
    .line 35
    .line 36
    goto :goto_1

    .line 37
    :catchall_2
    move-exception p0

    .line 38
    invoke-static {v3, p0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 39
    .line 40
    .line 41
    :cond_0
    :goto_1
    if-nez v3, :cond_3

    .line 42
    .line 43
    array-length p0, v2

    .line 44
    const-wide/16 v3, -0x1

    .line 45
    .line 46
    cmp-long v3, v0, v3

    .line 47
    .line 48
    if-eqz v3, :cond_2

    .line 49
    .line 50
    int-to-long v3, p0

    .line 51
    cmp-long v3, v0, v3

    .line 52
    .line 53
    if-nez v3, :cond_1

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_1
    new-instance v2, Ljava/io/IOException;

    .line 57
    .line 58
    new-instance v3, Ljava/lang/StringBuilder;

    .line 59
    .line 60
    const-string v4, "Content-Length ("

    .line 61
    .line 62
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v3, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string v0, ") and stream length ("

    .line 69
    .line 70
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string p0, ") disagree"

    .line 77
    .line 78
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-direct {v2, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw v2

    .line 89
    :cond_2
    :goto_2
    return-object v2

    .line 90
    :cond_3
    throw v3

    .line 91
    :cond_4
    new-instance p0, Ljava/io/IOException;

    .line 92
    .line 93
    const-string v2, "Cannot buffer entire body for content length: "

    .line 94
    .line 95
    invoke-static {v0, v1, v2}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw p0
.end method

.method public abstract b()J
.end method

.method public close()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ld01/v0;->p0()Lu01/h;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Le01/e;->b(Ljava/io/Closeable;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public abstract d()Ld01/d0;
.end method

.method public final f()Ljava/lang/String;
    .locals 4

    .line 1
    invoke-virtual {p0}, Ld01/v0;->p0()Lu01/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :try_start_0
    invoke-virtual {p0}, Ld01/v0;->d()Ld01/d0;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    sget-object v2, Ld01/d0;->e:Lly0/n;

    .line 13
    .line 14
    invoke-virtual {p0, v1}, Ld01/d0;->a(Ljava/nio/charset/Charset;)Ljava/nio/charset/Charset;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    if-nez p0, :cond_1

    .line 19
    .line 20
    :cond_0
    sget-object p0, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 21
    .line 22
    :cond_1
    invoke-static {v0, p0}, Le01/g;->f(Lu01/h;Ljava/nio/charset/Charset;)Ljava/nio/charset/Charset;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-interface {v0, p0}, Lu01/h;->f0(Ljava/nio/charset/Charset;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 30
    :try_start_1
    invoke-interface {v0}, Ljava/io/Closeable;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :catchall_0
    move-exception v1

    .line 35
    :goto_0
    move-object v3, v1

    .line 36
    move-object v1, p0

    .line 37
    move-object p0, v3

    .line 38
    goto :goto_1

    .line 39
    :catchall_1
    move-exception p0

    .line 40
    if-eqz v0, :cond_2

    .line 41
    .line 42
    :try_start_2
    invoke-interface {v0}, Ljava/io/Closeable;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :catchall_2
    move-exception v0

    .line 47
    invoke-static {p0, v0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 48
    .line 49
    .line 50
    :cond_2
    :goto_1
    if-nez p0, :cond_3

    .line 51
    .line 52
    return-object v1

    .line 53
    :cond_3
    throw p0
.end method

.method public abstract p0()Lu01/h;
.end method
