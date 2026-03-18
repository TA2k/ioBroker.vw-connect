.class public abstract Li9/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x1d

    .line 2
    .line 3
    new-array v0, v0, [I

    .line 4
    .line 5
    fill-array-data v0, :array_0

    .line 6
    .line 7
    .line 8
    sput-object v0, Li9/p;->a:[I

    .line 9
    .line 10
    return-void

    .line 11
    :array_0
    .array-data 4
        0x69736f6d
        0x69736f32
        0x69736f33
        0x69736f34
        0x69736f35
        0x69736f36
        0x69736f39
        0x61766331
        0x68766331
        0x68657631
        0x61763031
        0x6d703431
        0x6d703432
        0x33673261
        0x33673262
        0x33677236
        0x33677336
        0x33676536
        0x33676736
        0x4d345620    # 1.89096448E8f
        0x4d344120    # 1.89010432E8f
        0x66347620
        0x6b646469
        0x4d345650
        0x71742020
        0x4d534e56    # 2.215704E8f
        0x64627931
        0x69736d6c
        0x70696666
    .end array-data
.end method

.method public static a(Lt7/c0;Ljava/lang/String;)Lx7/a;
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    iget-object v1, p0, Lt7/c0;->a:[Lt7/b0;

    .line 3
    .line 4
    array-length v2, v1

    .line 5
    if-ge v0, v2, :cond_1

    .line 6
    .line 7
    aget-object v1, v1, v0

    .line 8
    .line 9
    instance-of v2, v1, Lx7/a;

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    check-cast v1, Lx7/a;

    .line 14
    .line 15
    iget-object v2, v1, Lx7/a;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-virtual {v2, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    return-object v1

    .line 24
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    const/4 p0, 0x0

    .line 28
    return-object p0
.end method

.method public static b(Ljava/util/ArrayList;)Ljava/lang/String;
    .locals 4

    .line 1
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const/4 v0, 0x0

    .line 6
    const/4 v1, 0x0

    .line 7
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    if-eqz v2, :cond_4

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    check-cast v2, Li9/t;

    .line 18
    .line 19
    iget-object v2, v2, Li9/t;->a:Li9/q;

    .line 20
    .line 21
    iget-object v2, v2, Li9/q;->g:Lt7/o;

    .line 22
    .line 23
    iget-object v2, v2, Lt7/o;->n:Ljava/lang/String;

    .line 24
    .line 25
    invoke-static {v2}, Lt7/d0;->l(Ljava/lang/String;)Z

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    if-eqz v3, :cond_1

    .line 30
    .line 31
    const-string p0, "video/mp4"

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_1
    invoke-static {v2}, Lt7/d0;->i(Ljava/lang/String;)Z

    .line 35
    .line 36
    .line 37
    move-result v3

    .line 38
    if-eqz v3, :cond_2

    .line 39
    .line 40
    const/4 v0, 0x1

    .line 41
    goto :goto_0

    .line 42
    :cond_2
    invoke-static {v2}, Lt7/d0;->j(Ljava/lang/String;)Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-eqz v3, :cond_0

    .line 47
    .line 48
    const-string v3, "image/heic"

    .line 49
    .line 50
    invoke-static {v2, v3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    if-eqz v3, :cond_3

    .line 55
    .line 56
    const-string v1, "image/heif"

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_3
    const-string v3, "image/avif"

    .line 60
    .line 61
    invoke-static {v2, v3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-eqz v2, :cond_0

    .line 66
    .line 67
    move-object v1, v3

    .line 68
    goto :goto_0

    .line 69
    :cond_4
    if-eqz v0, :cond_5

    .line 70
    .line 71
    const-string p0, "audio/mp4"

    .line 72
    .line 73
    return-object p0

    .line 74
    :cond_5
    if-eqz v1, :cond_6

    .line 75
    .line 76
    return-object v1

    .line 77
    :cond_6
    const-string p0, "application/mp4"

    .line 78
    .line 79
    return-object p0
.end method

.method public static c(IZ)Z
    .locals 3

    .line 1
    ushr-int/lit8 v0, p0, 0x8

    .line 2
    .line 3
    const v1, 0x336770

    .line 4
    .line 5
    .line 6
    const/4 v2, 0x1

    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    return v2

    .line 10
    :cond_0
    const v0, 0x68656963

    .line 11
    .line 12
    .line 13
    if-ne p0, v0, :cond_1

    .line 14
    .line 15
    if-eqz p1, :cond_1

    .line 16
    .line 17
    return v2

    .line 18
    :cond_1
    const/4 p1, 0x0

    .line 19
    move v0, p1

    .line 20
    :goto_0
    const/16 v1, 0x1d

    .line 21
    .line 22
    if-ge v0, v1, :cond_3

    .line 23
    .line 24
    sget-object v1, Li9/p;->a:[I

    .line 25
    .line 26
    aget v1, v1, v0

    .line 27
    .line 28
    if-ne v1, p0, :cond_2

    .line 29
    .line 30
    return v2

    .line 31
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_3
    return p1
.end method

.method public static d(ILw7/p;)Lc9/e;
    .locals 3

    .line 1
    invoke-virtual {p1}, Lw7/p;->j()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Lw7/p;->j()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const v2, 0x64617461

    .line 10
    .line 11
    .line 12
    if-ne v1, v2, :cond_0

    .line 13
    .line 14
    const/16 p0, 0x8

    .line 15
    .line 16
    invoke-virtual {p1, p0}, Lw7/p;->J(I)V

    .line 17
    .line 18
    .line 19
    add-int/lit8 v0, v0, -0x10

    .line 20
    .line 21
    invoke-virtual {p1, v0}, Lw7/p;->s(I)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    new-instance p1, Lc9/e;

    .line 26
    .line 27
    const-string v0, "und"

    .line 28
    .line 29
    invoke-direct {p1, v0, p0, p0}, Lc9/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    .line 34
    .line 35
    const-string v0, "Failed to parse comment attribute: "

    .line 36
    .line 37
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    invoke-static {p0}, Lkq/d;->b(I)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    const-string p1, "MetadataUtil"

    .line 52
    .line 53
    invoke-static {p1, p0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    const/4 p0, 0x0

    .line 57
    return-object p0
.end method

.method public static e(Lw7/p;)Lc9/a;
    .locals 5

    .line 1
    invoke-virtual {p0}, Lw7/p;->j()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Lw7/p;->j()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const v2, 0x64617461

    .line 10
    .line 11
    .line 12
    const-string v3, "MetadataUtil"

    .line 13
    .line 14
    const/4 v4, 0x0

    .line 15
    if-ne v1, v2, :cond_3

    .line 16
    .line 17
    invoke-virtual {p0}, Lw7/p;->j()I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    sget-object v2, Li9/e;->a:[B

    .line 22
    .line 23
    const v2, 0xffffff

    .line 24
    .line 25
    .line 26
    and-int/2addr v1, v2

    .line 27
    const/16 v2, 0xd

    .line 28
    .line 29
    if-ne v1, v2, :cond_0

    .line 30
    .line 31
    const-string v2, "image/jpeg"

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/16 v2, 0xe

    .line 35
    .line 36
    if-ne v1, v2, :cond_1

    .line 37
    .line 38
    const-string v2, "image/png"

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    move-object v2, v4

    .line 42
    :goto_0
    if-nez v2, :cond_2

    .line 43
    .line 44
    const-string p0, "Unrecognized cover art flags: "

    .line 45
    .line 46
    invoke-static {p0, v1, v3}, Lvj/b;->w(Ljava/lang/String;ILjava/lang/String;)V

    .line 47
    .line 48
    .line 49
    return-object v4

    .line 50
    :cond_2
    const/4 v1, 0x4

    .line 51
    invoke-virtual {p0, v1}, Lw7/p;->J(I)V

    .line 52
    .line 53
    .line 54
    add-int/lit8 v0, v0, -0x10

    .line 55
    .line 56
    new-array v1, v0, [B

    .line 57
    .line 58
    const/4 v3, 0x0

    .line 59
    invoke-virtual {p0, v1, v3, v0}, Lw7/p;->h([BII)V

    .line 60
    .line 61
    .line 62
    new-instance p0, Lc9/a;

    .line 63
    .line 64
    const/4 v0, 0x3

    .line 65
    invoke-direct {p0, v0, v2, v4, v1}, Lc9/a;-><init>(ILjava/lang/String;Ljava/lang/String;[B)V

    .line 66
    .line 67
    .line 68
    return-object p0

    .line 69
    :cond_3
    const-string p0, "Failed to parse cover art attribute"

    .line 70
    .line 71
    invoke-static {v3, p0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    return-object v4
.end method

.method public static f(ILjava/lang/String;Lw7/p;)Lc9/o;
    .locals 4

    .line 1
    invoke-virtual {p2}, Lw7/p;->j()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p2}, Lw7/p;->j()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const v2, 0x64617461

    .line 10
    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    if-ne v1, v2, :cond_1

    .line 14
    .line 15
    const/16 v1, 0x16

    .line 16
    .line 17
    if-lt v0, v1, :cond_1

    .line 18
    .line 19
    const/16 v0, 0xa

    .line 20
    .line 21
    invoke-virtual {p2, v0}, Lw7/p;->J(I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p2}, Lw7/p;->C()I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    if-lez v0, :cond_1

    .line 29
    .line 30
    const-string p0, ""

    .line 31
    .line 32
    invoke-static {v0, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-virtual {p2}, Lw7/p;->C()I

    .line 37
    .line 38
    .line 39
    move-result p2

    .line 40
    if-lez p2, :cond_0

    .line 41
    .line 42
    new-instance v0, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string p0, "/"

    .line 51
    .line 52
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    :cond_0
    new-instance p2, Lc9/o;

    .line 63
    .line 64
    invoke-static {p0}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-direct {p2, p1, v3, p0}, Lc9/o;-><init>(Ljava/lang/String;Ljava/lang/String;Lhr/x0;)V

    .line 69
    .line 70
    .line 71
    return-object p2

    .line 72
    :cond_1
    new-instance p1, Ljava/lang/StringBuilder;

    .line 73
    .line 74
    const-string p2, "Failed to parse index/count attribute: "

    .line 75
    .line 76
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    invoke-static {p0}, Lkq/d;->b(I)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    const-string p1, "MetadataUtil"

    .line 91
    .line 92
    invoke-static {p1, p0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    return-object v3
.end method

.method public static g(Lw7/p;)I
    .locals 3

    .line 1
    invoke-virtual {p0}, Lw7/p;->j()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0}, Lw7/p;->j()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const v2, 0x64617461

    .line 10
    .line 11
    .line 12
    if-ne v1, v2, :cond_4

    .line 13
    .line 14
    const/16 v1, 0x8

    .line 15
    .line 16
    invoke-virtual {p0, v1}, Lw7/p;->J(I)V

    .line 17
    .line 18
    .line 19
    add-int/lit8 v0, v0, -0x10

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    if-eq v0, v1, :cond_3

    .line 23
    .line 24
    const/4 v1, 0x2

    .line 25
    if-eq v0, v1, :cond_2

    .line 26
    .line 27
    const/4 v1, 0x3

    .line 28
    if-eq v0, v1, :cond_1

    .line 29
    .line 30
    const/4 v1, 0x4

    .line 31
    if-eq v0, v1, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    iget-object v0, p0, Lw7/p;->a:[B

    .line 35
    .line 36
    iget v1, p0, Lw7/p;->b:I

    .line 37
    .line 38
    aget-byte v0, v0, v1

    .line 39
    .line 40
    and-int/lit16 v0, v0, 0x80

    .line 41
    .line 42
    if-nez v0, :cond_4

    .line 43
    .line 44
    invoke-virtual {p0}, Lw7/p;->A()I

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    return p0

    .line 49
    :cond_1
    invoke-virtual {p0}, Lw7/p;->z()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    return p0

    .line 54
    :cond_2
    invoke-virtual {p0}, Lw7/p;->C()I

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    return p0

    .line 59
    :cond_3
    invoke-virtual {p0}, Lw7/p;->w()I

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    return p0

    .line 64
    :cond_4
    :goto_0
    const-string p0, "MetadataUtil"

    .line 65
    .line 66
    const-string v0, "Failed to parse data atom to int"

    .line 67
    .line 68
    invoke-static {p0, v0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    const/4 p0, -0x1

    .line 72
    return p0
.end method

.method public static h(ILjava/lang/String;Lw7/p;ZZ)Lc9/j;
    .locals 0

    .line 1
    invoke-static {p2}, Li9/p;->g(Lw7/p;)I

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    if-eqz p4, :cond_0

    .line 6
    .line 7
    const/4 p4, 0x1

    .line 8
    invoke-static {p4, p2}, Ljava/lang/Math;->min(II)I

    .line 9
    .line 10
    .line 11
    move-result p2

    .line 12
    :cond_0
    const/4 p4, 0x0

    .line 13
    if-ltz p2, :cond_2

    .line 14
    .line 15
    if-eqz p3, :cond_1

    .line 16
    .line 17
    new-instance p0, Lc9/o;

    .line 18
    .line 19
    invoke-static {p2}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    invoke-static {p2}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 24
    .line 25
    .line 26
    move-result-object p2

    .line 27
    invoke-direct {p0, p1, p4, p2}, Lc9/o;-><init>(Ljava/lang/String;Ljava/lang/String;Lhr/x0;)V

    .line 28
    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_1
    new-instance p0, Lc9/e;

    .line 32
    .line 33
    const-string p3, "und"

    .line 34
    .line 35
    invoke-static {p2}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    invoke-direct {p0, p3, p1, p2}, Lc9/e;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_2
    new-instance p1, Ljava/lang/StringBuilder;

    .line 44
    .line 45
    const-string p2, "Failed to parse uint8 attribute: "

    .line 46
    .line 47
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-static {p0}, Lkq/d;->b(I)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    const-string p1, "MetadataUtil"

    .line 62
    .line 63
    invoke-static {p1, p0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    return-object p4
.end method

.method public static i(ILjava/lang/String;Lw7/p;)Lc9/o;
    .locals 4

    .line 1
    invoke-virtual {p2}, Lw7/p;->j()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p2}, Lw7/p;->j()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const v2, 0x64617461

    .line 10
    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    const/16 p0, 0x8

    .line 16
    .line 17
    invoke-virtual {p2, p0}, Lw7/p;->J(I)V

    .line 18
    .line 19
    .line 20
    add-int/lit8 v0, v0, -0x10

    .line 21
    .line 22
    invoke-virtual {p2, v0}, Lw7/p;->s(I)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    new-instance p2, Lc9/o;

    .line 27
    .line 28
    invoke-static {p0}, Lhr/h0;->u(Ljava/lang/Object;)Lhr/x0;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-direct {p2, p1, v3, p0}, Lc9/o;-><init>(Ljava/lang/String;Ljava/lang/String;Lhr/x0;)V

    .line 33
    .line 34
    .line 35
    return-object p2

    .line 36
    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    .line 37
    .line 38
    const-string p2, "Failed to parse text attribute: "

    .line 39
    .line 40
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-static {p0}, Lkq/d;->b(I)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    const-string p1, "MetadataUtil"

    .line 55
    .line 56
    invoke-static {p1, p0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    return-object v3
.end method

.method public static varargs j(ILt7/c0;Lt7/n;Lt7/c0;[Lt7/c0;)V
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p3, :cond_0

    .line 3
    .line 4
    goto :goto_0

    .line 5
    :cond_0
    new-instance p3, Lt7/c0;

    .line 6
    .line 7
    new-array v1, v0, [Lt7/b0;

    .line 8
    .line 9
    invoke-direct {p3, v1}, Lt7/c0;-><init>([Lt7/b0;)V

    .line 10
    .line 11
    .line 12
    :goto_0
    if-eqz p1, :cond_3

    .line 13
    .line 14
    move v1, v0

    .line 15
    :goto_1
    iget-object v2, p1, Lt7/c0;->a:[Lt7/b0;

    .line 16
    .line 17
    array-length v3, v2

    .line 18
    if-ge v1, v3, :cond_3

    .line 19
    .line 20
    aget-object v2, v2, v1

    .line 21
    .line 22
    instance-of v3, v2, Lx7/a;

    .line 23
    .line 24
    if-eqz v3, :cond_2

    .line 25
    .line 26
    check-cast v2, Lx7/a;

    .line 27
    .line 28
    iget-object v3, v2, Lx7/a;->a:Ljava/lang/String;

    .line 29
    .line 30
    const-string v4, "com.android.capture.fps"

    .line 31
    .line 32
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    const/4 v4, 0x1

    .line 37
    if-eqz v3, :cond_1

    .line 38
    .line 39
    const/4 v3, 0x2

    .line 40
    if-ne p0, v3, :cond_2

    .line 41
    .line 42
    new-array v3, v4, [Lt7/b0;

    .line 43
    .line 44
    aput-object v2, v3, v0

    .line 45
    .line 46
    invoke-virtual {p3, v3}, Lt7/c0;->a([Lt7/b0;)Lt7/c0;

    .line 47
    .line 48
    .line 49
    move-result-object p3

    .line 50
    goto :goto_2

    .line 51
    :cond_1
    new-array v3, v4, [Lt7/b0;

    .line 52
    .line 53
    aput-object v2, v3, v0

    .line 54
    .line 55
    invoke-virtual {p3, v3}, Lt7/c0;->a([Lt7/b0;)Lt7/c0;

    .line 56
    .line 57
    .line 58
    move-result-object p3

    .line 59
    :cond_2
    :goto_2
    add-int/lit8 v1, v1, 0x1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    array-length p0, p4

    .line 63
    :goto_3
    if-ge v0, p0, :cond_4

    .line 64
    .line 65
    aget-object p1, p4, v0

    .line 66
    .line 67
    invoke-virtual {p3, p1}, Lt7/c0;->b(Lt7/c0;)Lt7/c0;

    .line 68
    .line 69
    .line 70
    move-result-object p3

    .line 71
    add-int/lit8 v0, v0, 0x1

    .line 72
    .line 73
    goto :goto_3

    .line 74
    :cond_4
    iget-object p0, p3, Lt7/c0;->a:[Lt7/b0;

    .line 75
    .line 76
    array-length p0, p0

    .line 77
    if-lez p0, :cond_5

    .line 78
    .line 79
    iput-object p3, p2, Lt7/n;->k:Lt7/c0;

    .line 80
    .line 81
    :cond_5
    return-void
.end method

.method public static k(Lo8/p;ZZ)Lo8/g0;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    invoke-interface {v0}, Lo8/p;->getLength()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    const-wide/16 v4, -0x1

    .line 10
    .line 11
    cmp-long v6, v2, v4

    .line 12
    .line 13
    const-wide/16 v7, 0x1000

    .line 14
    .line 15
    if-eqz v6, :cond_1

    .line 16
    .line 17
    cmp-long v9, v2, v7

    .line 18
    .line 19
    if-lez v9, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move-wide v7, v2

    .line 23
    :cond_1
    :goto_0
    long-to-int v7, v7

    .line 24
    new-instance v8, Lw7/p;

    .line 25
    .line 26
    const/16 v9, 0x40

    .line 27
    .line 28
    invoke-direct {v8, v9}, Lw7/p;-><init>(I)V

    .line 29
    .line 30
    .line 31
    const/4 v9, 0x0

    .line 32
    move v10, v9

    .line 33
    move v11, v10

    .line 34
    :goto_1
    if-ge v10, v7, :cond_2

    .line 35
    .line 36
    const/16 v13, 0x8

    .line 37
    .line 38
    invoke-virtual {v8, v13}, Lw7/p;->F(I)V

    .line 39
    .line 40
    .line 41
    iget-object v14, v8, Lw7/p;->a:[B

    .line 42
    .line 43
    const/4 v15, 0x1

    .line 44
    invoke-interface {v0, v14, v9, v13, v15}, Lo8/p;->b([BIIZ)Z

    .line 45
    .line 46
    .line 47
    move-result v14

    .line 48
    if-nez v14, :cond_3

    .line 49
    .line 50
    :cond_2
    move v4, v9

    .line 51
    const/16 v17, 0x0

    .line 52
    .line 53
    goto/16 :goto_9

    .line 54
    .line 55
    :cond_3
    invoke-virtual {v8}, Lw7/p;->y()J

    .line 56
    .line 57
    .line 58
    move-result-wide v16

    .line 59
    invoke-virtual {v8}, Lw7/p;->j()I

    .line 60
    .line 61
    .line 62
    move-result v14

    .line 63
    const-wide/16 v18, 0x1

    .line 64
    .line 65
    cmp-long v18, v16, v18

    .line 66
    .line 67
    if-nez v18, :cond_4

    .line 68
    .line 69
    move-wide/from16 v18, v4

    .line 70
    .line 71
    iget-object v4, v8, Lw7/p;->a:[B

    .line 72
    .line 73
    invoke-interface {v0, v4, v13, v13}, Lo8/p;->o([BII)V

    .line 74
    .line 75
    .line 76
    const/16 v4, 0x10

    .line 77
    .line 78
    invoke-virtual {v8, v4}, Lw7/p;->H(I)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v8}, Lw7/p;->q()J

    .line 82
    .line 83
    .line 84
    move-result-wide v16

    .line 85
    move/from16 v21, v10

    .line 86
    .line 87
    :goto_2
    move-wide/from16 v9, v16

    .line 88
    .line 89
    const/4 v5, 0x0

    .line 90
    goto :goto_4

    .line 91
    :cond_4
    move-wide/from16 v18, v4

    .line 92
    .line 93
    const-wide/16 v4, 0x0

    .line 94
    .line 95
    cmp-long v4, v16, v4

    .line 96
    .line 97
    if-nez v4, :cond_5

    .line 98
    .line 99
    invoke-interface {v0}, Lo8/p;->getLength()J

    .line 100
    .line 101
    .line 102
    move-result-wide v4

    .line 103
    cmp-long v20, v4, v18

    .line 104
    .line 105
    if-eqz v20, :cond_5

    .line 106
    .line 107
    invoke-interface {v0}, Lo8/p;->h()J

    .line 108
    .line 109
    .line 110
    move-result-wide v16

    .line 111
    sub-long v4, v4, v16

    .line 112
    .line 113
    move/from16 v21, v10

    .line 114
    .line 115
    int-to-long v9, v13

    .line 116
    add-long v16, v4, v9

    .line 117
    .line 118
    :goto_3
    move v4, v13

    .line 119
    goto :goto_2

    .line 120
    :cond_5
    move/from16 v21, v10

    .line 121
    .line 122
    goto :goto_3

    .line 123
    :goto_4
    int-to-long v12, v4

    .line 124
    cmp-long v17, v9, v12

    .line 125
    .line 126
    if-gez v17, :cond_6

    .line 127
    .line 128
    new-instance v0, Li9/k;

    .line 129
    .line 130
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 131
    .line 132
    .line 133
    return-object v0

    .line 134
    :cond_6
    add-int v4, v21, v4

    .line 135
    .line 136
    move-object/from16 v17, v5

    .line 137
    .line 138
    const v5, 0x6d6f6f76

    .line 139
    .line 140
    .line 141
    if-ne v14, v5, :cond_8

    .line 142
    .line 143
    long-to-int v5, v9

    .line 144
    add-int/2addr v7, v5

    .line 145
    if-eqz v6, :cond_7

    .line 146
    .line 147
    int-to-long v9, v7

    .line 148
    cmp-long v5, v9, v2

    .line 149
    .line 150
    if-lez v5, :cond_7

    .line 151
    .line 152
    long-to-int v7, v2

    .line 153
    :cond_7
    move v10, v4

    .line 154
    move-wide/from16 v4, v18

    .line 155
    .line 156
    const/4 v9, 0x0

    .line 157
    goto :goto_1

    .line 158
    :cond_8
    const v5, 0x6d6f6f66

    .line 159
    .line 160
    .line 161
    if-eq v14, v5, :cond_16

    .line 162
    .line 163
    const v5, 0x6d766578

    .line 164
    .line 165
    .line 166
    if-ne v14, v5, :cond_9

    .line 167
    .line 168
    goto/16 :goto_8

    .line 169
    .line 170
    :cond_9
    const v5, 0x6d646174

    .line 171
    .line 172
    .line 173
    if-ne v14, v5, :cond_a

    .line 174
    .line 175
    move v11, v15

    .line 176
    :cond_a
    move-wide/from16 v21, v2

    .line 177
    .line 178
    int-to-long v2, v4

    .line 179
    add-long/2addr v2, v9

    .line 180
    sub-long/2addr v2, v12

    .line 181
    move-wide/from16 v23, v2

    .line 182
    .line 183
    int-to-long v2, v7

    .line 184
    cmp-long v2, v23, v2

    .line 185
    .line 186
    if-ltz v2, :cond_b

    .line 187
    .line 188
    const/4 v9, 0x0

    .line 189
    goto/16 :goto_a

    .line 190
    .line 191
    :cond_b
    sub-long/2addr v9, v12

    .line 192
    long-to-int v2, v9

    .line 193
    add-int v10, v4, v2

    .line 194
    .line 195
    const v3, 0x66747970

    .line 196
    .line 197
    .line 198
    if-ne v14, v3, :cond_14

    .line 199
    .line 200
    const/16 v3, 0x8

    .line 201
    .line 202
    if-ge v2, v3, :cond_c

    .line 203
    .line 204
    new-instance v0, Li9/k;

    .line 205
    .line 206
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 207
    .line 208
    .line 209
    return-object v0

    .line 210
    :cond_c
    invoke-virtual {v8, v2}, Lw7/p;->F(I)V

    .line 211
    .line 212
    .line 213
    iget-object v3, v8, Lw7/p;->a:[B

    .line 214
    .line 215
    const/4 v4, 0x0

    .line 216
    invoke-interface {v0, v3, v4, v2}, Lo8/p;->o([BII)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {v8}, Lw7/p;->j()I

    .line 220
    .line 221
    .line 222
    move-result v2

    .line 223
    invoke-static {v2, v1}, Li9/p;->c(IZ)Z

    .line 224
    .line 225
    .line 226
    move-result v2

    .line 227
    if-eqz v2, :cond_d

    .line 228
    .line 229
    move v11, v15

    .line 230
    :cond_d
    const/4 v2, 0x4

    .line 231
    invoke-virtual {v8, v2}, Lw7/p;->J(I)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v8}, Lw7/p;->a()I

    .line 235
    .line 236
    .line 237
    move-result v3

    .line 238
    div-int/2addr v3, v2

    .line 239
    if-nez v11, :cond_10

    .line 240
    .line 241
    if-lez v3, :cond_10

    .line 242
    .line 243
    new-array v12, v3, [I

    .line 244
    .line 245
    move v2, v4

    .line 246
    :goto_5
    if-ge v2, v3, :cond_f

    .line 247
    .line 248
    invoke-virtual {v8}, Lw7/p;->j()I

    .line 249
    .line 250
    .line 251
    move-result v5

    .line 252
    aput v5, v12, v2

    .line 253
    .line 254
    invoke-static {v5, v1}, Li9/p;->c(IZ)Z

    .line 255
    .line 256
    .line 257
    move-result v5

    .line 258
    if-eqz v5, :cond_e

    .line 259
    .line 260
    goto :goto_6

    .line 261
    :cond_e
    add-int/lit8 v2, v2, 0x1

    .line 262
    .line 263
    goto :goto_5

    .line 264
    :cond_f
    move v15, v11

    .line 265
    goto :goto_6

    .line 266
    :cond_10
    move v15, v11

    .line 267
    move-object/from16 v12, v17

    .line 268
    .line 269
    :goto_6
    if-nez v15, :cond_13

    .line 270
    .line 271
    new-instance v0, Li9/k;

    .line 272
    .line 273
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 274
    .line 275
    .line 276
    if-eqz v12, :cond_12

    .line 277
    .line 278
    sget v1, Lkr/a;->f:I

    .line 279
    .line 280
    array-length v1, v12

    .line 281
    if-nez v1, :cond_11

    .line 282
    .line 283
    return-object v0

    .line 284
    :cond_11
    new-instance v1, Lkr/a;

    .line 285
    .line 286
    array-length v2, v12

    .line 287
    invoke-static {v12, v2}, Ljava/util/Arrays;->copyOf([II)[I

    .line 288
    .line 289
    .line 290
    move-result-object v2

    .line 291
    invoke-direct {v1, v2}, Lkr/a;-><init>([I)V

    .line 292
    .line 293
    .line 294
    return-object v0

    .line 295
    :cond_12
    sget v1, Lkr/a;->f:I

    .line 296
    .line 297
    return-object v0

    .line 298
    :cond_13
    move v11, v15

    .line 299
    goto :goto_7

    .line 300
    :cond_14
    const/4 v4, 0x0

    .line 301
    if-eqz v2, :cond_15

    .line 302
    .line 303
    invoke-interface {v0, v2}, Lo8/p;->i(I)V

    .line 304
    .line 305
    .line 306
    :cond_15
    :goto_7
    move v9, v4

    .line 307
    move-wide/from16 v4, v18

    .line 308
    .line 309
    move-wide/from16 v2, v21

    .line 310
    .line 311
    goto/16 :goto_1

    .line 312
    .line 313
    :cond_16
    :goto_8
    move v9, v15

    .line 314
    goto :goto_a

    .line 315
    :goto_9
    move v9, v4

    .line 316
    :goto_a
    if-nez v11, :cond_17

    .line 317
    .line 318
    sget-object v0, Li9/k;->c:Li9/k;

    .line 319
    .line 320
    return-object v0

    .line 321
    :cond_17
    move/from16 v0, p1

    .line 322
    .line 323
    if-eq v0, v9, :cond_19

    .line 324
    .line 325
    if-eqz v9, :cond_18

    .line 326
    .line 327
    sget-object v0, Li9/k;->a:Li9/k;

    .line 328
    .line 329
    return-object v0

    .line 330
    :cond_18
    sget-object v0, Li9/k;->b:Li9/k;

    .line 331
    .line 332
    return-object v0

    .line 333
    :cond_19
    return-object v17
.end method
