.class public final Ls11/a;
.super Ln11/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final k:I


# instance fields
.field public final i:Ls11/d;

.field public final transient j:[Lp3/h;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    :try_start_0
    const-string v0, "org.joda.time.tz.CachedDateTimeZone.size"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->getInteger(Ljava/lang/String;)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 7
    goto :goto_0

    .line 8
    :catch_0
    const/4 v0, 0x0

    .line 9
    :goto_0
    const/4 v1, 0x1

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    const/16 v0, 0x200

    .line 13
    .line 14
    goto :goto_2

    .line 15
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    add-int/lit8 v0, v0, -0x1

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    :goto_1
    if-lez v0, :cond_1

    .line 23
    .line 24
    add-int/lit8 v2, v2, 0x1

    .line 25
    .line 26
    shr-int/lit8 v0, v0, 0x1

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    shl-int v0, v1, v2

    .line 30
    .line 31
    :goto_2
    sub-int/2addr v0, v1

    .line 32
    sput v0, Ls11/a;->k:I

    .line 33
    .line 34
    return-void
.end method

.method public constructor <init>(Ls11/d;)V
    .locals 1

    .line 1
    iget-object v0, p1, Ln11/f;->d:Ljava/lang/String;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Ln11/f;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget v0, Ls11/a;->k:I

    .line 7
    .line 8
    add-int/lit8 v0, v0, 0x1

    .line 9
    .line 10
    new-array v0, v0, [Lp3/h;

    .line 11
    .line 12
    iput-object v0, p0, Ls11/a;->j:[Lp3/h;

    .line 13
    .line 14
    iput-object p1, p0, Ls11/a;->i:Ls11/d;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Ls11/a;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    check-cast p1, Ls11/a;

    .line 10
    .line 11
    iget-object p1, p1, Ls11/a;->i:Ls11/d;

    .line 12
    .line 13
    iget-object p0, p0, Ls11/a;->i:Ls11/d;

    .line 14
    .line 15
    invoke-virtual {p0, p1}, Ls11/d;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_1
    const/4 p0, 0x0

    .line 21
    return p0
.end method

.method public final g(J)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Ls11/a;->s(J)Lp3/h;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0, p1, p2}, Lp3/h;->b(J)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Ls11/a;->i:Ls11/d;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln11/f;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final i(J)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Ls11/a;->s(J)Lp3/h;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0, p1, p2}, Lp3/h;->c(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final l(J)I
    .locals 0

    .line 1
    invoke-virtual {p0, p1, p2}, Ls11/a;->s(J)Lp3/h;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0, p1, p2}, Lp3/h;->d(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final m()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ls11/a;->i:Ls11/d;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return p0
.end method

.method public final n(J)J
    .locals 0

    .line 1
    iget-object p0, p0, Ls11/a;->i:Ls11/d;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ls11/d;->n(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final p(J)J
    .locals 0

    .line 1
    iget-object p0, p0, Ls11/a;->i:Ls11/d;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ls11/d;->p(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final s(J)Lp3/h;
    .locals 8

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    shr-long v1, p1, v0

    .line 4
    .line 5
    long-to-int v1, v1

    .line 6
    sget v2, Ls11/a;->k:I

    .line 7
    .line 8
    and-int/2addr v2, v1

    .line 9
    iget-object v3, p0, Ls11/a;->j:[Lp3/h;

    .line 10
    .line 11
    aget-object v4, v3, v2

    .line 12
    .line 13
    if-eqz v4, :cond_1

    .line 14
    .line 15
    iget-wide v5, v4, Lp3/h;->a:J

    .line 16
    .line 17
    shr-long/2addr v5, v0

    .line 18
    long-to-int v0, v5

    .line 19
    if-eq v0, v1, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    return-object v4

    .line 23
    :cond_1
    :goto_0
    const-wide v0, -0x100000000L

    .line 24
    .line 25
    .line 26
    .line 27
    .line 28
    and-long/2addr p1, v0

    .line 29
    new-instance v0, Lp3/h;

    .line 30
    .line 31
    iget-object p0, p0, Ls11/a;->i:Ls11/d;

    .line 32
    .line 33
    invoke-direct {v0, p0, p1, p2}, Lp3/h;-><init>(Ls11/d;J)V

    .line 34
    .line 35
    .line 36
    const-wide v4, 0xffffffffL

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    or-long/2addr v4, p1

    .line 42
    move-object v1, v0

    .line 43
    :goto_1
    invoke-virtual {p0, p1, p2}, Ls11/d;->n(J)J

    .line 44
    .line 45
    .line 46
    move-result-wide v6

    .line 47
    cmp-long p1, v6, p1

    .line 48
    .line 49
    if-eqz p1, :cond_3

    .line 50
    .line 51
    cmp-long p1, v6, v4

    .line 52
    .line 53
    if-lez p1, :cond_2

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_2
    new-instance p1, Lp3/h;

    .line 57
    .line 58
    invoke-direct {p1, p0, v6, v7}, Lp3/h;-><init>(Ls11/d;J)V

    .line 59
    .line 60
    .line 61
    iput-object p1, v1, Lp3/h;->e:Ljava/lang/Object;

    .line 62
    .line 63
    move-object v1, p1

    .line 64
    move-wide p1, v6

    .line 65
    goto :goto_1

    .line 66
    :cond_3
    :goto_2
    aput-object v0, v3, v2

    .line 67
    .line 68
    return-object v0
.end method
