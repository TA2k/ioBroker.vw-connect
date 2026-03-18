.class public final Lin/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lmy0/i;


# instance fields
.field public final d:I

.field public final e:J


# direct methods
.method public synthetic constructor <init>(IJ)V
    .locals 0

    .line 1
    iput p1, p0, Lin/p;->d:I

    iput-wide p2, p0, Lin/p;->e:J

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(JI)V
    .locals 0

    .line 2
    iput-wide p1, p0, Lin/p;->e:J

    iput p3, p0, Lin/p;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public static a(IILjava/lang/String;)Lin/p;
    .locals 6

    .line 1
    if-lt p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    const-wide/16 v0, 0x0

    .line 5
    .line 6
    move v2, p0

    .line 7
    :goto_0
    if-ge v2, p1, :cond_2

    .line 8
    .line 9
    invoke-virtual {p2, v2}, Ljava/lang/String;->charAt(I)C

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    const/16 v4, 0x30

    .line 14
    .line 15
    if-lt v3, v4, :cond_2

    .line 16
    .line 17
    const/16 v4, 0x39

    .line 18
    .line 19
    if-gt v3, v4, :cond_2

    .line 20
    .line 21
    const-wide/16 v4, 0xa

    .line 22
    .line 23
    mul-long/2addr v0, v4

    .line 24
    add-int/lit8 v3, v3, -0x30

    .line 25
    .line 26
    int-to-long v3, v3

    .line 27
    add-long/2addr v0, v3

    .line 28
    const-wide/32 v3, 0x7fffffff

    .line 29
    .line 30
    .line 31
    cmp-long v3, v0, v3

    .line 32
    .line 33
    if-lez v3, :cond_1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_2
    if-ne v2, p0, :cond_3

    .line 40
    .line 41
    :goto_1
    const/4 p0, 0x0

    .line 42
    return-object p0

    .line 43
    :cond_3
    new-instance p0, Lin/p;

    .line 44
    .line 45
    invoke-direct {p0, v0, v1, v2}, Lin/p;-><init>(JI)V

    .line 46
    .line 47
    .line 48
    return-object p0
.end method

.method public static b(Lo8/p;Lw7/p;)Lin/p;
    .locals 3

    .line 1
    iget-object v0, p1, Lw7/p;->a:[B

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-interface {p0, v0, v2, v1}, Lo8/p;->o([BII)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p1, v2}, Lw7/p;->I(I)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p1}, Lw7/p;->j()I

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    invoke-virtual {p1}, Lw7/p;->n()J

    .line 17
    .line 18
    .line 19
    move-result-wide v0

    .line 20
    new-instance p1, Lin/p;

    .line 21
    .line 22
    invoke-direct {p1, p0, v0, v1}, Lin/p;-><init>(IJ)V

    .line 23
    .line 24
    .line 25
    return-object p1
.end method


# virtual methods
.method public toInstant()Lmy0/f;
    .locals 4

    .line 1
    sget-object v0, Lmy0/f;->f:Lmy0/f;

    .line 2
    .line 3
    iget-wide v0, v0, Lmy0/f;->d:J

    .line 4
    .line 5
    iget-wide v2, p0, Lin/p;->e:J

    .line 6
    .line 7
    cmp-long v0, v2, v0

    .line 8
    .line 9
    if-ltz v0, :cond_0

    .line 10
    .line 11
    sget-object v0, Lmy0/f;->g:Lmy0/f;

    .line 12
    .line 13
    iget-wide v0, v0, Lmy0/f;->d:J

    .line 14
    .line 15
    cmp-long v0, v2, v0

    .line 16
    .line 17
    if-gtz v0, :cond_0

    .line 18
    .line 19
    iget p0, p0, Lin/p;->d:I

    .line 20
    .line 21
    invoke-static {p0, v2, v3}, Lmy0/h;->i(IJ)Lmy0/f;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :cond_0
    new-instance p0, Lgz0/a;

    .line 27
    .line 28
    new-instance v0, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    const-string v1, "The parsed date is outside the range representable by Instant (Unix epoch second "

    .line 31
    .line 32
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const/16 v1, 0x29

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    const/4 v1, 0x2

    .line 48
    invoke-direct {p0, v0, v1}, Lgz0/a;-><init>(Ljava/lang/String;I)V

    .line 49
    .line 50
    .line 51
    throw p0
.end method
