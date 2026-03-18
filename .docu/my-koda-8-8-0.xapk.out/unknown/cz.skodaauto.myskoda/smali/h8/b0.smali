.class public final Lh8/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/Object;

.field public final b:I

.field public final c:I

.field public final d:J

.field public final e:I


# direct methods
.method public constructor <init>(JLjava/lang/Object;)V
    .locals 7

    const/4 v3, -0x1

    const/4 v6, -0x1

    const/4 v2, -0x1

    move-object v0, p0

    move-wide v4, p1

    move-object v1, p3

    .line 2
    invoke-direct/range {v0 .. v6}, Lh8/b0;-><init>(Ljava/lang/Object;IIJI)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;)V
    .locals 2

    const-wide/16 v0, -0x1

    .line 1
    invoke-direct {p0, v0, v1, p1}, Lh8/b0;-><init>(JLjava/lang/Object;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;IIJI)V
    .locals 0

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Lh8/b0;->a:Ljava/lang/Object;

    .line 6
    iput p2, p0, Lh8/b0;->b:I

    .line 7
    iput p3, p0, Lh8/b0;->c:I

    .line 8
    iput-wide p4, p0, Lh8/b0;->d:J

    .line 9
    iput p6, p0, Lh8/b0;->e:I

    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;JI)V
    .locals 7

    const/4 v2, -0x1

    const/4 v3, -0x1

    move-object v0, p0

    move-object v1, p1

    move-wide v4, p2

    move v6, p4

    .line 3
    invoke-direct/range {v0 .. v6}, Lh8/b0;-><init>(Ljava/lang/Object;IIJI)V

    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)Lh8/b0;
    .locals 8

    .line 1
    iget-object v0, p0, Lh8/b0;->a:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    new-instance v1, Lh8/b0;

    .line 11
    .line 12
    iget-wide v5, p0, Lh8/b0;->d:J

    .line 13
    .line 14
    iget v7, p0, Lh8/b0;->e:I

    .line 15
    .line 16
    iget v3, p0, Lh8/b0;->b:I

    .line 17
    .line 18
    iget v4, p0, Lh8/b0;->c:I

    .line 19
    .line 20
    move-object v2, p1

    .line 21
    invoke-direct/range {v1 .. v7}, Lh8/b0;-><init>(Ljava/lang/Object;IIJI)V

    .line 22
    .line 23
    .line 24
    return-object v1
.end method

.method public final b()Z
    .locals 1

    .line 1
    iget p0, p0, Lh8/b0;->b:I

    .line 2
    .line 3
    const/4 v0, -0x1

    .line 4
    if-eq p0, v0, :cond_0

    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lh8/b0;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lh8/b0;

    .line 12
    .line 13
    iget-object v1, p0, Lh8/b0;->a:Ljava/lang/Object;

    .line 14
    .line 15
    iget-object v3, p1, Lh8/b0;->a:Ljava/lang/Object;

    .line 16
    .line 17
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    iget v1, p0, Lh8/b0;->b:I

    .line 24
    .line 25
    iget v3, p1, Lh8/b0;->b:I

    .line 26
    .line 27
    if-ne v1, v3, :cond_2

    .line 28
    .line 29
    iget v1, p0, Lh8/b0;->c:I

    .line 30
    .line 31
    iget v3, p1, Lh8/b0;->c:I

    .line 32
    .line 33
    if-ne v1, v3, :cond_2

    .line 34
    .line 35
    iget-wide v3, p0, Lh8/b0;->d:J

    .line 36
    .line 37
    iget-wide v5, p1, Lh8/b0;->d:J

    .line 38
    .line 39
    cmp-long v1, v3, v5

    .line 40
    .line 41
    if-nez v1, :cond_2

    .line 42
    .line 43
    iget p0, p0, Lh8/b0;->e:I

    .line 44
    .line 45
    iget p1, p1, Lh8/b0;->e:I

    .line 46
    .line 47
    if-ne p0, p1, :cond_2

    .line 48
    .line 49
    return v0

    .line 50
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 5

    .line 1
    const/16 v0, 0x20f

    .line 2
    .line 3
    iget-object v1, p0, Lh8/b0;->a:Ljava/lang/Object;

    .line 4
    .line 5
    const/16 v2, 0x1f

    .line 6
    .line 7
    invoke-static {v0, v1, v2}, Lp3/m;->b(ILjava/lang/Object;I)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iget v1, p0, Lh8/b0;->b:I

    .line 12
    .line 13
    add-int/2addr v0, v1

    .line 14
    mul-int/2addr v0, v2

    .line 15
    iget v1, p0, Lh8/b0;->c:I

    .line 16
    .line 17
    add-int/2addr v0, v1

    .line 18
    mul-int/2addr v0, v2

    .line 19
    iget-wide v3, p0, Lh8/b0;->d:J

    .line 20
    .line 21
    long-to-int v1, v3

    .line 22
    add-int/2addr v0, v1

    .line 23
    mul-int/2addr v0, v2

    .line 24
    iget p0, p0, Lh8/b0;->e:I

    .line 25
    .line 26
    add-int/2addr v0, p0

    .line 27
    return v0
.end method
