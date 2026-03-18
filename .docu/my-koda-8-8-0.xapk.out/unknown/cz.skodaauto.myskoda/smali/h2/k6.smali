.class public final Lh2/k6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lx4/x;

.field public final b:Z

.field public final c:Z


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lx4/x;->d:Lx4/x;

    .line 5
    .line 6
    iput-object v0, p0, Lh2/k6;->a:Lx4/x;

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    iput-boolean v0, p0, Lh2/k6;->b:Z

    .line 10
    .line 11
    iput-boolean v0, p0, Lh2/k6;->c:Z

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Lh2/k6;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lh2/k6;

    .line 10
    .line 11
    iget-object v0, p1, Lh2/k6;->a:Lx4/x;

    .line 12
    .line 13
    iget-object v1, p0, Lh2/k6;->a:Lx4/x;

    .line 14
    .line 15
    if-eq v1, v0, :cond_2

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_2
    iget-boolean v0, p0, Lh2/k6;->c:Z

    .line 19
    .line 20
    iget-boolean v1, p1, Lh2/k6;->c:Z

    .line 21
    .line 22
    if-eq v0, v1, :cond_3

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_3
    iget-boolean p0, p0, Lh2/k6;->b:Z

    .line 26
    .line 27
    iget-boolean p1, p1, Lh2/k6;->b:Z

    .line 28
    .line 29
    if-eq p0, p1, :cond_4

    .line 30
    .line 31
    :goto_0
    const/4 p0, 0x0

    .line 32
    return p0

    .line 33
    :cond_4
    :goto_1
    const/4 p0, 0x1

    .line 34
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lh2/k6;->a:Lx4/x;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-boolean v1, p0, Lh2/k6;->b:Z

    .line 10
    .line 11
    const/16 v2, 0x745f

    .line 12
    .line 13
    invoke-static {v0, v2, v1}, La7/g0;->e(IIZ)I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    iget-boolean p0, p0, Lh2/k6;->c:Z

    .line 18
    .line 19
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    add-int/2addr p0, v0

    .line 24
    return p0
.end method
