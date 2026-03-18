.class public final Lx4/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Lx4/x;

.field public final d:Z

.field public final e:Z

.field public final f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 3

    and-int/lit8 v0, p1, 0x2

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eqz v0, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    and-int/lit8 p1, p1, 0x4

    if-eqz p1, :cond_1

    move v1, v2

    .line 9
    :cond_1
    invoke-direct {p0, v2, v0, v1}, Lx4/p;-><init>(ZZZ)V

    return-void
.end method

.method public constructor <init>(ZZZ)V
    .locals 7

    .line 10
    sget-object v0, Lx4/x;->d:Lx4/x;

    const/4 v5, 0x1

    const/16 v6, 0x20

    move-object v1, p0

    move v2, p1

    move v3, p2

    move v4, p3

    .line 11
    invoke-direct/range {v1 .. v6}, Lx4/p;-><init>(ZZZZI)V

    return-void
.end method

.method public constructor <init>(ZZZZI)V
    .locals 0

    .line 1
    sget-object p5, Lx4/x;->d:Lx4/x;

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-boolean p1, p0, Lx4/p;->a:Z

    .line 4
    iput-boolean p2, p0, Lx4/p;->b:Z

    .line 5
    iput-object p5, p0, Lx4/p;->c:Lx4/x;

    .line 6
    iput-boolean p3, p0, Lx4/p;->d:Z

    .line 7
    iput-boolean p4, p0, Lx4/p;->e:Z

    .line 8
    const-string p1, ""

    iput-object p1, p0, Lx4/p;->f:Ljava/lang/String;

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
    instance-of v0, p1, Lx4/p;

    .line 5
    .line 6
    if-nez v0, :cond_1

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_1
    check-cast p1, Lx4/p;

    .line 10
    .line 11
    iget-boolean v0, p1, Lx4/p;->a:Z

    .line 12
    .line 13
    iget-boolean v1, p0, Lx4/p;->a:Z

    .line 14
    .line 15
    if-eq v1, v0, :cond_2

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_2
    iget-boolean v0, p0, Lx4/p;->b:Z

    .line 19
    .line 20
    iget-boolean v1, p1, Lx4/p;->b:Z

    .line 21
    .line 22
    if-eq v0, v1, :cond_3

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_3
    iget-object v0, p0, Lx4/p;->c:Lx4/x;

    .line 26
    .line 27
    iget-object v1, p1, Lx4/p;->c:Lx4/x;

    .line 28
    .line 29
    if-eq v0, v1, :cond_4

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_4
    iget-boolean v0, p0, Lx4/p;->d:Z

    .line 33
    .line 34
    iget-boolean v1, p1, Lx4/p;->d:Z

    .line 35
    .line 36
    if-eq v0, v1, :cond_5

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_5
    iget-boolean p0, p0, Lx4/p;->e:Z

    .line 40
    .line 41
    iget-boolean p1, p1, Lx4/p;->e:Z

    .line 42
    .line 43
    if-eq p0, p1, :cond_6

    .line 44
    .line 45
    :goto_0
    const/4 p0, 0x0

    .line 46
    return p0

    .line 47
    :cond_6
    :goto_1
    const/4 p0, 0x1

    .line 48
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Lx4/p;->a:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-boolean v2, p0, Lx4/p;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lx4/p;->c:Lx4/x;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    iget-boolean v0, p0, Lx4/p;->d:Z

    .line 25
    .line 26
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget-boolean p0, p0, Lx4/p;->e:Z

    .line 31
    .line 32
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    add-int/2addr p0, v0

    .line 37
    return p0
.end method
