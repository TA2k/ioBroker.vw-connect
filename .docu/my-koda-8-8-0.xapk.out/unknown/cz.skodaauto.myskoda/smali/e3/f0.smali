.class public final Le3/f0;
.super Le3/g0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ld3/d;

.field public final b:Le3/i;


# direct methods
.method public constructor <init>(Ld3/d;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le3/f0;->a:Ld3/d;

    .line 5
    .line 6
    invoke-static {p1}, Ljp/df;->d(Ld3/d;)Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {v0, p1}, Le3/i;->c(Le3/i;Ld3/d;)V

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 v0, 0x0

    .line 21
    :goto_0
    iput-object v0, p0, Le3/f0;->b:Le3/i;

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final a()Ld3/c;
    .locals 4

    .line 1
    new-instance v0, Ld3/c;

    .line 2
    .line 3
    iget-object p0, p0, Le3/f0;->a:Ld3/d;

    .line 4
    .line 5
    iget v1, p0, Ld3/d;->a:F

    .line 6
    .line 7
    iget v2, p0, Ld3/d;->b:F

    .line 8
    .line 9
    iget v3, p0, Ld3/d;->c:F

    .line 10
    .line 11
    iget p0, p0, Ld3/d;->d:F

    .line 12
    .line 13
    invoke-direct {v0, v1, v2, v3, p0}, Ld3/c;-><init>(FFFF)V

    .line 14
    .line 15
    .line 16
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Le3/f0;

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
    check-cast p1, Le3/f0;

    .line 12
    .line 13
    iget-object p1, p1, Le3/f0;->a:Ld3/d;

    .line 14
    .line 15
    iget-object p0, p0, Le3/f0;->a:Ld3/d;

    .line 16
    .line 17
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-nez p0, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    return v0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Le3/f0;->a:Ld3/d;

    .line 2
    .line 3
    invoke-virtual {p0}, Ld3/d;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
