.class public final Lhz0/c0;
.super Ljz0/m;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lhz0/e0;


# direct methods
.method public constructor <init>(Lhz0/e0;)V
    .locals 3

    .line 1
    const-string v0, "names"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lhz0/m;->b:Ljz0/u;

    .line 7
    .line 8
    iget-object v1, p1, Lhz0/e0;->a:Ljava/util/List;

    .line 9
    .line 10
    const-string v2, "dayOfWeekName"

    .line 11
    .line 12
    invoke-direct {p0, v0, v1, v2}, Ljz0/m;-><init>(Ljz0/u;Ljava/util/List;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lhz0/c0;->d:Lhz0/e0;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lhz0/c0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lhz0/c0;->d:Lhz0/e0;

    .line 6
    .line 7
    iget-object p0, p0, Lhz0/e0;->a:Ljava/util/List;

    .line 8
    .line 9
    check-cast p1, Lhz0/c0;

    .line 10
    .line 11
    iget-object p1, p1, Lhz0/c0;->d:Lhz0/e0;

    .line 12
    .line 13
    iget-object p1, p1, Lhz0/e0;->a:Ljava/util/List;

    .line 14
    .line 15
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_0
    const/4 p0, 0x0

    .line 24
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lhz0/c0;->d:Lhz0/e0;

    .line 2
    .line 3
    iget-object p0, p0, Lhz0/e0;->a:Ljava/util/List;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method
