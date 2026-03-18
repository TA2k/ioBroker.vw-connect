.class public final Lc1/d1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc1/v;


# instance fields
.field public final a:I


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lc1/d1;->a:I

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Lc1/b2;)Lc1/d2;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lc1/d1;->a(Lc1/b2;)Lc1/f2;

    move-result-object p0

    return-object p0
.end method

.method public final a(Lc1/b2;)Lc1/f2;
    .locals 1

    .line 2
    new-instance p1, Lc1/l2;

    iget p0, p0, Lc1/d1;->a:I

    const/4 v0, 0x0

    invoke-direct {p1, p0, v0}, Lc1/l2;-><init>(II)V

    return-object p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lc1/d1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lc1/d1;

    .line 6
    .line 7
    iget p1, p1, Lc1/d1;->a:I

    .line 8
    .line 9
    iget p0, p0, Lc1/d1;->a:I

    .line 10
    .line 11
    if-ne p1, p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Lc1/d1;->a:I

    .line 2
    .line 3
    return p0
.end method
