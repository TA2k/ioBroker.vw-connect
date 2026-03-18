.class public final Lk1/m1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu3/c;
.implements Lu3/f;


# instance fields
.field public final b:Ll2/j1;

.field public final c:Lk1/b0;


# direct methods
.method public constructor <init>(Lk1/b0;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lk1/b0;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Lk1/b0;-><init>(I)V

    .line 8
    .line 9
    .line 10
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lk1/m1;->b:Ll2/j1;

    .line 15
    .line 16
    iput-object p1, p0, Lk1/m1;->c:Lk1/b0;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final d()Lk1/q1;
    .locals 0

    .line 1
    iget-object p0, p0, Lk1/m1;->b:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lk1/q1;

    .line 8
    .line 9
    return-object p0
.end method

.method public final e(Lu3/g;)V
    .locals 2

    .line 1
    sget-object v0, Lk1/d;->c:Lu3/h;

    .line 2
    .line 3
    invoke-interface {p1, v0}, Lu3/g;->b(Lu3/h;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    check-cast p1, Lk1/q1;

    .line 8
    .line 9
    new-instance v0, Lk1/l1;

    .line 10
    .line 11
    iget-object v1, p0, Lk1/m1;->c:Lk1/b0;

    .line 12
    .line 13
    invoke-direct {v0, v1, p1}, Lk1/l1;-><init>(Lk1/q1;Lk1/q1;)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lk1/m1;->b:Ll2/j1;

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

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
    instance-of v0, p1, Lk1/m1;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_1
    check-cast p1, Lk1/m1;

    .line 12
    .line 13
    iget-object p1, p1, Lk1/m1;->c:Lk1/b0;

    .line 14
    .line 15
    iget-object p0, p0, Lk1/m1;->c:Lk1/b0;

    .line 16
    .line 17
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final getKey()Lu3/h;
    .locals 0

    .line 1
    sget-object p0, Lk1/d;->c:Lu3/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lk1/m1;->c:Lk1/b0;

    .line 2
    .line 3
    invoke-virtual {p0}, Lk1/b0;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
