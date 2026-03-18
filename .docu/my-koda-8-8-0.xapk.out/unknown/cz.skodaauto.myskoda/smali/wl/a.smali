.class public final Lwl/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lwl/e;


# instance fields
.field public final b:I


# direct methods
.method public constructor <init>(I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lwl/a;->b:I

    .line 5
    .line 6
    if-lez p1, :cond_0

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 10
    .line 11
    const-string p1, "durationMillis must be > 0."

    .line 12
    .line 13
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    throw p0
.end method


# virtual methods
.method public final a(Ljl/i;Ltl/i;)Lwl/f;
    .locals 2

    .line 1
    instance-of v0, p2, Ltl/n;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance p0, Lwl/d;

    .line 6
    .line 7
    invoke-direct {p0, p1, p2}, Lwl/d;-><init>(Ljl/i;Ltl/i;)V

    .line 8
    .line 9
    .line 10
    return-object p0

    .line 11
    :cond_0
    move-object v0, p2

    .line 12
    check-cast v0, Ltl/n;

    .line 13
    .line 14
    iget-object v0, v0, Ltl/n;->c:Lkl/e;

    .line 15
    .line 16
    sget-object v1, Lkl/e;->d:Lkl/e;

    .line 17
    .line 18
    if-ne v0, v1, :cond_1

    .line 19
    .line 20
    new-instance p0, Lwl/d;

    .line 21
    .line 22
    invoke-direct {p0, p1, p2}, Lwl/d;-><init>(Ljl/i;Ltl/i;)V

    .line 23
    .line 24
    .line 25
    return-object p0

    .line 26
    :cond_1
    new-instance v0, Lwl/b;

    .line 27
    .line 28
    iget p0, p0, Lwl/a;->b:I

    .line 29
    .line 30
    invoke-direct {v0, p1, p2, p0}, Lwl/b;-><init>(Ljl/i;Ltl/i;I)V

    .line 31
    .line 32
    .line 33
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lwl/a;

    .line 6
    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    check-cast p1, Lwl/a;

    .line 10
    .line 11
    iget p1, p1, Lwl/a;->b:I

    .line 12
    .line 13
    iget p0, p0, Lwl/a;->b:I

    .line 14
    .line 15
    if-ne p0, p1, :cond_1

    .line 16
    .line 17
    return v0

    .line 18
    :cond_1
    const/4 p0, 0x0

    .line 19
    return p0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget p0, p0, Lwl/a;->b:I

    .line 2
    .line 3
    mul-int/lit8 p0, p0, 0x1f

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    add-int/2addr v0, p0

    .line 11
    return v0
.end method
