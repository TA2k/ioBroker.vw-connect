.class public final Lg11/o;
.super Ll11/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lj11/q;

.field public b:Z

.field public c:I


# direct methods
.method public constructor <init>(Lj11/q;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lg11/o;->a:Lj11/q;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final c(Lj11/a;)Z
    .locals 2

    .line 1
    instance-of p1, p1, Lj11/r;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p1, :cond_1

    .line 5
    .line 6
    iget-boolean p1, p0, Lg11/o;->b:Z

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    iget p1, p0, Lg11/o;->c:I

    .line 12
    .line 13
    if-ne p1, v1, :cond_0

    .line 14
    .line 15
    iput-boolean v0, p0, Lg11/o;->b:Z

    .line 16
    .line 17
    :cond_0
    return v1

    .line 18
    :cond_1
    return v0
.end method

.method public final f()Lj11/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lg11/o;->a:Lj11/q;

    .line 2
    .line 3
    return-object p0
.end method

.method public final g()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final i(Lg11/g;)Lc9/h;
    .locals 2

    .line 1
    iget-boolean v0, p1, Lg11/g;->i:Z

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iput-boolean v1, p0, Lg11/o;->b:Z

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    iput v0, p0, Lg11/o;->c:I

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-boolean v0, p0, Lg11/o;->b:Z

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    iget v0, p0, Lg11/o;->c:I

    .line 17
    .line 18
    add-int/2addr v0, v1

    .line 19
    iput v0, p0, Lg11/o;->c:I

    .line 20
    .line 21
    :cond_1
    :goto_0
    iget p0, p1, Lg11/g;->c:I

    .line 22
    .line 23
    invoke-static {p0}, Lc9/h;->a(I)Lc9/h;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method
