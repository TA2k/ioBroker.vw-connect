.class public abstract Llp/y9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 2

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, -0x418bfa6f

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 v0, 0x0

    .line 14
    :goto_0
    and-int/lit8 v1, p1, 0x1

    .line 15
    .line 16
    invoke-virtual {p0, v1, v0}, Ll2/t;->O(IZ)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_1
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 24
    .line 25
    .line 26
    :goto_1
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    if-eqz p0, :cond_2

    .line 31
    .line 32
    new-instance v0, Li40/j2;

    .line 33
    .line 34
    const/16 v1, 0x15

    .line 35
    .line 36
    invoke-direct {v0, p1, v1}, Li40/j2;-><init>(II)V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 40
    .line 41
    :cond_2
    return-void
.end method


# virtual methods
.method public abstract b(I)V
.end method

.method public abstract c(Landroid/graphics/Typeface;Z)V
.end method
