.class public abstract Lb1/h1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Landroid/view/ViewConfiguration;->getScrollFriction()F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    sput v0, Lb1/h1;->a:F

    .line 6
    .line 7
    return-void
.end method

.method public static final a(Ll2/o;)Lc1/u;
    .locals 3

    .line 1
    sget-object v0, Lw3/h1;->h:Ll2/u2;

    .line 2
    .line 3
    check-cast p0, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lt4/c;

    .line 10
    .line 11
    invoke-interface {v0}, Lt4/c;->a()F

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    invoke-virtual {p0, v1}, Ll2/t;->d(F)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    if-nez v1, :cond_0

    .line 24
    .line 25
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 26
    .line 27
    if-ne v2, v1, :cond_1

    .line 28
    .line 29
    :cond_0
    new-instance v1, La0/j;

    .line 30
    .line 31
    invoke-direct {v1, v0}, La0/j;-><init>(Lt4/c;)V

    .line 32
    .line 33
    .line 34
    new-instance v2, Lc1/u;

    .line 35
    .line 36
    invoke-direct {v2, v1}, Lc1/u;-><init>(Lc1/c0;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    :cond_1
    check-cast v2, Lc1/u;

    .line 43
    .line 44
    return-object v2
.end method
