.class public abstract Lx2/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lx2/g;

.field public static final b:Lx2/g;

.field public static final c:Lx2/f;

.field public static final d:Lx2/f;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lx2/g;

    .line 2
    .line 3
    const/high16 v1, -0x40800000    # -1.0f

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lx2/g;-><init>(F)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lx2/a;->a:Lx2/g;

    .line 9
    .line 10
    new-instance v0, Lx2/g;

    .line 11
    .line 12
    const/high16 v2, 0x3f800000    # 1.0f

    .line 13
    .line 14
    invoke-direct {v0, v2}, Lx2/g;-><init>(F)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lx2/a;->b:Lx2/g;

    .line 18
    .line 19
    new-instance v0, Lx2/f;

    .line 20
    .line 21
    invoke-direct {v0, v1}, Lx2/f;-><init>(F)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Lx2/a;->c:Lx2/f;

    .line 25
    .line 26
    new-instance v0, Lx2/f;

    .line 27
    .line 28
    invoke-direct {v0, v2}, Lx2/f;-><init>(F)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lx2/a;->d:Lx2/f;

    .line 32
    .line 33
    return-void
.end method

.method public static final a(Lx2/s;Lay0/o;)Lx2/s;
    .locals 1

    .line 1
    new-instance v0, Lx2/m;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lx2/m;-><init>(Lay0/o;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public static final b(Ll2/o;Lx2/s;)Lx2/s;
    .locals 2

    .line 1
    sget-object v0, Lx2/n;->f:Lx2/n;

    .line 2
    .line 3
    invoke-interface {p1, v0}, Lx2/s;->b(Lay0/k;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    return-object p1

    .line 10
    :cond_0
    check-cast p0, Ll2/t;

    .line 11
    .line 12
    const v0, 0x48ae8da7

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0, v0}, Ll2/t;->Z(I)V

    .line 16
    .line 17
    .line 18
    new-instance v0, Lb1/g;

    .line 19
    .line 20
    const/4 v1, 0x5

    .line 21
    invoke-direct {v0, p0, v1}, Lb1/g;-><init>(Ljava/lang/Object;I)V

    .line 22
    .line 23
    .line 24
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 25
    .line 26
    invoke-interface {p1, v1, v0}, Lx2/s;->a(Ljava/lang/Object;Lay0/n;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    check-cast p1, Lx2/s;

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    invoke-virtual {p0, v0}, Ll2/t;->q(Z)V

    .line 34
    .line 35
    .line 36
    return-object p1
.end method

.method public static final c(Ll2/o;Lx2/s;)Lx2/s;
    .locals 1

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x1a365f2c

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->Y(I)V

    .line 7
    .line 8
    .line 9
    invoke-static {p0, p1}, Lx2/a;->b(Ll2/o;Lx2/s;)Lx2/s;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    const/4 v0, 0x0

    .line 14
    invoke-virtual {p0, v0}, Ll2/t;->q(Z)V

    .line 15
    .line 16
    .line 17
    return-object p1
.end method

.method public static final d(Lx2/s;F)Lx2/s;
    .locals 1

    .line 1
    new-instance v0, Landroidx/compose/ui/ZIndexElement;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Landroidx/compose/ui/ZIndexElement;-><init>(F)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method
