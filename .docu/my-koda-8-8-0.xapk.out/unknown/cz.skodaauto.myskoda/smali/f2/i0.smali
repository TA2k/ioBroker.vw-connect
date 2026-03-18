.class public abstract Lf2/i0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;

.field public static final b:Lf2/j0;

.field public static final c:Lg2/b;

.field public static final d:Lg2/b;

.field public static final e:Lg2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lf2/h0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lf2/h0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Ll2/e0;

    .line 8
    .line 9
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 10
    .line 11
    .line 12
    sput-object v1, Lf2/i0;->a:Ll2/e0;

    .line 13
    .line 14
    new-instance v0, Lf2/j0;

    .line 15
    .line 16
    sget-wide v1, Le3/s;->i:J

    .line 17
    .line 18
    const/4 v3, 0x1

    .line 19
    invoke-direct {v0, v1, v2, v3}, Lf2/j0;-><init>(JZ)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lf2/i0;->b:Lf2/j0;

    .line 23
    .line 24
    new-instance v0, Lf2/j0;

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    invoke-direct {v0, v1, v2, v3}, Lf2/j0;-><init>(JZ)V

    .line 28
    .line 29
    .line 30
    new-instance v0, Lg2/b;

    .line 31
    .line 32
    const v1, 0x3e23d70a    # 0.16f

    .line 33
    .line 34
    .line 35
    const v2, 0x3e75c28f    # 0.24f

    .line 36
    .line 37
    .line 38
    const v3, 0x3da3d70a    # 0.08f

    .line 39
    .line 40
    .line 41
    invoke-direct {v0, v1, v2, v3, v2}, Lg2/b;-><init>(FFFF)V

    .line 42
    .line 43
    .line 44
    sput-object v0, Lf2/i0;->c:Lg2/b;

    .line 45
    .line 46
    new-instance v0, Lg2/b;

    .line 47
    .line 48
    const v1, 0x3df5c28f    # 0.12f

    .line 49
    .line 50
    .line 51
    const v2, 0x3d23d70a    # 0.04f

    .line 52
    .line 53
    .line 54
    invoke-direct {v0, v3, v1, v2, v1}, Lg2/b;-><init>(FFFF)V

    .line 55
    .line 56
    .line 57
    sput-object v0, Lf2/i0;->d:Lg2/b;

    .line 58
    .line 59
    new-instance v0, Lg2/b;

    .line 60
    .line 61
    const v4, 0x3dcccccd    # 0.1f

    .line 62
    .line 63
    .line 64
    invoke-direct {v0, v3, v1, v2, v4}, Lg2/b;-><init>(FFFF)V

    .line 65
    .line 66
    .line 67
    sput-object v0, Lf2/i0;->e:Lg2/b;

    .line 68
    .line 69
    return-void
.end method

.method public static a(I)Lf2/j0;
    .locals 3

    .line 1
    sget-wide v0, Le3/s;->i:J

    .line 2
    .line 3
    const/high16 p0, 0x7fc00000    # Float.NaN

    .line 4
    .line 5
    invoke-static {p0, p0}, Lt4/f;->a(FF)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    invoke-static {v0, v1, v0, v1}, Le3/s;->c(JJ)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    sget-object p0, Lf2/i0;->b:Lf2/j0;

    .line 18
    .line 19
    return-object p0

    .line 20
    :cond_0
    new-instance p0, Lf2/j0;

    .line 21
    .line 22
    const/4 v2, 0x1

    .line 23
    invoke-direct {p0, v0, v1, v2}, Lf2/j0;-><init>(JZ)V

    .line 24
    .line 25
    .line 26
    return-object p0
.end method
