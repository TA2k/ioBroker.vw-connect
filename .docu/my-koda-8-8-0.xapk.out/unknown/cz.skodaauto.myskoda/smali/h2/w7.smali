.class public abstract Lh2/w7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;

.field public static final b:Lh2/x7;

.field public static final c:Lh2/x7;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lgz0/e0;

    .line 2
    .line 3
    const/16 v1, 0x12

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lgz0/e0;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/e0;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lh2/w7;->a:Ll2/e0;

    .line 14
    .line 15
    new-instance v0, Lh2/x7;

    .line 16
    .line 17
    sget-wide v1, Le3/s;->i:J

    .line 18
    .line 19
    const/4 v3, 0x1

    .line 20
    const/high16 v4, 0x7fc00000    # Float.NaN

    .line 21
    .line 22
    invoke-direct {v0, v3, v4, v1, v2}, Lh2/x7;-><init>(ZFJ)V

    .line 23
    .line 24
    .line 25
    sput-object v0, Lh2/w7;->b:Lh2/x7;

    .line 26
    .line 27
    new-instance v0, Lh2/x7;

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    invoke-direct {v0, v3, v4, v1, v2}, Lh2/x7;-><init>(ZFJ)V

    .line 31
    .line 32
    .line 33
    sput-object v0, Lh2/w7;->c:Lh2/x7;

    .line 34
    .line 35
    return-void
.end method

.method public static a(JFIZ)Lh2/x7;
    .locals 2

    .line 1
    and-int/lit8 v0, p3, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 p4, 0x1

    .line 6
    :cond_0
    and-int/lit8 v0, p3, 0x2

    .line 7
    .line 8
    const/high16 v1, 0x7fc00000    # Float.NaN

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    move p2, v1

    .line 13
    :cond_1
    and-int/lit8 p3, p3, 0x4

    .line 14
    .line 15
    if-eqz p3, :cond_2

    .line 16
    .line 17
    sget-wide p0, Le3/s;->i:J

    .line 18
    .line 19
    :cond_2
    invoke-static {p2, v1}, Lt4/f;->a(FF)Z

    .line 20
    .line 21
    .line 22
    move-result p3

    .line 23
    if-eqz p3, :cond_4

    .line 24
    .line 25
    sget-wide v0, Le3/s;->i:J

    .line 26
    .line 27
    invoke-static {p0, p1, v0, v1}, Le3/s;->c(JJ)Z

    .line 28
    .line 29
    .line 30
    move-result p3

    .line 31
    if-eqz p3, :cond_4

    .line 32
    .line 33
    if-eqz p4, :cond_3

    .line 34
    .line 35
    sget-object p0, Lh2/w7;->b:Lh2/x7;

    .line 36
    .line 37
    return-object p0

    .line 38
    :cond_3
    sget-object p0, Lh2/w7;->c:Lh2/x7;

    .line 39
    .line 40
    return-object p0

    .line 41
    :cond_4
    new-instance p3, Lh2/x7;

    .line 42
    .line 43
    invoke-direct {p3, p4, p2, p0, p1}, Lh2/x7;-><init>(ZFJ)V

    .line 44
    .line 45
    .line 46
    return-object p3
.end method
