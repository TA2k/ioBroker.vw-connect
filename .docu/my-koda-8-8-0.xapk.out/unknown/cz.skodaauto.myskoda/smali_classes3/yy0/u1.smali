.class public final Lyy0/u1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lyy0/w1;

.field public static final b:Lyy0/w1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lyy0/w1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lyy0/w1;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lyy0/u1;->a:Lyy0/w1;

    .line 8
    .line 9
    new-instance v0, Lyy0/w1;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lyy0/w1;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lyy0/u1;->b:Lyy0/w1;

    .line 16
    .line 17
    return-void
.end method

.method public static a(IJ)Lyy0/z1;
    .locals 0

    .line 1
    and-int/lit8 p0, p0, 0x1

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const-wide/16 p1, 0x0

    .line 6
    .line 7
    :cond_0
    new-instance p0, Lyy0/z1;

    .line 8
    .line 9
    invoke-direct {p0, p1, p2}, Lyy0/z1;-><init>(J)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method
