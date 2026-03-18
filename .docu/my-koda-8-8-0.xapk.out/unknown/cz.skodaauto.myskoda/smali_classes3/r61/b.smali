.class public abstract Lr61/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lqk/a;

    .line 2
    .line 3
    const/16 v1, 0x13

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lqk/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lt2/b;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const v3, -0xd7b802c

    .line 12
    .line 13
    .line 14
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lr61/b;->a:Lt2/b;

    .line 18
    .line 19
    return-void
.end method

.method public static final a(Lx2/s;Ll2/o;I)V
    .locals 8

    .line 1
    const-string v0, "modifier"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v5, p1

    .line 7
    check-cast v5, Ll2/t;

    .line 8
    .line 9
    const p1, -0x63bcb002

    .line 10
    .line 11
    .line 12
    invoke-virtual {v5, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 p1, p2, 0x3

    .line 16
    .line 17
    const/4 v0, 0x2

    .line 18
    if-eq p1, v0, :cond_0

    .line 19
    .line 20
    const/4 p1, 0x1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p1, 0x0

    .line 23
    :goto_0
    and-int/lit8 v0, p2, 0x1

    .line 24
    .line 25
    invoke-virtual {v5, v0, p1}, Ll2/t;->O(IZ)Z

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    if-eqz p1, :cond_1

    .line 30
    .line 31
    sget-wide v0, Le3/s;->h:J

    .line 32
    .line 33
    sget-object p1, Le3/j0;->a:Le3/i0;

    .line 34
    .line 35
    invoke-static {p0, v0, v1, p1}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    const/16 v6, 0xc00

    .line 40
    .line 41
    const/4 v7, 0x6

    .line 42
    const/4 v2, 0x0

    .line 43
    const/4 v3, 0x0

    .line 44
    sget-object v4, Lr61/b;->a:Lt2/b;

    .line 45
    .line 46
    invoke-static/range {v1 .. v7}, Lk1/d;->a(Lx2/s;Lx2/e;ZLt2/b;Ll2/o;II)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 51
    .line 52
    .line 53
    :goto_1
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    if-eqz p1, :cond_2

    .line 58
    .line 59
    new-instance v0, Ll30/a;

    .line 60
    .line 61
    const/16 v1, 0x17

    .line 62
    .line 63
    invoke-direct {v0, p0, p2, v1}, Ll30/a;-><init>(Lx2/s;II)V

    .line 64
    .line 65
    .line 66
    iput-object v0, p1, Ll2/u1;->d:Lay0/n;

    .line 67
    .line 68
    :cond_2
    return-void
.end method
