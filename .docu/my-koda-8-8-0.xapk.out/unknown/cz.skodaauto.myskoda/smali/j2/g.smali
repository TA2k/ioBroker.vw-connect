.class public final Lj2/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Z

.field public final synthetic e:J

.field public final synthetic f:Lj2/p;


# direct methods
.method public constructor <init>(ZJLj2/p;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lj2/g;->d:Z

    .line 5
    .line 6
    iput-wide p2, p0, Lj2/g;->e:J

    .line 7
    .line 8
    iput-object p4, p0, Lj2/g;->f:Lj2/p;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    check-cast p1, Lk1/q;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Number;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    and-int/lit8 p3, p1, 0x11

    .line 12
    .line 13
    const/16 v0, 0x10

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    if-eq p3, v0, :cond_0

    .line 17
    .line 18
    move p3, v1

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 p3, 0x0

    .line 21
    :goto_0
    and-int/2addr p1, v1

    .line 22
    move-object v5, p2

    .line 23
    check-cast v5, Ll2/t;

    .line 24
    .line 25
    invoke-virtual {v5, p1, p3}, Ll2/t;->O(IZ)Z

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    if-eqz p1, :cond_1

    .line 30
    .line 31
    iget-boolean p1, p0, Lj2/g;->d:Z

    .line 32
    .line 33
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    sget-object p1, Lk2/w;->f:Lk2/w;

    .line 38
    .line 39
    invoke-static {p1, v5}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    new-instance p1, Lj2/f;

    .line 44
    .line 45
    iget-wide p2, p0, Lj2/g;->e:J

    .line 46
    .line 47
    iget-object p0, p0, Lj2/g;->f:Lj2/p;

    .line 48
    .line 49
    invoke-direct {p1, p2, p3, p0}, Lj2/f;-><init>(JLj2/p;)V

    .line 50
    .line 51
    .line 52
    const p0, -0x7b07a338

    .line 53
    .line 54
    .line 55
    invoke-static {p0, v5, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    const/16 v6, 0x6000

    .line 60
    .line 61
    const/16 v7, 0xa

    .line 62
    .line 63
    const/4 v1, 0x0

    .line 64
    const/4 v3, 0x0

    .line 65
    invoke-static/range {v0 .. v7}, Ljp/w1;->b(Ljava/lang/Object;Lx2/s;Lc1/a0;Ljava/lang/String;Lt2/b;Ll2/o;II)V

    .line 66
    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_1
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 70
    .line 71
    .line 72
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    return-object p0
.end method
