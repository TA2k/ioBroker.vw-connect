.class public final Lh2/ha;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:Lay0/n;

.field public final synthetic e:Lt2/b;

.field public final synthetic f:Lay0/n;

.field public final synthetic g:J

.field public final synthetic h:J


# direct methods
.method public constructor <init>(Lay0/n;Lt2/b;Lay0/n;JJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/ha;->d:Lay0/n;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/ha;->e:Lt2/b;

    .line 7
    .line 8
    iput-object p3, p0, Lh2/ha;->f:Lay0/n;

    .line 9
    .line 10
    iput-wide p4, p0, Lh2/ha;->g:J

    .line 11
    .line 12
    iput-wide p6, p0, Lh2/ha;->h:J

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    check-cast p1, Ll2/o;

    .line 2
    .line 3
    check-cast p2, Ljava/lang/Number;

    .line 4
    .line 5
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 6
    .line 7
    .line 8
    move-result p2

    .line 9
    and-int/lit8 v0, p2, 0x3

    .line 10
    .line 11
    const/4 v1, 0x2

    .line 12
    const/4 v2, 0x1

    .line 13
    if-eq v0, v1, :cond_0

    .line 14
    .line 15
    move v0, v2

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x0

    .line 18
    :goto_0
    and-int/2addr p2, v2

    .line 19
    check-cast p1, Ll2/t;

    .line 20
    .line 21
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    if-eqz p2, :cond_1

    .line 26
    .line 27
    sget-object p2, Lk2/k0;->h:Lk2/p0;

    .line 28
    .line 29
    invoke-static {p2, p1}, Lh2/ec;->a(Lk2/p0;Ll2/o;)Lg4/p0;

    .line 30
    .line 31
    .line 32
    move-result-object p2

    .line 33
    sget-object v0, Lk2/k0;->b:Lk2/p0;

    .line 34
    .line 35
    invoke-static {v0, p1}, Lh2/ec;->a(Lk2/p0;Ll2/o;)Lg4/p0;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    sget-object v0, Lh2/rb;->a:Ll2/e0;

    .line 40
    .line 41
    invoke-virtual {v0, p2}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    new-instance v1, Lh2/ga;

    .line 46
    .line 47
    iget-wide v6, p0, Lh2/ha;->g:J

    .line 48
    .line 49
    iget-wide v8, p0, Lh2/ha;->h:J

    .line 50
    .line 51
    iget-object v2, p0, Lh2/ha;->d:Lay0/n;

    .line 52
    .line 53
    iget-object v3, p0, Lh2/ha;->e:Lt2/b;

    .line 54
    .line 55
    iget-object v4, p0, Lh2/ha;->f:Lay0/n;

    .line 56
    .line 57
    invoke-direct/range {v1 .. v9}, Lh2/ga;-><init>(Lay0/n;Lt2/b;Lay0/n;Lg4/p0;JJ)V

    .line 58
    .line 59
    .line 60
    const p0, 0x39cbc4b1

    .line 61
    .line 62
    .line 63
    invoke-static {p0, p1, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    const/16 v0, 0x38

    .line 68
    .line 69
    invoke-static {p2, p0, p1, v0}, Ll2/b;->a(Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 74
    .line 75
    .line 76
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 77
    .line 78
    return-object p0
.end method
